"""services/route_service.py — Enhanced with tie-aware optimal selection."""
from core.topology import NetworkTopology
from core.routing_table import RoutingTableGenerator
from core.congestion import CongestionSimulator
from core.visualization import NetworkVisualizer
from core.algorithms import ALL_ALGORITHMS
from core.ip_network import simulate_traceroute, build_topology_from_hops, resolve_hostname, validate_ip

# Priority order when multiple algorithms tie on cost:
# Prefer algorithms that are more "interesting" to show than Dijkstra alone.
_DISPLAY_PRIORITY = [
    "Dijkstra", "A* Search", "OSPF (Link-State)", "Bellman-Ford",
    "Floyd-Warshall", "RIP (Distance-Vector)", "Q-Learning (RL)",
    "BFS (Min-Hops)", "Prim's MST", "Kruskal's MST", "DFS"
]


def _rd(r):
    if r is None:
        return None
    return {
        "name": r.name, "path": r.path, "cost": r.cost,
        "time_ms": r.time_ms, "hops": r.hops,
        "description": r.description, "complexity": r.complexity,
        "notes": r.notes
    }


def _hd(h):
    return {
        "hop_num": h.hop_num, "ip": h.ip, "hostname": h.hostname,
        "rtt_ms": h.rtt_ms, "asn": h.asn, "org": h.org,
        "country": h.country, "isp": getattr(h, "isp", "")
    }


def _pick_optimal(valid_results):
    """
    Given all valid results, find the minimum cost and return:
    - optimal: the single best result to show in the banner
              (chosen by display priority when tied)
    - tied_names: list of ALL algorithm names that share the minimum cost
    - tied_results: full result objects for all tied algorithms
    """
    if not valid_results:
        return None, [], []

    min_cost = min(r.cost for r in valid_results)

    # Round to 3dp to avoid float noise (e.g. 44.397000000001 vs 44.397)
    tied = [r for r in valid_results
            if abs(r.cost - min_cost) < 0.001]

    tied_names = [r.name for r in tied]

    # Pick the "banner" algorithm by display priority
    for preferred in _DISPLAY_PRIORITY:
        for r in tied:
            if r.name == preferred:
                return r, tied_names, tied
    return tied[0], tied_names, tied


class RouteService:
    def __init__(self):
        self.network = NetworkTopology()
        self.table_generator = RoutingTableGenerator(self.network)
        self.congestion_simulator = CongestionSimulator(self.network)
        self.visualizer = NetworkVisualizer(self.network)
        self._last_results = {}   # key: (src, dst) → last computed results snapshot

    # ── Link Management ───────────────────────────────────────────────────

    def add_link(self, source: str, destination: str,
                 delay=1.0, congestion=0.0, bandwidth=100.0):
        source = str(source).strip().upper()
        destination = str(destination).strip().upper()
        if not source or not destination:
            raise ValueError("Router name cannot be empty.")
        if source == destination:
            raise ValueError("Cannot create a self-loop link.")
        delay = max(0.0, float(delay))
        bandwidth = max(0.001, float(bandwidth))
        self.network.add_link(source, destination, delay=delay,
                              congestion=congestion, bandwidth=bandwidth)

    def remove_link(self, source: str, destination: str):
        source = str(source).strip().upper()
        destination = str(destination).strip().upper()
        self.network.remove_link(source, destination)

    def get_all_routers(self):
        return self.network.get_routers()

    # ── Route Computation ────────────────────────────────────────────────

    def compute_route(self, source: str, destination: str, selected_algos=None):
        source = str(source).strip().upper()
        destination = str(destination).strip().upper()
        routers = self.network.get_routers()

        def _err(msg):
            # Always include src_ip/dst_ip even on error so the Launch panel renders
            try:
                s_ip = self.network.get_router_ip(source)
            except Exception:
                s_ip = None
            try:
                d_ip = self.network.get_router_ip(destination)
            except Exception:
                d_ip = None
            return {"error": msg, "source": source, "destination": destination,
                    "src_ip": s_ip, "dst_ip": d_ip}

        if not routers:
            return _err("No routers in topology. Add links first.")
        if source not in routers:
            return _err(f"Router '{source}' not found. Add it via 'Add Network Link' first.")
        if destination not in routers:
            return _err(f"Router '{destination}' not found. Add it via 'Add Network Link' first.")
        if source == destination:
            return _err("Source and destination cannot be the same router.")
        if not self.network.has_path(source, destination):
            return _err(f"No path exists between '{source}' and '{destination}'. The network may be disconnected.")

        algos = ALL_ALGORITHMS
        if selected_algos:
            algos = [a for a in ALL_ALGORITHMS if a.NAME in selected_algos]
        if not algos:
            algos = ALL_ALGORITHMS

        results = []
        for algo in algos:
            try:
                r = algo.compute(self.network, source, destination)
                results.append(r)
            except Exception:
                pass

        valid = [r for r in results if r.path and r.cost < float('inf')]
        optimal, tied_names, tied_results = _pick_optimal(valid)

        try:
            self.visualizer.generate_graph_image(
                highlight_path=optimal.path if optimal else None,
                filename="static/network.png"
            )
            img = "network.png"
        except Exception:
            img = None

        net_info = self.network.summary()

        current_snapshot = {r.name: {"cost": r.cost, "path": r.path} for r in valid}

        # Gap 4: store result snapshot for before/after comparison
        key = (source, destination)
        previous = self._last_results.get(key)
        # Cap at 50 entries to prevent unbounded growth in long sessions
        if len(self._last_results) >= 50:
            self._last_results.pop(next(iter(self._last_results)))
        self._last_results[key] = current_snapshot

        # Build IP map for path nodes
        path_ips = {}
        if optimal and optimal.path:
            for node in optimal.path:
                path_ips[node] = self.network.get_router_ip(node)

        return {
            "source": source, "destination": destination, "mode": "topology",
            "results": [_rd(r) for r in results],
            "optimal": _rd(optimal),
            "tied_names": tied_names,
            "tied_count": len(tied_names),
            "image": img,
            "network_info": net_info,
            "path_ips": path_ips,
            "src_ip": self.network.get_router_ip(source),
            "dst_ip": self.network.get_router_ip(destination),
        }

    def get_comparison(self, source: str, destination: str):
        """Return before/after comparison when congestion is active."""
        key = (source, destination)
        previous = self._last_results.get(key)
        if not previous:
            return None
        # current state
        algos = ALL_ALGORITHMS
        current_results = []
        for algo in algos:
            try:
                r = algo.compute(self.network, source, destination)
                current_results.append(r)
            except Exception:
                pass
        rows = []
        for r in current_results:
            prev = previous.get(r.name)
            if prev and r.path and r.cost < float('inf'):
                same_path = (r.path == prev["path"])
                rows.append({
                    "algo": r.name,
                    "cost_before": prev["cost"],
                    "cost_after": r.cost,
                    "delta": round(r.cost - prev["cost"], 3),
                    "rerouted": not same_path,
                })
        return rows if rows else None

    def compute_ip_route(self, src_ip: str, dst_ip: str, selected_algos=None):
        src_ip = src_ip.strip()
        dst_ip = dst_ip.strip()

        for label, ip in [("Source IP", src_ip), ("Destination IP", dst_ip)]:
            ok, err = validate_ip(ip)
            if not ok:
                return {"error": f"{label}: {err}", "source": src_ip,
                        "destination": dst_ip, "mode": "ip"}

        if src_ip == dst_ip:
            return {"error": "Source and destination IP addresses cannot be the same.",
                    "source": src_ip, "destination": dst_ip, "mode": "ip"}

        src_res = resolve_hostname(src_ip)
        dst_res = resolve_hostname(dst_ip)

        try:
            hops = simulate_traceroute(src_res, dst_res)
        except ValueError as e:
            return {"error": str(e), "source": src_ip, "destination": dst_ip, "mode": "ip"}
        except Exception as e:
            return {"error": f"Traceroute simulation failed: {e}",
                    "source": src_ip, "destination": dst_ip, "mode": "ip"}

        if len(hops) < 2:
            return {"error": "Traceroute returned fewer than 2 hops.",
                    "source": src_ip, "destination": dst_ip, "mode": "ip"}

        topo = build_topology_from_hops(hops)
        src_node, dst_node = hops[0].ip, hops[-1].ip

        algos = ALL_ALGORITHMS
        if selected_algos:
            algos = [a for a in ALL_ALGORITHMS if a.NAME in selected_algos]
        if not algos:
            algos = ALL_ALGORITHMS

        results = []
        for algo in algos:
            try:
                r = algo.compute(topo, src_node, dst_node)
                results.append(r)
            except Exception:
                pass

        valid = [r for r in results if r.path and r.cost < float('inf')]
        optimal, tied_names, tied_results = _pick_optimal(valid)

        return {
            "source": src_ip, "destination": dst_ip,
            "src_resolved": src_res, "dst_resolved": dst_res,
            "hops": [_hd(h) for h in hops],
            "results": [_rd(r) for r in results],
            "optimal": _rd(optimal),
            "tied_names": tied_names,
            "tied_count": len(tied_names),
            "mode": "ip",
            "hop_count": len(hops),
            "total_rtt": round(hops[-1].rtt_ms, 2) if hops else 0,
        }

    # ── Congestion ───────────────────────────────────────────────────────

    MAX_CONGESTION_MS = 500.0  # backend cap — prevents runaway cost values

    def apply_congestion_to_link(self, source: str, destination: str, value: float):
        source = str(source).strip().upper()
        destination = str(destination).strip().upper()
        value = max(0.0, min(float(value), self.MAX_CONGESTION_MS))
        if value != float(value) or value > self.MAX_CONGESTION_MS:
            raise ValueError(f"Congestion value must be between 0 and {self.MAX_CONGESTION_MS} ms.")
        self.congestion_simulator.apply_congestion_to_link(source, destination, value)

    def reset_congestion(self):
        self.congestion_simulator.reset_congestion()

    def simulate_traffic_spike(self):
        self.congestion_simulator.apply_random_congestion(10)

    # ── Routing Tables ───────────────────────────────────────────────────

    def generate_routing_tables(self):
        return self.table_generator.generate_all_routing_tables()

    def get_router_ip_map(self) -> dict:
        """Return {router_name: ip} for all routers in the topology."""
        return {r: self.network.get_router_ip(r)
                for r in self.network.get_routers()}

    # ── Persistence ──────────────────────────────────────────────────────

    def save_topology(self, filepath: str = "data/topology.json") -> dict:
        """Serialise the current topology to a JSON file. Returns status dict."""
        import json, os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        routers = self.network.get_routers()
        seen = set()
        links = []
        for r in routers:
            for lnk in self.network.get_neighbors(r):
                key = tuple(sorted([r, lnk.destination]))
                if key not in seen:
                    seen.add(key)
                    links.append({
                        "source":      r,
                        "destination": lnk.destination,
                        "delay":       lnk.delay,
                        "congestion":  lnk.congestion,
                        "bandwidth":   lnk.bandwidth,
                    })
        payload = {
            "routers":    routers,
            "links":      links,
            "router_ips": {r: self.network.get_router_ip(r) for r in routers},
        }
        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)
        return {"saved": True, "links": len(links), "routers": len(routers), "file": filepath}

    def load_topology(self, filepath: str = "data/topology.json") -> dict:
        """Load a topology from a JSON file, replacing the current one. Returns status dict."""
        import json, os
        if not os.path.exists(filepath):
            return {"loaded": False, "error": f"File not found: {filepath}"}
        try:
            with open(filepath) as f:
                payload = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return {"loaded": False, "error": f"Could not read file: {e}"}

        # Re-initialise topology cleanly
        self.network = __import__('core.topology', fromlist=['NetworkTopology']).NetworkTopology()
        self.table_generator = __import__('core.routing_table', fromlist=['RoutingTableGenerator']).RoutingTableGenerator(self.network)
        self.congestion_simulator = __import__('core.congestion', fromlist=['CongestionSimulator']).CongestionSimulator(self.network)
        self.visualizer = __import__('core.visualization', fromlist=['NetworkVisualizer']).NetworkVisualizer(self.network)
        self._last_results = {}

        # Restore saved IPs first so they remain consistent
        for router, ip in payload.get("router_ips", {}).items():
            self.network.router_ips[router] = ip

        links_loaded = 0
        errors = []
        for lnk in payload.get("links", []):
            try:
                self.add_link(
                    lnk["source"], lnk["destination"],
                    delay=lnk.get("delay", 1.0),
                    congestion=lnk.get("congestion", 0.0),
                    bandwidth=lnk.get("bandwidth", 100.0),
                )
                links_loaded += 1
            except Exception as e:
                errors.append(str(e))

        return {
            "loaded":       True,
            "links":        links_loaded,
            "routers":      len(self.network.get_routers()),
            "errors":       errors,
            "file":         filepath,
        }
