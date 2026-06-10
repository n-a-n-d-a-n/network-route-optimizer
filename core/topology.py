# core/topology.py  — Enhanced with NetworkX backend

import networkx as nx


class Link:
    """Represents a connection between two routers with network metrics."""

    def __init__(self, destination, delay=1.0, congestion=0.0, bandwidth=100.0):
        self.destination = destination
        self.delay = max(0.0, float(delay))
        self.congestion = max(0.0, float(congestion))
        self.bandwidth = max(0.001, float(bandwidth))  # prevent divide-by-zero

    def get_cost(self):
        """
        Cost = delay + congestion + (1000 / bandwidth)
        Higher bandwidth = lower cost (realistic OSPF-style metric).
        """
        bw_penalty = 1000.0 / self.bandwidth
        return round(self.delay + self.congestion + bw_penalty, 6)

    def to_dict(self):
        return {
            "destination": self.destination,
            "delay": self.delay,
            "congestion": self.congestion,
            "bandwidth": self.bandwidth,
            "cost": self.get_cost()
        }


class NetworkTopology:
    """Network graph backed by NetworkX for robust algorithm support."""

    def __init__(self):
        self.graph = {}            # {router: [Link, ...]}
        self._nx = nx.Graph()      # NetworkX mirror
        self.router_ips = {}       # {router_name: "10.0.X.Y"} — auto-assigned

    def _assign_ip(self, router: str) -> str:
        """Auto-assign a deterministic 10.0.x.y IP to a router name."""
        if router in self.router_ips:
            return self.router_ips[router]
        import hashlib
        h = int(hashlib.md5(router.encode()).hexdigest(), 16)
        third  = max(1, min((h >> 8) & 0xFF, 254))
        fourth = max(1, min(h & 0xFF, 254))
        ip = f"10.0.{third}.{fourth}"
        used = set(self.router_ips.values())
        while ip in used:
            fourth = (fourth % 253) + 1
            ip = f"10.0.{third}.{fourth}"
        self.router_ips[router] = ip
        return ip

    def get_router_ip(self, router: str) -> str:
        """Return the IP assigned to a router, assigning one if needed."""
        return self.router_ips.get(router) or self._assign_ip(router)

    # ── Router Management ──────────────────────────────────────────

    def add_router(self, router: str):
        if not isinstance(router, str) or not router.strip():
            raise ValueError(f"Invalid router name: {router!r}")
        router = router.strip()
        if router not in self.graph:
            self.graph[router] = []
            self._nx.add_node(router)
            self._assign_ip(router)   # assign deterministic IP on first add

    def get_routers(self):
        return list(self.graph.keys())

    def has_router(self, router: str) -> bool:
        return router in self.graph

    # ── Link Management ────────────────────────────────────────────

    def add_link(self, source: str, destination: str,
                 delay=1.0, congestion=0.0, bandwidth=100.0):
        source = str(source).strip()
        destination = str(destination).strip()
        if not source or not destination:
            raise ValueError("Router names cannot be empty.")
        if source == destination:
            raise ValueError("Source and destination must be different routers.")

        delay = max(0.0, float(delay))
        congestion = max(0.0, float(congestion))
        bandwidth = max(0.001, float(bandwidth))

        self.add_router(source)
        self.add_router(destination)

        def _set(frm, to):
            existing = next((l for l in self.graph[frm] if l.destination == to), None)
            if existing:
                existing.delay = delay
                existing.congestion = congestion
                existing.bandwidth = bandwidth
            else:
                self.graph[frm].append(Link(to, delay, congestion, bandwidth))

        _set(source, destination)
        _set(destination, source)

        cost = Link(destination, delay, congestion, bandwidth).get_cost()
        self._nx.add_edge(source, destination,
                          weight=cost, delay=delay,
                          bandwidth=bandwidth, congestion=congestion)

    def remove_link(self, source: str, destination: str):
        source = str(source).strip()
        destination = str(destination).strip()
        if source in self.graph:
            self.graph[source] = [l for l in self.graph[source] if l.destination != destination]
        if destination in self.graph:
            self.graph[destination] = [l for l in self.graph[destination] if l.destination != source]
        if self._nx.has_edge(source, destination):
            self._nx.remove_edge(source, destination)

    def get_neighbors(self, router: str):
        return self.graph.get(router, [])

    def get_link(self, source: str, destination: str):
        for link in self.graph.get(source, []):
            if link.destination == destination:
                return link
        return None

    def _sync_nx_weights(self):
        for router in self.graph:
            for link in self.graph[router]:
                if self._nx.has_edge(router, link.destination):
                    self._nx[router][link.destination]['weight'] = link.get_cost()

    # ── Analysis ───────────────────────────────────────────────────

    def is_connected(self) -> bool:
        if len(self.graph) < 2:
            return False
        return nx.is_connected(self._nx)

    def has_path(self, source: str, destination: str) -> bool:
        try:
            return nx.has_path(self._nx, source, destination)
        except Exception:
            return False

    def get_link_count(self) -> int:
        return self._nx.number_of_edges()

    def get_nx_graph(self) -> nx.Graph:
        self._sync_nx_weights()
        return self._nx

    def summary(self) -> dict:
        return {
            "routers": len(self.graph),
            "links": self.get_link_count(),
            "connected": self.is_connected(),
        }

    def display_topology(self):
        for router in self.graph:
            line = f"{router} -> "
            for link in self.graph[router]:
                line += f"{link.destination}(cost={link.get_cost():.2f}) "
            print(line)
