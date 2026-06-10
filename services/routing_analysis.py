"""
services/routing_analysis.py
Route-relevant academic analysis: protocol mapping, convergence, congestion chain.
📚 Chapter 4 — Routing Protocols
📚 Chapter 5 — Transport Layer (Congestion Control)
"""
from core.topology import NetworkTopology
from core.algorithms import ALL_ALGORITHMS


# ── Protocol → Algorithm mapping ────────────────────────────────────────────────
PROTOCOL_MAP = [
    {
        "algo":        "Dijkstra",
        "protocol":    "OSPF (Open Shortest Path First)",
        "type":        "Link-State",
        "domain":      "IGP",
        "standard":    "RFC 2328",
        "deployed_in": "Enterprise LANs, ISP backbone (intra-AS)",
        "key_feature": "Every router has full topology map → runs SPF",
        "syllabus":    "📚 Ch4: Link-State Routing — OSPF"
    },
    {
        "algo":        "Bellman-Ford",
        "protocol":    "RIP v2 (Routing Information Protocol)",
        "type":        "Distance-Vector",
        "domain":      "IGP",
        "standard":    "RFC 2453",
        "deployed_in": "Small/legacy networks (< 15 hops)",
        "key_feature": "Shares distance table with neighbors — count-to-infinity risk",
        "syllabus":    "📚 Ch4: Distance-Vector Routing — RIP"
    },
    {
        "algo":        "A* Search",
        "protocol":    "SANET / GPS-guided routing",
        "type":        "Heuristic",
        "domain":      "IGP",
        "standard":    "Research / SDN",
        "deployed_in": "Mobile ad-hoc networks, GPS navigation",
        "key_feature": "Heuristic h(n) prunes search — faster than pure Dijkstra",
        "syllabus":    "📚 Ch4: Shortest Path Routing (heuristic variant)"
    },
    {
        "algo":        "Floyd-Warshall",
        "protocol":    "SDN Controller (all-pairs)",
        "type":        "Dynamic Programming",
        "domain":      "IGP / Controller",
        "standard":    "Theoretical / OpenFlow",
        "deployed_in": "SDN controllers computing all-pairs routing tables",
        "key_feature": "Computes every src→dst pair in one O(V³) pass",
        "syllabus":    "📚 Ch4: Shortest Path Routing — all-pairs DP"
    },
    {
        "algo":        "Greedy Best-First",
        "protocol":    "EIGRP (feasible successor approximation)",
        "type":        "Hybrid / Heuristic",
        "domain":      "IGP",
        "standard":    "Cisco proprietary",
        "deployed_in": "Cisco networks using EIGRP feasible successor selection",
        "key_feature": "Uses only heuristic — not optimal but very fast",
        "syllabus":    "📚 Ch4: Shortest Path Routing — greedy heuristic"
    },
    {
        "algo":        "BFS (Min-Hops)",
        "protocol":    "Hop-count routing / STP",
        "type":        "Flood + BFS",
        "domain":      "IGP",
        "standard":    "IEEE 802.1D",
        "deployed_in": "Ethernet bridging, Spanning Tree Protocol",
        "key_feature": "Minimises hop count — ignores link weight entirely",
        "syllabus":    "📚 Ch4: Flooding / Hop-count routing"
    },
    {
        "algo":        "DFS Path",
        "protocol":    "Flooding (baseline)",
        "type":        "Exhaustive Search",
        "domain":      "IGP",
        "standard":    "Theoretical baseline",
        "deployed_in": "Not used in production — educational comparison only",
        "key_feature": "Shows worst-case path — demonstrates why optimised algorithms exist",
        "syllabus":    "📚 Ch4: Flooding — baseline comparison"
    },
    {
        "algo":        "OSPF (Delay-Metric)",
        "protocol":    "OSPF with bandwidth metric",
        "type":        "Link-State",
        "domain":      "IGP",
        "standard":    "RFC 2328 + Cisco OSPF cost",
        "deployed_in": "Real Cisco/Juniper routers — cost = 10⁸ / bandwidth",
        "key_feature": "Standard OSPF cost formula: reference_bw / interface_bw",
        "syllabus":    "📚 Ch4: OSPF — Interior Routing Algorithm"
    },
    {
        "algo":        "Widest Path (Max-BW)",
        "protocol":    "MPLS / QoS constraint-based routing",
        "type":        "Constraint-Based",
        "domain":      "IGP / TE",
        "standard":    "RFC 3272 (Traffic Engineering)",
        "deployed_in": "ISP backbone for video streaming, SLA guarantees",
        "key_feature": "Maximises bottleneck bandwidth — best for throughput-sensitive flows",
        "syllabus":    "📚 Ch4: Path State Routing — QoS / constraint-based"
    },
    {
        "algo":        "Simulated Annealing",
        "protocol":    "SDN / AI-driven routing",
        "type":        "Metaheuristic",
        "domain":      "IGP / Research",
        "standard":    "Research / SDN controllers",
        "deployed_in": "Software-Defined Networks, research-grade optimisers",
        "key_feature": "Probabilistic — escapes local optima, handles complex cost surfaces",
        "syllabus":    "📚 Ch4: Dynamic Routing — metaheuristic optimisation"
    },
]


def get_protocol_map() -> list:
    return PROTOCOL_MAP


def get_algo_protocol(algo_name: str) -> dict:
    for p in PROTOCOL_MAP:
        if p["algo"] == algo_name:
            return p
    return {}


# ── Convergence analysis after link failure ──────────────────────────────────
def convergence_analysis(network: NetworkTopology, src: str, dst: str,
                         removed_link: tuple) -> dict:
    """
    📚 Chapter 4 — Static vs Dynamic Routing, Convergence
    Run all algorithms before and after a link failure.
    Show which re-converged and at what cost increase.
    """
    routers = network.get_routers()
    if src not in routers or dst not in routers:
        return {}

    # Run all algos on current topology (after removal already applied)
    after_results = {}
    for algo in ALL_ALGORITHMS:
        try:
            r = algo.compute(network, src, dst)
            after_results[algo.NAME] = {
                "path":    r.path,
                "cost":    r.cost,
                "hops":    r.hops,
                "found":   bool(r.path and r.cost < float('inf'))
            }
        except Exception:
            after_results[algo.NAME] = {"path": [], "cost": float('inf'), "hops": 0, "found": False}

    return {
        "removed_link":   f"{removed_link[0]} ↔ {removed_link[1]}",
        "after_results":  after_results,
        "syllabus_note":  "📚 Ch4: Dynamic Routing — algorithms re-converge after topology change"
    }


# ── RIP warning ───────────────────────────────────────────────────────────────
def rip_hop_warning(hops: int) -> dict:
    """
    📚 Chapter 4 — RIP, Distance-Vector Routing
    """
    if hops > 15:
        return {
            "warning": True,
            "message": f"⚠ RIP would declare this destination UNREACHABLE — path has {hops} hops, exceeding RIP's maximum of 15.",
            "detail": "This is the count-to-infinity problem: RIP uses hop count as its only metric. When hops > 15, RIP marks the route with metric=16 (infinity) and stops advertising it. This is why OSPF (which uses bandwidth-based cost with no hop limit) replaced RIP in large networks.",
            "syllabus": "📚 Ch4: RIP — Distance-Vector, 15-hop limit, count-to-infinity"
        }
    return {"warning": False}


# ── Congestion → Transport layer cascade ──────────────────────────────────────
def congestion_cascade(congestion_ms: float, bandwidth_mbps: float) -> dict:
    """
    📚 Chapter 5 — Congestion Control (Leaky Bucket, Token Bucket, TCP Window)
    Show how link congestion cascades through transport layer.
    """
    # TCP window size estimation (simplified)
    rtt_base   = 20  # ms base RTT
    rtt_total  = rtt_base + congestion_ms
    # TCP throughput ≈ (MSS / RTT) * sqrt(3/2p) — simplified
    mss = 1460  # bytes
    # Approximate window shrinkage
    normal_window  = 65535  # bytes
    reduced_window = max(4096, int(normal_window * (rtt_base / max(rtt_total, 1))))
    normal_tput  = round((normal_window * 8) / (rtt_base / 1000) / 1_000_000, 2)
    reduced_tput = round((reduced_window * 8) / (rtt_total / 1000) / 1_000_000, 2)

    # Leaky bucket: output rate = fixed
    leaky_rate = round(bandwidth_mbps * 0.8, 1)  # 80% of link BW

    # Token bucket: allows burst up to bucket_size
    bucket_size = round(bandwidth_mbps * 10, 0)  # 10ms worth of tokens

    return {
        "congestion_ms":   congestion_ms,
        "rtt_before":      rtt_base,
        "rtt_after":       rtt_total,
        "window_before":   normal_window,
        "window_after":    reduced_window,
        "throughput_before": normal_tput,
        "throughput_after":  reduced_tput,
        "throughput_drop_pct": round((1 - reduced_tput / max(normal_tput, 0.001)) * 100, 1),
        "leaky_bucket_rate": leaky_rate,
        "token_bucket_size": bucket_size,
        "cascade_steps": [
            f"Congestion adds {congestion_ms}ms to link delay",
            f"RTT increases: {rtt_base}ms → {rtt_total}ms",
            f"Routing cost increases (cost = delay + congestion + 1000/BW)",
            f"TCP detects delay increase → reduces congestion window: {normal_window}B → {reduced_window}B",
            f"Effective throughput drops: {normal_tput} Mbps → {reduced_tput} Mbps ({round((1-reduced_tput/max(normal_tput,0.001))*100,1)}% reduction)",
            "Routing algorithm re-selects path to avoid congested link"
        ],
        "leaky_note":    f"Leaky Bucket: smooths traffic to {leaky_rate} Mbps output regardless of burst",
        "token_note":    f"Token Bucket: allows bursts up to {bucket_size} bytes, then limits to {leaky_rate} Mbps",
        "syllabus_note": "📚 Ch5: Congestion Control — Leaky Bucket, Token Bucket, TCP window"
    }


# ── Application → Algorithm recommendation ───────────────────────────────────
APP_ALGO_MAP = {
    "HTTPS": {
        "protocol": "HTTPS / TCP",
        "need":     "Low latency, reliable delivery",
        "algorithm": "Dijkstra or OSPF (Delay-Metric)",
        "reason":   "TCP requires reliable ordered delivery. Lowest-cost path minimises RTT and TCP retransmissions.",
        "syllabus": "📚 Ch6: HTTP/HTTPS over TCP — Ch5: TCP reliability — Ch4: OSPF shortest path"
    },
    "UDP": {
        "protocol": "UDP / RTP Media Stream",
        "need":     "Maximum bandwidth (throughput > latency)",
        "algorithm": "Widest Path (Max-BW)",
        "reason":   "UDP video streams tolerate some delay but need maximum bandwidth. Widest Path maximises the bottleneck link capacity.",
        "syllabus": "📚 Ch6: UDP applications — Ch4: QoS / constraint-based routing"
    },
    "DNS": {
        "protocol": "DNS / UDP port 53",
        "need":     "Reaches name server — any path is acceptable",
        "algorithm": "BFS (Min-Hops)",
        "reason":   "DNS queries are tiny (< 100 bytes). Fewest hops = fastest response. Link weight is irrelevant at this scale.",
        "syllabus": "📚 Ch6: DNS resolution chain — Ch4: hop-count routing"
    },
    "BGP": {
        "protocol": "BGP / TCP port 179",
        "need":     "Inter-domain path — IGP algorithms do NOT apply",
        "algorithm": "BGP path vector (not in this project — inter-AS only)",
        "reason":   "BGP is an Exterior Gateway Protocol. It operates between Autonomous Systems (the ASNs shown in your traceroute). IGP algorithms (Dijkstra, OSPF) only operate WITHIN a single AS.",
        "syllabus": "📚 Ch4: BGP — Exterior Routing Algorithm, path vector, inter-domain"
    },
    "OSPF": {
        "protocol": "OSPF Hello / IP protocol 89",
        "need":     "Neighbor discovery — not end-to-end routing",
        "algorithm": "Dijkstra (OSPF runs SPF after Hello exchanges)",
        "reason":   "OSPF Hello packets build the neighbor table. Once neighbors are known, OSPF floods Link-State Advertisements, and every router runs Dijkstra on the collected LSA database.",
        "syllabus": "📚 Ch4: OSPF — Link-State flooding → Dijkstra SPF calculation"
    },
    "ICMP": {
        "protocol": "ICMP Echo / Ping",
        "need":     "Reachability test — shortest path",
        "algorithm": "Dijkstra / A* Search",
        "reason":   "Ping uses ICMP which travels the same IP path as data packets. The optimal ICMP path = the optimal data path.",
        "syllabus": "📚 Ch3: ICMP — Network Layer control protocol"
    },
}


def get_app_algo_recommendation(protocol: str) -> dict:
    return APP_ALGO_MAP.get(protocol.upper(), {})


def get_all_recommendations() -> dict:
    return APP_ALGO_MAP
