# System Architecture — Congestion-Aware Route Optimizer

## Overview

This application is a Flask-based network simulation and analysis tool. It models a custom network topology in memory, runs multiple routing algorithms against it, and visualises the results. It also provides real network diagnostics (live ping, DNS, ASN lookup) layered on top of the simulated topology.

---

## Layer Architecture

```
┌─────────────────────────────────────────────────┐
│                  Browser (HTML/JS)               │
│         templates/ — Jinja2 + vanilla JS         │
└─────────────────────┬───────────────────────────┘
                      │ HTTP (Flask routes + JSON API)
┌─────────────────────▼───────────────────────────┐
│                   app.py                         │
│         Flask routes, request handling,          │
│         flash messages, error boundaries         │
└──────┬──────────────┬──────────────┬────────────┘
       │              │              │
┌──────▼──────┐ ┌─────▼──────┐ ┌───▼────────────┐
│route_service│ │report_svc  │ │ ip_tools /     │
│             │ │            │ │ routing_analysis│
│Wraps topo + │ │Health      │ │                │
│algorithms + │ │report from │ │Subnet, NAT,    │
│comparison   │ │topology    │ │protocol maps   │
└──────┬──────┘ └─────┬──────┘ └────────────────┘
       │              │
┌──────▼──────────────▼──────────────────────────┐
│                  core/                           │
│  topology.py  algorithms.py  packet_analyzer.py │
│  ip_network.py  real_network.py  congestion.py  │
└─────────────────────────────────────────────────┘
```

---

## Core Components

### `core/topology.py` — NetworkTopology

The central data structure. Maintains two parallel representations:

- **Adjacency list** (`graph: dict[str, list[Link]]`) — used by all routing algorithms for fast neighbor iteration
- **NetworkX `nx.Graph` mirror** — used for connectivity checks (`has_path`, `is_connected`) and graph image generation

Every `add_link` and `remove_link` keeps both in sync. Router IPs are auto-assigned from the `10.0.0.0/8` space and cached in `router_ips` — the same router always gets the same IP within a session.

**Link cost formula:**
```
cost = (delay + congestion) * 100 / bandwidth
```
Higher bandwidth = lower cost. Higher delay or congestion = higher cost. This models real link-state metrics.

---

### `core/algorithms.py` — 10 Routing Algorithms

All algorithms implement the same interface:
```python
algo.compute(topology, source, destination) -> AlgoResult
```

| Algorithm | Strategy | Optimal? |
|---|---|---|
| Dijkstra | Min-heap, greedy | ✅ Yes |
| Bellman-Ford | Edge relaxation (V-1 passes) | ✅ Yes |
| A\* Search | Dijkstra + hop-index heuristic | ✅ Yes (admissible h) |
| Floyd-Warshall | All-pairs DP | ✅ Yes |
| OSPF (Delay-Metric) | Dijkstra with ref\_bw/iface\_bw cost | ✅ Yes |
| Widest Path | Max-min bandwidth (modified Dijkstra) | ✅ For BW |
| Greedy Best-First | Heuristic only, no backtrack | ❌ No |
| BFS (Min-Hops) | Breadth-first, ignores weights | ❌ Not cost-optimal |
| DFS Path | Depth-first with backtracking | ❌ No |
| Simulated Annealing | Probabilistic metaheuristic | ❌ Approximate |

When multiple algorithms tie on cost, the banner algorithm is chosen by display priority (Dijkstra → A\* → OSPF → ...) rather than arbitrarily.

---

### `core/packet_analyzer.py` — PacketAnalyzer

Generates deterministic, session-aware packet sequences. A capture always starts with:
1. DNS query/response (UDP 53)
2. TCP 3-way handshake (SYN, SYN-ACK, ACK)
3. TLS ClientHello / ServerHello (if dst_port 443)
4. Data transfer packets (HTTPS, UDP stream, or ICMP depending on protocol mix)
5. TCP FIN/ACK teardown

Each call to `simulate_traffic()` **replaces** `self.packets` — it does not accumulate. This ensures `/api/packet_detail/<id>` always searches through at most the last `count` packets.

---

### `services/route_service.py` — RouteService

The main service layer. Owns the `NetworkTopology` instance and coordinates:

- **Link management** — `add_link`, `remove_link` with validation
- **Route computation** — runs all selected algorithms, picks optimal, generates graph image
- **Before/after comparison** — `_last_results` stores the last snapshot per `(src, dst)` pair for congestion delta display. Cleared on `reset_congestion()`.
- **IP route** — delegates to `simulate_traceroute` + `build_topology_from_hops`, then runs algorithms on the hop topology

---

### `core/real_network.py` — Live Network Calls

All functions are non-blocking with timeouts and fail gracefully — failures return `{"real": False}` rather than raising:

| Function | What it does | Timeout |
|---|---|---|
| `real_dns_lookup` | Queries 8.8.8.8 via dnspython, stdlib fallback | — |
| `real_https_probe` | HTTP HEAD + TLS cert extraction | 5s |
| `real_ping` | OS `ping` command via subprocess | 15s |
| `real_asn_lookup` | ipinfo.io → ip-api.com fallback | 3s each |
| `real_interface_stats` | psutil 1-second throughput sample | 1s |

---

### `core/ip_network.py` — Traceroute Simulation

`simulate_traceroute(src_ip, dst_ip)` generates a deterministic hop sequence using a seed derived from the IP strings. This means the same IP pair always produces the same path — consistent for demo purposes.

The hop sequence models a realistic ISP path:
```
Client LAN → ISP Edge → Regional POP → National Backbone → IXP → Destination AS
```

ISP profiles (latency ranges, hop counts, ASN data) are selected based on the source IP's first octet. ASN and country data for each hop is then enriched with **live ipinfo.io lookups** in `app.py`.

> **Note:** The hop path itself is simulated. Ping results and ASN enrichment are real.

---

## Data Flow — Route Computation

```
POST /compute_route
        │
        ▼
app.py extracts form fields (source, dest, selected algorithms)
        │
        ▼
route_service.compute_route(src, dst, selected_algos)
        │
        ├── validates routers exist in topology
        ├── checks path connectivity (nx.has_path)
        ├── runs each algorithm: algo.compute(topology, src, dst)
        ├── picks optimal by min cost + display priority
        ├── generates network.png via NetworkVisualizer
        ├── stores snapshot in _last_results[(src,dst)]
        └── returns result dict with path_ips, src_ip, dst_ip
        │
        ▼
app.py adds: congestion_active, algorithm_rec, comparison
        │
        ▼
render_template("result.html", ...)
```

---

## Data Flow — Packet Capture

```
POST /api/capture_packets  (JSON body)
        │
        ▼
app.py validates src_ip, dst_ip, count
        │
        ▼
analyzer.simulate_traffic(src_ip, dst_ip, count)
  └── resets self.packets
  └── builds session-ordered packet list
  └── assigns realistic ports, TTLs, flags, payloads
        │
        ▼
app.py: real_https_probe(dst_ip) — inject live TLS info if available
        │
        ▼
filter by protocol if requested
        │
        ▼
return JSON: {packets: [...], stats: {...}}
```

---

## Key Design Decisions

**Why adjacency list + NetworkX?**
The adjacency list gives O(degree) neighbor iteration for routing algorithms. NetworkX is only used for `has_path` and `is_connected` — operations that are expensive to implement correctly from scratch. This avoids duplicating graph traversal logic while keeping algorithm code clean.

**Why reset PacketAnalyzer.packets on each capture?**
The global `analyzer` object persists for the lifetime of the server process. Without resetting, hundreds of captures would accumulate thousands of stale packets, making `/api/packet_detail/<id>` searches progressively slower. Each capture is self-contained — there is no meaningful use case for querying packets from a previous session.

**Why deterministic traceroute simulation?**
Determinism (via IP-seeded RNG) means the same src/dst always produces the same hop path. This is intentional for demo stability — non-deterministic paths would make it hard to explain results or reproduce screenshots.

**Why `_last_results` for before/after comparison?**
The before/after congestion comparison requires knowing what costs looked like before congestion was applied. Since topology state is mutable (congestion changes link costs), we snapshot results after each `compute_route` call and diff against them when congestion is active.
