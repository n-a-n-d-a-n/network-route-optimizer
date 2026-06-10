# Congestion-Aware Route Optimizer

A Flask web application that simulates and visualises network routing algorithms with real-time congestion modelling, packet analysis, and live network diagnostics.

Built as a Computer Networks course project (Group 10).

---

## Features

- **10 routing algorithms** — Dijkstra, Bellman-Ford, A\*, Floyd-Warshall, OSPF, Widest Path, BFS, DFS, Greedy Best-First, Simulated Annealing
- **Live congestion simulation** — apply congestion to links and watch algorithms reroute in real time
- **Packet Analyzer** — simulate realistic TCP/UDP/ICMP/DNS/TLS packet captures with per-session statistics
- **IP Route Analyzer** — simulated ISP-grade traceroute enriched with live ASN, ping, and DNS data
- **Health Report** — live interface stats, congestion cascade analysis, routing protocol recommendations
- **Routing Tables** — per-router forwarding tables generated from the current topology

---

## Requirements

- Python 3.9 or higher
- pip

---

## Installation

```bash
# 1. Clone or unzip the project
cd cn_project_v2

# 2. (Optional but recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the App

```bash
python3 app.py
```

Then open your browser at: **http://localhost:5000**

---

## Environment Variables

All variables are optional. The app runs fine without setting any of them.

| Variable | Default | Description |
|---|---|---|
| `CN_SECRET_KEY` | `kavach-congestion-aware-g10-dev` | Flask session secret key. Set a strong random value in production. |
| `CN_DEBUG` | `false` | Set to `true` to enable Flask's interactive debugger. Never use in production. |
| `CN_PORT` | `5000` | Port the app listens on. |

Example:
```bash
CN_PORT=8080 python3 app.py
```

---

## Running Tests

```bash
# Run all test files individually
python3 test_routing.py
python3 test_service.py
python3 test_routing_table.py
python3 test_congestion.py
python3 test_topology.py

# Or run with pytest (shows pass/fail per assertion)
pip install pytest
pytest test_*.py -v
```

Run the algorithm benchmark (standalone, not part of the app):
```bash
python3 -m services.benchmark_service
```

---

## Project Structure

```
cn_project_v2/
├── app.py                        # Flask application — all routes and API endpoints
├── requirements.txt
├── README.md
│
├── core/                         # Core networking logic
│   ├── algorithms.py             # All 10 routing algorithm implementations
│   ├── topology.py               # Network graph (adjacency list + NetworkX mirror)
│   ├── packet_analyzer.py        # Packet capture simulation
│   ├── ip_network.py             # IP validation, traceroute simulation, subnet tools
│   ├── real_network.py           # Live DNS, ping, ASN lookup, HTTPS probe, interface stats
│   ├── congestion.py             # Congestion simulator
│   ├── routing_table.py          # Per-router forwarding table generator
│   ├── routing_algorithms.py     # Dijkstra used by routing table generator
│   ├── bellman_ford.py           # Standalone Bellman-Ford (used by routing table)
│   ├── visualization.py          # NetworkX/Matplotlib graph image generator
│   └── topology_generator.py    # Random topology generator (used by benchmark)
│
├── services/                     # Business logic layer
│   ├── route_service.py          # Main service — wraps topology, algorithms, comparison
│   ├── report_service.py         # Health report generation
│   ├── ip_tools.py               # Subnet analysis, NAT simulation, routing necessity
│   ├── routing_analysis.py       # Protocol mapping, RIP warnings, cascade analysis
│   └── benchmark_service.py     # Standalone algorithm timing benchmark (not used by app)
│
├── templates/                    # Jinja2 HTML templates
│   ├── index.html                # Main page — topology builder, route controls
│   ├── result.html               # Topology route results
│   ├── ip_result.html            # IP route / traceroute results
│   ├── packet_analyzer.html      # Packet capture UI
│   ├── routing_table.html        # Routing table viewer
│   └── report.html               # Network health report
│
├── static/
│   └── network.png               # Auto-generated topology graph image
│
├── docs/
│   └── architecture.md           # System architecture and design notes
│
└── test_*.py                     # Test files
```

---

## Quick Start (Demo Topology)

1. Open the app at http://localhost:5000
2. Under **Add Network Link**, add a few links, e.g.:
   - Source: `A`, Destination: `B`, Delay: `2`, Bandwidth: `10`
   - Source: `A`, Destination: `C`, Delay: `1`, Bandwidth: `20`
   - Source: `C`, Destination: `D`, Delay: `3`, Bandwidth: `8`
   - Source: `B`, Destination: `D`, Delay: `4`, Bandwidth: `6`
3. Under **Compute Route**, select Source `A`, Destination `D`, click Compute
4. Apply congestion to a link and recompute to see rerouting in action
5. Click **Packet Analyzer** to simulate a packet capture between the route's IPs
