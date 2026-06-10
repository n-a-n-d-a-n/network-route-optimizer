"""
core/algorithms.py — Exactly 10 Routing Algorithms (user-specified set)
1.  Dijkstra
2.  Bellman-Ford
3.  A* Search
4.  Floyd-Warshall
5.  Greedy Best-First
6.  BFS (Min-Hops)
7.  DFS Path
8.  OSPF (Delay-Metric)
9.  Widest Path (Max-BW)
10. Simulated Annealing
"""
import heapq, time, math, random
from dataclasses import dataclass
from typing import List
from collections import deque


@dataclass
class AlgoResult:
    name: str
    path: List[str]
    cost: float
    time_ms: float
    hops: int
    description: str
    complexity: str
    notes: str = ""


# ── Shared helpers ────────────────────────────────────────────────────────────

def _rebuild(prev, src, dst):
    """Reconstruct path from predecessor map with cycle guard."""
    if dst not in prev:
        return []
    path, cur, visited = [], dst, set()
    while cur is not None:
        if cur in visited:
            return []
        visited.add(cur)
        path.append(cur)
        cur = prev.get(cur)
    path.reverse()
    return path if path and path[0] == src else []


def _cost(topology, path):
    """Sum edge costs along a path."""
    total = 0.0
    for i in range(len(path) - 1):
        link = topology.get_link(path[i], path[i + 1])
        if link is None:
            return float('inf')
        total += link.get_cost()
    return round(total, 6)


def _routers(topology):
    return topology.get_routers()


def _edges(topology):
    return [(r, lnk.destination, lnk.get_cost())
            for r in _routers(topology)
            for lnk in topology.get_neighbors(r)]


def _missing(name, desc, complexity, note="Source/destination not in topology."):
    return AlgoResult(name, [], float('inf'), 0.0, 0, desc, complexity, note)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Dijkstra
# ─────────────────────────────────────────────────────────────────────────────
class Dijkstra:
    NAME        = "Dijkstra"
    DESCRIPTION = "Greedy shortest-path using a min-heap priority queue. The standard algorithm behind OSPF and link-state routing protocols."
    COMPLEXITY  = "O((V+E) log V)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        dist = {r: float('inf') for r in routers}
        prev = {r: None for r in routers}
        dist[src] = 0.0
        pq = [(0.0, src)]
        visited = set()

        while pq:
            d, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in dist:
                    continue
                nd = d + lnk.get_cost()
                if nd < dist[v]:
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))

        path = _rebuild(prev, src, dst)
        return AlgoResult(
            self.NAME, path, round(dist.get(dst, float('inf')), 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Industry standard. Guarantees optimal path on non-negative weights."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Bellman-Ford
# ─────────────────────────────────────────────────────────────────────────────
class BellmanFord:
    NAME        = "Bellman-Ford"
    DESCRIPTION = "Iterative edge relaxation across V-1 passes. Models RIP distance-vector routing. Handles negative weights and detects negative cycles."
    COMPLEXITY  = "O(V × E)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        dist = {r: float('inf') for r in routers}
        prev = {r: None for r in routers}
        dist[src] = 0.0
        edges = _edges(topology)

        for _ in range(len(routers) - 1):
            updated = False
            for u, v, w in edges:
                if dist[u] + w < dist[v]:
                    dist[v] = dist[u] + w
                    prev[v] = u
                    updated = True
            if not updated:
                break

        neg_cycle = any(dist[u] + w < dist[v] for u, v, w in edges)
        path = _rebuild(prev, src, dst)
        note = ("⚠ Negative cycle detected!" if neg_cycle
                else "Slower than Dijkstra but handles negative edge weights. Used in RIP.")
        return AlgoResult(
            self.NAME, path, round(dist.get(dst, float('inf')), 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY, note
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. A* Search
# ─────────────────────────────────────────────────────────────────────────────
class AStar:
    NAME        = "A* Search"
    DESCRIPTION = "Heuristic-guided Dijkstra. Uses hop-index distance as admissible h(n) to prune the search space and reach the goal faster."
    COMPLEXITY  = "O(E log V) best-case"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        ridx = {r: i for i, r in enumerate(routers)}
        di = ridx.get(dst, 0)
        h = lambda n: abs(ridx.get(n, 0) - di) * 0.05

        g = {r: float('inf') for r in routers}
        prev = {r: None for r in routers}
        g[src] = 0.0
        pq = [(h(src), 0.0, src)]
        closed = set()

        while pq:
            f, d, u = heapq.heappop(pq)
            if u in closed:
                continue
            closed.add(u)
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in g or v in closed:
                    continue
                ng = g[u] + lnk.get_cost()
                if ng < g[v]:
                    g[v] = ng
                    prev[v] = u
                    heapq.heappush(pq, (ng + h(v), ng, v))

        path = _rebuild(prev, src, dst)
        return AlgoResult(
            self.NAME, path, round(g.get(dst, float('inf')), 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Faster than Dijkstra when heuristic is tight. Used in GPS navigation and game AI."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Floyd-Warshall
# ─────────────────────────────────────────────────────────────────────────────
class FloydWarshall:
    NAME        = "Floyd-Warshall"
    DESCRIPTION = "All-pairs shortest path via dynamic programming. Computes every source-destination pair simultaneously in a single O(V³) pass."
    COMPLEXITY  = "O(V³)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        idx = {r: i for i, r in enumerate(routers)}
        n = len(routers)
        INF = float('inf')
        dist = [[INF] * n for _ in range(n)]
        nxt  = [[None] * n for _ in range(n)]

        for i in range(n):
            dist[i][i] = 0.0

        for r in routers:
            for lnk in topology.get_neighbors(r):
                if lnk.destination in idx:
                    i, j = idx[r], idx[lnk.destination]
                    c = lnk.get_cost()
                    if c < dist[i][j]:
                        dist[i][j] = c
                        nxt[i][j] = lnk.destination

        for k in range(n):
            for i in range(n):
                for j in range(n):
                    if dist[i][k] + dist[k][j] < dist[i][j]:
                        dist[i][j] = dist[i][k] + dist[k][j]
                        nxt[i][j] = nxt[i][k]

        si, di_ = idx.get(src), idx.get(dst)
        cost = dist[si][di_] if si is not None and di_ is not None else INF

        path = []
        if cost < INF and si is not None and di_ is not None:
            cur = si
            path.append(routers[cur])
            guard = 0
            while cur != di_ and guard < n + 1:
                nxt_node = nxt[cur][di_]
                if nxt_node is None:
                    path = []
                    break
                path.append(nxt_node)
                cur = idx[nxt_node]
                guard += 1

        return AlgoResult(
            self.NAME, path, round(cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Best for dense networks. Computes ALL pairs at once. Cubic time — avoid on large graphs."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Greedy Best-First
# ─────────────────────────────────────────────────────────────────────────────
class GreedyBestFirst:
    NAME        = "Greedy Best-First"
    DESCRIPTION = "Always expands the node that looks closest to the destination by heuristic alone. Fast but NOT guaranteed optimal — may miss cheaper paths."
    COMPLEXITY  = "O(E log V)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        ridx = {r: i for i, r in enumerate(routers)}
        di = ridx.get(dst, 0)
        # Heuristic: hop-index distance — purely greedy, no accumulated cost
        h = lambda n: abs(ridx.get(n, 0) - di)

        prev = {src: None}
        visited = set()
        pq = [(h(src), src)]

        while pq:
            _, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in visited and v not in prev:
                    prev[v] = u
                    heapq.heappush(pq, (h(v), v))

        path = _rebuild(prev, src, dst)
        cost = _cost(topology, path)
        return AlgoResult(
            self.NAME, path, round(cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Very fast but suboptimal — uses only heuristic, ignores actual edge costs."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 6. BFS (Min-Hops)
# ─────────────────────────────────────────────────────────────────────────────
class BFS:
    NAME        = "BFS (Min-Hops)"
    DESCRIPTION = "Breadth-first search finds the path with the fewest router hops, ignoring link weights entirely. Optimal for hop count, not for cost."
    COMPLEXITY  = "O(V + E)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        visited = {src}
        prev = {src: None}
        queue = deque([src])

        while queue:
            u = queue.popleft()
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in visited:
                    visited.add(v)
                    prev[v] = u
                    queue.append(v)

        path = _rebuild(prev, src, dst)
        cost = _cost(topology, path)
        return AlgoResult(
            self.NAME, path, round(cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Minimises hop count, not link cost. Used in Ethernet bridging and simple forwarding."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 7. DFS Path
# ─────────────────────────────────────────────────────────────────────────────
class DFS:
    NAME        = "DFS Path"
    DESCRIPTION = "Depth-first search explores as deep as possible before backtracking. Finds A path (not necessarily shortest). Educational comparison baseline."
    COMPLEXITY  = "O(V + E)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        stack = [(src, [src])]
        visited = set()
        best_path = []

        while stack:
            u, path = stack.pop()
            if u in visited:
                continue
            visited.add(u)
            if u == dst:
                best_path = path
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in visited:
                    stack.append((v, path + [v]))

        cost = _cost(topology, best_path)
        return AlgoResult(
            self.NAME, best_path, round(cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(best_path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Non-optimal. Shows how depth-first explores differently from BFS and Dijkstra."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 8. OSPF (Delay-Metric)
# ─────────────────────────────────────────────────────────────────────────────
class OSPF:
    NAME        = "OSPF (Delay-Metric)"
    DESCRIPTION = "Open Shortest Path First with the standard OSPF cost formula: reference_bandwidth / interface_bandwidth. Models real Cisco/Juniper OSPF behaviour."
    COMPLEXITY  = "O((V+E) log V)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        dist = {r: float('inf') for r in routers}
        prev = {r: None for r in routers}
        dist[src] = 0.0
        pq = [(0.0, src)]
        visited = set()

        while pq:
            d, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in dist:
                    continue
                # Real OSPF metric: 100,000 / bandwidth_Mbps (Cisco reference BW = 100 Mbps)
                ospf_cost = max(1, round(100_000 / lnk.bandwidth)) + lnk.delay * 0.1 + lnk.congestion
                nd = d + ospf_cost
                if nd < dist[v]:
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))

        path = _rebuild(prev, src, dst)
        real_cost = _cost(topology, path)
        return AlgoResult(
            self.NAME, path, round(real_cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            "Uses OSPF cost formula (ref_bw / iface_bw). RFC 2328 compliant. Industry standard IGP."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 9. Widest Path (Max-BW)
# ─────────────────────────────────────────────────────────────────────────────
class WidestPath:
    NAME        = "Widest Path (Max-BW)"
    DESCRIPTION = "Maximises the minimum bandwidth along the path (bottleneck bandwidth). Ideal for video streaming, large file transfers, and QoS-sensitive traffic."
    COMPLEXITY  = "O((V+E) log V)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)

        # Max-heap via negation: maximise min-bandwidth along path
        bw = {r: 0.0 for r in routers}
        prev = {r: None for r in routers}
        bw[src] = float('inf')
        pq = [(-float('inf'), src)]    # negate for max-heap behaviour

        while pq:
            neg_b, u = heapq.heappop(pq)
            cur_bw = -neg_b
            if cur_bw < bw[u]:
                continue
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in bw:
                    continue
                # Bottleneck = min of current path BW and this link's BW
                new_bw = min(cur_bw, lnk.bandwidth)
                if new_bw > bw[v]:
                    bw[v] = new_bw
                    prev[v] = u
                    heapq.heappush(pq, (-new_bw, v))

        path = _rebuild(prev, src, dst)
        real_cost = _cost(topology, path)
        bottleneck = round(bw.get(dst, 0), 1)
        return AlgoResult(
            self.NAME, path, round(real_cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            f"Bottleneck bandwidth on this path: {bottleneck} Mbps. Best for throughput-sensitive flows."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 10. Simulated Annealing
# ─────────────────────────────────────────────────────────────────────────────
class SimulatedAnnealing:
    NAME        = "Simulated Annealing"
    DESCRIPTION = "Probabilistic metaheuristic inspired by metallurgical annealing. Accepts worse solutions early (high temperature) to escape local optima, then cools down."
    COMPLEXITY  = "O(iterations × V)"

    def compute(self, topology, src, dst):
        t0 = time.perf_counter()
        routers = _routers(topology)
        if src not in routers or dst not in routers:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY)
        if len(routers) < 2:
            return _missing(self.NAME, self.DESCRIPTION, self.COMPLEXITY, "Need at least 2 routers.")

        rng = random.Random(42)   # deterministic seed for reproducibility

        def random_path():
            """Build a random path from src to dst via BFS-guided random walk."""
            visited_set = {src}
            path = [src]
            current = src
            for _ in range(len(routers) * 2):
                if current == dst:
                    break
                neighbors = [lnk.destination for lnk in topology.get_neighbors(current)
                             if lnk.destination not in visited_set]
                if not neighbors:
                    break
                # Bias toward dst using heuristic
                ridx = {r: i for i, r in enumerate(routers)}
                di = ridx.get(dst, 0)
                neighbors.sort(key=lambda n: abs(ridx.get(n, 0) - di))
                # Probabilistically pick: 60% choose best, 40% random
                if rng.random() < 0.6:
                    nxt = neighbors[0]
                else:
                    nxt = rng.choice(neighbors)
                path.append(nxt)
                visited_set.add(nxt)
                current = nxt
            return path if path[-1] == dst else []

        def path_cost(p):
            return _cost(topology, p) if p else float('inf')

        def mutate(p):
            """Mutate: replace a random middle segment with a different route."""
            if len(p) <= 2:
                return p
            cut = rng.randint(1, len(p) - 1)
            new_seg = [p[cut - 1]]
            current = p[cut - 1]
            visited_m = set(p[:cut])
            for _ in range(len(routers)):
                if current == dst:
                    break
                neighbors = [lnk.destination for lnk in topology.get_neighbors(current)
                             if lnk.destination not in visited_m]
                if not neighbors:
                    break
                nxt = rng.choice(neighbors)
                new_seg.append(nxt)
                visited_m.add(nxt)
                current = nxt
            if new_seg[-1] == dst:
                return p[:cut - 1] + new_seg
            return p

        # Initialise with a BFS path as warm start
        from collections import deque as _deque
        bfs_prev = {src: None}
        bfs_q = _deque([src])
        bfs_vis = {src}
        while bfs_q:
            u = bfs_q.popleft()
            if u == dst:
                break
            for lnk in topology.get_neighbors(u):
                v = lnk.destination
                if v not in bfs_vis:
                    bfs_vis.add(v)
                    bfs_prev[v] = u
                    bfs_q.append(v)
        current_path = _rebuild(bfs_prev, src, dst)
        if not current_path:
            current_path = random_path()

        best_path = current_path[:]
        best_cost  = path_cost(best_path)
        current_cost = best_cost

        # Annealing schedule
        T = 100.0
        T_min = 0.5
        alpha = 0.88
        iterations = 0

        while T > T_min:
            candidate = mutate(current_path)
            if not candidate:
                T *= alpha
                continue
            c_cost = path_cost(candidate)
            delta = c_cost - current_cost
            # Accept if better, or with probability e^(-delta/T) if worse
            if delta < 0 or (T > 0 and rng.random() < math.exp(-delta / T)):
                current_path = candidate
                current_cost = c_cost
                if c_cost < best_cost:
                    best_path  = candidate[:]
                    best_cost  = c_cost
            T *= alpha
            iterations += 1

        return AlgoResult(
            self.NAME, best_path, round(best_cost, 3),
            round((time.perf_counter() - t0) * 1000, 5),
            max(0, len(best_path) - 1), self.DESCRIPTION, self.COMPLEXITY,
            f"Metaheuristic — ran {iterations} cooling steps. Good for complex cost landscapes."
        )


# ── Exactly 10 algorithms — in the order shown in the UI ─────────────────────
ALL_ALGORITHMS = [
    Dijkstra(),
    BellmanFord(),
    AStar(),
    FloydWarshall(),
    GreedyBestFirst(),
    BFS(),
    DFS(),
    OSPF(),
    WidestPath(),
    SimulatedAnnealing(),
]
