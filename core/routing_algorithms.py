"""core/routing_algorithms.py — Dijkstra implementation used by RoutingTableGenerator."""
import heapq


class DijkstraRouting:
    def __init__(self, topology):
        self.topology = topology

    def compute_shortest_path(self, source: str):
        """
        Returns (distances dict, previous dict) from source to all routers.
        Used by RoutingTableGenerator to build per-router forwarding tables.
        """
        routers = self.topology.get_routers()
        if source not in routers:
            return {}, {}

        dist = {r: float('inf') for r in routers}
        prev = {r: None for r in routers}
        dist[source] = 0.0
        pq = [(0.0, source)]
        visited = set()

        while pq:
            d, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            for link in self.topology.get_neighbors(u):
                v = link.destination
                if v not in dist:
                    continue
                nd = d + link.get_cost()
                if nd < dist[v]:
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))

        return dist, prev

    def reconstruct_path(self, previous: dict, start_router: str, end_router: str) -> list:
        """Reconstruct path from the previous-node dict returned by compute_shortest_path."""
        path = []
        current = end_router
        while current is not None:
            path.append(current)
            current = previous.get(current)
        path.reverse()
        if path and path[0] == start_router:
            return path
        return []

