# core/bellman_ford.py

import time


class BellmanFordRouting:
    """
    Implements Bellman-Ford Algorithm
    Simulates Distance Vector Routing (like RIP).
    """

    def __init__(self, topology):
        self.topology = topology

    def compute_shortest_path(self, start_router):
        """
        Computes shortest paths from start_router to all routers.
        Returns:
            distances, previous, execution_time
        """

        start_time = time.perf_counter()

        routers = self.topology.get_routers()

        distances = {router: float('inf') for router in routers}
        previous = {router: None for router in routers}

        distances[start_router] = 0

        # Relax edges (V-1 times)
        for _ in range(len(routers) - 1):
            for router in routers:
                for link in self.topology.get_neighbors(router):
                    neighbor = link.destination
                    cost = link.get_cost()

                    if distances[router] + cost < distances[neighbor]:
                        distances[neighbor] = distances[router] + cost
                        previous[neighbor] = router

        end_time = time.perf_counter()
        execution_time = end_time - start_time

        return distances, previous, execution_time

    def reconstruct_path(self, previous, start_router, end_router):
        path = []
        current = end_router

        while current is not None:
            path.append(current)
            current = previous[current]

        path.reverse()

        if path and path[0] == start_router:
            return path
        else:
            return []
