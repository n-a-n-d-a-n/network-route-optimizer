# core/routing_table.py

from core.routing_algorithms import DijkstraRouting


class RoutingTableGenerator:
    """
    Generates routing tables for all routers in the network.
    """

    def __init__(self, topology):
        self.topology = topology
        self.dijkstra = DijkstraRouting(topology)

    def generate_table_for_router(self, router):
        """
        Generates routing table for a single router.
        Returns:
            {
                destination: {
                    "next_hop": router,
                    "cost": total_cost
                }
            }
        """

        distances, previous = self.dijkstra.compute_shortest_path(router)

        routing_table = {}

        for destination in distances:
            if destination == router:
                continue

            next_hop = self._get_next_hop(previous, router, destination)

            routing_table[destination] = {
                "next_hop": next_hop,
                "cost": round(distances[destination], 2)
            }

        return routing_table

    def generate_all_routing_tables(self):
        """
        Generates routing tables for every router in the network.
        """

        all_tables = {}

        for router in self.topology.get_routers():
            all_tables[router] = self.generate_table_for_router(router)

        return all_tables

    def _get_next_hop(self, previous, start, destination):
        """
        Determines the next hop for reaching destination from start.
        """

        current = destination
        path = []

        while current is not None:
            path.append(current)
            current = previous[current]

        path.reverse()

        if len(path) > 1:
            return path[1]  # next hop
        else:
            return None
