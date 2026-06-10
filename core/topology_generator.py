import random
from core.topology import NetworkTopology


class TopologyGenerator:
    """
    Generates connected random network topologies
    for scalability and performance testing.
    """

    def generate_random_network(self, num_nodes, edge_density=0.3):
        """
        Generates a connected random network.

        :param num_nodes: Number of routers
        :param edge_density: Probability of extra links
        :return: NetworkTopology object
        """

        topology = NetworkTopology()

        # -----------------------------
        # Create Routers
        # -----------------------------
        for i in range(num_nodes):
            topology.add_router(f"R{i}")

        routers = topology.get_routers()

        # -----------------------------
        # Ensure Connectivity (Chain)
        # -----------------------------
        for i in range(num_nodes - 1):
            self._add_random_link(topology, routers[i], routers[i + 1])

        # -----------------------------
        # Add Extra Random Links
        # -----------------------------
        for i in range(num_nodes):
            for j in range(i + 2, num_nodes):
                if random.random() < edge_density:
                    self._add_random_link(topology, routers[i], routers[j])

        return topology

    def _add_random_link(self, topology, r1, r2):
        """
        Adds a link with random realistic metrics.
        """

        delay = random.randint(1, 20)          # ms
        bandwidth = random.randint(1, 100)     # Mbps
        congestion = random.randint(0, 10)     # load factor

        topology.add_link(
            r1,
            r2,
            delay=delay,
            congestion=congestion,
            bandwidth=bandwidth
        )
