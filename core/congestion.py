# core/congestion.py — Enhanced congestion simulator with edge-case handling

import random


class CongestionSimulator:
    """
    Simulates network congestion by modifying link congestion values.
    Handles edge cases: non-existent links, zero-router topologies, etc.
    """

    def __init__(self, topology):
        self.topology = topology

    def apply_random_congestion(self, max_increase=5.0):
        """
        Randomly increases congestion on all links.
        max_increase: maximum additional congestion (ms) per link.
        """
        max_increase = max(0.0, float(max_increase))
        for router in self.topology.get_routers():
            for link in self.topology.get_neighbors(router):
                link.congestion += random.uniform(0, max_increase)

    def apply_congestion_to_link(self, source: str, destination: str, value: float):
        """
        Applies specific congestion value to a link.
        Silently ignores if the link doesn't exist.
        """
        value = max(0.0, float(value))

        for link in self.topology.get_neighbors(source):
            if link.destination == destination:
                link.congestion += value

        for link in self.topology.get_neighbors(destination):
            if link.destination == source:
                link.congestion += value

        # Re-sync NetworkX weights after congestion change
        try:
            self.topology._sync_nx_weights()
        except Exception:
            pass

    def reset_congestion(self):
        """Resets congestion on all links to zero."""
        for router in self.topology.get_routers():
            for link in self.topology.get_neighbors(router):
                link.congestion = 0.0

        try:
            self.topology._sync_nx_weights()
        except Exception:
            pass

    def get_congestion_report(self) -> dict:
        """Returns a report of all congested links (congestion > 0)."""
        report = {}
        seen = set()
        for router in self.topology.get_routers():
            for link in self.topology.get_neighbors(router):
                pair = tuple(sorted([router, link.destination]))
                if pair not in seen and link.congestion > 0:
                    seen.add(pair)
                    report[f"{pair[0]}—{pair[1]}"] = round(link.congestion, 2)
        return report
