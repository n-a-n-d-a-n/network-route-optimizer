"""services/benchmark_service.py — Standalone algorithm benchmark utility.

NOT used by the Flask app. Run directly to compare algorithm timing:
    python3 -m services.benchmark_service
"""
import time
from core.topology_generator import TopologyGenerator
from core.algorithms import Dijkstra, BellmanFord


class BenchmarkService:
    def __init__(self):
        self.generator = TopologyGenerator()

    def run_benchmark(self, sizes=None):
        if sizes is None:
            sizes = [10, 50, 100, 200]
        results = []

        for size in sizes:
            network = self.generator.generate_random_network(size)
            routers = network.get_routers()
            if len(routers) < 2:
                continue
            source = routers[0]
            destination = routers[-1]

            dijkstra = Dijkstra()
            start = time.perf_counter()
            dijkstra.compute(network, source, destination)
            dijkstra_time = (time.perf_counter() - start) * 1000

            bellman = BellmanFord()
            start = time.perf_counter()
            bellman.compute(network, source, destination)
            bellman_time = (time.perf_counter() - start) * 1000

            results.append({
                "size":          size,
                "dijkstra_ms":   round(dijkstra_time, 4),
                "bellman_ms":    round(bellman_time, 4),
            })

        return results


if __name__ == "__main__":
    svc = BenchmarkService()
    print(f"{'Routers':>8}  {'Dijkstra (ms)':>14}  {'Bellman-Ford (ms)':>18}")
    print("-" * 46)
    for row in svc.run_benchmark():
        print(f"{row['size']:>8}  {row['dijkstra_ms']:>14.4f}  {row['bellman_ms']:>18.4f}")
