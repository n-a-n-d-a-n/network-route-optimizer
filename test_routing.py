"""test_routing.py — Dijkstra shortest-path and path reconstruction."""
import pytest
from core.topology import NetworkTopology
from core.routing_algorithms import DijkstraRouting


@pytest.fixture
def network():
    net = NetworkTopology()
    net.add_link("A", "B", delay=2, congestion=1, bandwidth=5)
    net.add_link("A", "C", delay=1, congestion=0, bandwidth=10)
    net.add_link("C", "D", delay=3, congestion=2, bandwidth=8)
    net.add_link("B", "D", delay=4, congestion=1, bandwidth=6)
    return net


def test_dijkstra_distances(network):
    router = DijkstraRouting(network)
    distances, _ = router.compute_shortest_path("A")
    assert distances["A"] == 0.0
    assert distances["C"] < distances["B"], "A->C should be cheaper than A->B"
    assert distances["D"] < float("inf"), "D must be reachable"


def test_dijkstra_optimal_path(network):
    router = DijkstraRouting(network)
    _, previous = router.compute_shortest_path("A")
    path = router.reconstruct_path(previous, "A", "D")
    assert path[0] == "A" and path[-1] == "D"
    assert path == ["A", "C", "D"], f"Expected optimal path A->C->D, got {path}"


def test_dijkstra_unknown_source(network):
    router = DijkstraRouting(network)
    distances, previous = router.compute_shortest_path("Z")
    assert distances == {} and previous == {}


def test_reconstruct_path_empty_previous(network):
    router = DijkstraRouting(network)
    path = router.reconstruct_path({}, "A", "D")
    assert path == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
