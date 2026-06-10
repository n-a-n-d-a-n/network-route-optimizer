"""test_congestion.py — CongestionSimulator and its effect on routing."""
import pytest
from core.topology import NetworkTopology
from core.routing_algorithms import DijkstraRouting
from core.congestion import CongestionSimulator


@pytest.fixture
def setup():
    network = NetworkTopology()
    network.add_link("A", "B", delay=2, congestion=0, bandwidth=5)
    network.add_link("A", "C", delay=1, congestion=0, bandwidth=10)
    network.add_link("C", "D", delay=3, congestion=0, bandwidth=8)
    network.add_link("B", "D", delay=4, congestion=0, bandwidth=6)
    router = DijkstraRouting(network)
    simulator = CongestionSimulator(network)
    return network, router, simulator


def test_initial_path_is_optimal(setup):
    network, router, _ = setup
    _, previous = router.compute_shortest_path("A")
    path = router.reconstruct_path(previous, "A", "D")
    assert path == ["A", "C", "D"], f"Expected A->C->D, got {path}"


def test_congestion_increases_link_cost(setup):
    network, router, simulator = setup
    _, prev_before = router.compute_shortest_path("A")
    cost_before = router.compute_shortest_path("A")[0]["D"]

    simulator.apply_congestion_to_link("A", "C", value=10)
    cost_after = router.compute_shortest_path("A")[0]["D"]

    assert cost_after > cost_before, "Congestion must increase path cost"


def test_congestion_stored_on_link(setup):
    network, _, simulator = setup
    simulator.apply_congestion_to_link("A", "C", value=5)
    link = network.get_link("A", "C")
    assert link is not None
    assert link.congestion == 5.0


def test_reset_congestion_zeroes_all_links(setup):
    network, _, simulator = setup
    simulator.apply_congestion_to_link("A", "C", value=10)
    simulator.apply_congestion_to_link("B", "D", value=7)
    simulator.reset_congestion()
    for router in network.get_routers():
        for link in network.get_neighbors(router):
            assert link.congestion == 0.0, \
                f"Link {router}->{link.destination} still has congestion after reset"


def test_nonexistent_link_congestion_is_noop(setup):
    network, _, simulator = setup
    # Applying congestion to a non-existent link should not raise or modify anything
    simulator.apply_congestion_to_link("X", "Y", value=10)
    for router in network.get_routers():
        for link in network.get_neighbors(router):
            assert link.congestion == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
