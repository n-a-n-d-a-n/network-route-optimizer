"""test_topology.py — NetworkTopology structure and link management."""
import pytest
from core.topology import NetworkTopology


@pytest.fixture
def network():
    net = NetworkTopology()
    net.add_link("A", "B", delay=2, congestion=1, bandwidth=5)
    net.add_link("A", "C", delay=1, congestion=0, bandwidth=10)
    net.add_link("C", "D", delay=3, congestion=2, bandwidth=8)
    return net


def test_routers_registered(network):
    routers = network.get_routers()
    assert set(routers) == {"A", "B", "C", "D"}


def test_links_are_bidirectional(network):
    assert network.get_link("A", "B") is not None
    assert network.get_link("B", "A") is not None


def test_link_attributes(network):
    link = network.get_link("A", "C")
    assert link.delay == 1.0
    assert link.bandwidth == 10.0
    assert link.congestion == 0.0


def test_link_cost_positive(network):
    link = network.get_link("A", "B")
    assert link.get_cost() > 0


def test_remove_link(network):
    network.remove_link("A", "B")
    assert network.get_link("A", "B") is None
    assert network.get_link("B", "A") is None
    assert "B" in network.get_routers(), "Router B should still exist after link removal"


def test_self_loop_raises(network):
    with pytest.raises(ValueError):
        network.add_link("A", "A")


def test_empty_router_name_raises(network):
    with pytest.raises(ValueError):
        network.add_link("", "B")


def test_connectivity(network):
    assert network.has_path("A", "D")
    assert not network.has_path("B", "D"), "B->D disconnected after B is isolated"


def test_router_ip_assignment(network):
    ip_a = network.get_router_ip("A")
    ip_b = network.get_router_ip("B")
    assert ip_a.startswith("10."), "IPs should be in 10.0.0.0/8"
    assert ip_a != ip_b, "Each router must get a unique IP"
    # IPs are stable — same call returns same IP
    assert network.get_router_ip("A") == ip_a


def test_summary(network):
    s = network.summary()
    assert s["routers"] == 4
    assert s["links"] == 3
    assert isinstance(s["connected"], bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
