"""test_routing_table.py — RoutingTableGenerator tests."""
import pytest
from core.topology import NetworkTopology
from core.routing_table import RoutingTableGenerator


@pytest.fixture
def network():
    net = NetworkTopology()
    net.add_link("A", "B", delay=2, congestion=1, bandwidth=5)
    net.add_link("A", "C", delay=1, congestion=0, bandwidth=10)
    net.add_link("C", "D", delay=3, congestion=2, bandwidth=8)
    net.add_link("B", "D", delay=4, congestion=1, bandwidth=6)
    return net


def test_tables_generated_for_all_routers(network):
    tables = RoutingTableGenerator(network).generate_all_routing_tables()
    assert set(tables.keys()) == {"A", "B", "C", "D"}


def test_each_router_has_routes_to_all_others(network):
    tables = RoutingTableGenerator(network).generate_all_routing_tables()
    routers = {"A", "B", "C", "D"}
    for router, table in tables.items():
        expected_dests = routers - {router}
        assert set(table.keys()) == expected_dests, \
            f"Router {router} missing destinations: {expected_dests - set(table.keys())}"


def test_route_entries_have_required_fields(network):
    tables = RoutingTableGenerator(network).generate_all_routing_tables()
    for router, table in tables.items():
        for dest, info in table.items():
            assert "next_hop" in info, f"{router}->{dest} missing next_hop"
            assert "cost" in info, f"{router}->{dest} missing cost"
            assert info["cost"] > 0, f"{router}->{dest} cost should be positive"


def test_costs_are_symmetric(network):
    tables = RoutingTableGenerator(network).generate_all_routing_tables()
    # Undirected graph: cost A->D should equal cost D->A
    cost_ad = tables["A"]["D"]["cost"]
    cost_da = tables["D"]["A"]["cost"]
    assert abs(cost_ad - cost_da) < 0.01, \
        f"Asymmetric costs: A->D={cost_ad}, D->A={cost_da}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
