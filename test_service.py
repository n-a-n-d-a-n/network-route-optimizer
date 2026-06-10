"""test_service.py — RouteService integration tests."""
import pytest
from services.route_service import RouteService


@pytest.fixture
def service():
    svc = RouteService()
    svc.add_link("A", "B", delay=2, bandwidth=5)
    svc.add_link("A", "C", delay=1, bandwidth=10)
    svc.add_link("C", "D", delay=3, bandwidth=8)
    svc.add_link("B", "D", delay=4, bandwidth=6)
    return svc


def test_compute_route_returns_optimal(service):
    result = service.compute_route("A", "D")
    assert "error" not in result
    assert result["optimal"]["path"] == ["A", "C", "D"]
    assert result["optimal"]["cost"] < float("inf")


def test_compute_route_includes_ips(service):
    result = service.compute_route("A", "D")
    assert result.get("src_ip"), "src_ip must be present"
    assert result.get("dst_ip"), "dst_ip must be present"


def test_compute_route_all_algorithms_run(service):
    result = service.compute_route("A", "D")
    assert len(result["results"]) == 10, "All 10 algorithms should run"


def test_congestion_increases_cost(service):
    before = service.compute_route("A", "D")["optimal"]["cost"]
    service.apply_congestion_to_link("A", "C", 10)
    after = service.compute_route("A", "D")["optimal"]["cost"]
    assert after > before, "Cost should increase after congestion"


def test_reset_clears_congestion(service):
    service.apply_congestion_to_link("A", "C", 10)
    service.reset_congestion()
    service._last_results.clear()
    result = service.compute_route("A", "D")
    assert result["optimal"]["path"] == ["A", "C", "D"]


def test_self_loop_raises(service):
    with pytest.raises(ValueError):
        service.add_link("A", "A")


def test_routing_tables_cover_all_routers(service):
    tables = service.generate_routing_tables()
    assert set(tables.keys()) == {"A", "B", "C", "D"}
    for router, table in tables.items():
        others = {"A", "B", "C", "D"} - {router}
        assert set(table.keys()) == others, f"{router} table missing destinations"


def test_unknown_source_returns_error(service):
    result = service.compute_route("Z", "D")
    assert "error" in result


def test_same_source_dest_returns_error(service):
    result = service.compute_route("A", "A")
    assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
