"""services/report_service.py — Generates a network health report from the current topology."""
from core.topology import NetworkTopology


def generate_report(network: NetworkTopology) -> dict:
    """Analyse the topology and return a structured health report dict."""
    routers = network.get_routers()

    if not routers:
        return None

    # ── Collect all unique links ────────────────────────────────────────
    seen = set()
    links_data = []
    for router in routers:
        for link in network.get_neighbors(router):
            pair = tuple(sorted([router, link.destination]))
            if pair not in seen:
                seen.add(pair)
                links_data.append({
                    "source":      router,
                    "destination": link.destination,
                    "delay":       round(link.delay, 2),
                    "bandwidth":   round(link.bandwidth, 1),
                    "congestion":  round(link.congestion, 2),
                    "cost":        round(link.get_cost(), 3),
                })

    n_routers = len(routers)
    n_links   = len(links_data)
    connected  = network.is_connected()

    # Theoretical max links for full mesh
    max_links  = n_routers * (n_routers - 1) // 2 if n_routers > 1 else 1
    redundancy = round(n_links / max(max_links, 1) * 100)

    congested_links = [l for l in links_data if l["congestion"] > 0]
    high_delay_links = [l for l in links_data if l["delay"] > 15]
    avg_cost = round(sum(l["cost"] for l in links_data) / max(len(links_data), 1), 2)
    max_cost = max((l["cost"] for l in links_data), default=0)

    # ── Topology analysis rows ───────────────────────────────────────────
    topology_rows = [
        {
            "property": "Network Connectivity",
            "value":    "Fully Connected" if connected else "Partitioned",
            "status":   "ok" if connected else "danger",
            "explanation": "All routers can reach each other" if connected
                           else "Some routers are isolated — add more links"
        },
        {
            "property": "Router Count",
            "value":    str(n_routers),
            "status":   "ok" if n_routers >= 3 else "warn",
            "explanation": "Good network size for redundancy" if n_routers >= 3
                           else "Small topology — consider adding more routers"
        },
        {
            "property": "Link Count",
            "value":    str(n_links),
            "status":   "ok" if n_links >= n_routers else "warn",
            "explanation": f"{n_links} links across {n_routers} routers"
        },
        {
            "property": "Mesh Redundancy",
            "value":    f"{redundancy}%",
            "status":   "ok" if redundancy >= 50 else ("warn" if redundancy >= 25 else "danger"),
            "explanation": f"{redundancy}% of full mesh — {'good redundancy' if redundancy>=50 else 'low redundancy, single points of failure likely'}"
        },
        {
            "property": "Congested Links",
            "value":    str(len(congested_links)),
            "status":   "ok" if not congested_links else ("warn" if len(congested_links) == 1 else "danger"),
            "explanation": "No congestion detected" if not congested_links
                           else f"{len(congested_links)} link(s) have added congestion — may cause sub-optimal routing"
        },
        {
            "property": "Average Link Cost",
            "value":    str(avg_cost),
            "status":   "ok" if avg_cost < 20 else ("warn" if avg_cost < 50 else "danger"),
            "explanation": "Lower cost = faster paths. High cost suggests high delay or low bandwidth links."
        },
    ]

    # ── Per-metric health cards ─────────────────────────────────────────
    metrics = [
        {
            "icon": "🔗", "title": "Connectivity",
            "value": "✅ Connected" if connected else "🚨 Partitioned",
            "cls": "ok" if connected else "danger",
            "description": "All routers reachable" if connected else "Isolated routers detected"
        },
        {
            "icon": "📡", "title": "Total Links",
            "value": str(n_links),
            "cls": "ok" if n_links >= n_routers else "warn",
            "description": f"Covering {n_routers} routers"
        },
        {
            "icon": "⚠️", "title": "Congested Links",
            "value": str(len(congested_links)),
            "cls": "ok" if not congested_links else ("warn" if len(congested_links) == 1 else "danger"),
            "description": "Links with added latency"
        },
        {
            "icon": "⏱", "title": "High-Delay Links",
            "value": str(len(high_delay_links)),
            "cls": "ok" if not high_delay_links else "warn",
            "description": "Links with delay > 15ms"
        },
        {
            "icon": "📊", "title": "Avg Link Cost",
            "value": str(avg_cost),
            "cls": "ok" if avg_cost < 20 else ("warn" if avg_cost < 50 else "danger"),
            "description": "Lower is better"
        },
        {
            "icon": "🔀", "title": "Mesh Redundancy",
            "value": f"{redundancy}%",
            "cls": "ok" if redundancy >= 50 else ("warn" if redundancy >= 25 else "danger"),
            "description": "Of full-mesh coverage"
        },
    ]

    # ── Recommendations ─────────────────────────────────────────────────
    recommendations = []

    if not connected:
        recommendations.append({
            "priority": "high", "icon": "🔴",
            "title": "Fix Network Partitioning",
            "detail": "Some routers cannot reach each other. Add links between isolated routers to restore full connectivity."
        })

    if congested_links:
        for lnk in congested_links:
            recommendations.append({
                "priority": "high", "icon": "🚦",
                "title": f"Relieve Congestion: {lnk['source']} ↔ {lnk['destination']}",
                "detail": f"This link has {lnk['congestion']}ms of congestion. Use Reset Congestion on the dashboard, or increase bandwidth on an alternate path."
            })

    if high_delay_links:
        recommendations.append({
            "priority": "medium", "icon": "⏱",
            "title": "Reduce High-Latency Links",
            "detail": f"{len(high_delay_links)} link(s) have delay > 15ms. Consider adding a lower-latency parallel path or upgrading the physical link."
        })

    if redundancy < 30:
        recommendations.append({
            "priority": "medium", "icon": "🔀",
            "title": "Increase Network Redundancy",
            "detail": f"Only {redundancy}% mesh coverage. Add more links between routers to ensure traffic can reroute if a link fails."
        })

    if not recommendations:
        recommendations.append({
            "priority": "low", "icon": "✅",
            "title": "Network is Well-Configured",
            "detail": "No major issues detected. Continue monitoring with the Packet Analyzer to catch congestion early."
        })

    # ── Score calculation ────────────────────────────────────────────────
    score = 100
    if not connected:          score -= 40
    score -= len(congested_links) * 10
    score -= len(high_delay_links) * 5
    if redundancy < 25:        score -= 15
    elif redundancy < 50:      score -= 8
    if avg_cost > 50:          score -= 10
    elif avg_cost > 20:        score -= 5
    score = max(0, min(100, score))

    if score >= 85:
        grade   = "🟢 Excellent Network Health"
        summary = "Your network topology is well-designed with good redundancy, low latency, and no congestion."
        verdict = "Keep monitoring traffic with the Packet Analyzer to stay ahead of any issues."
    elif score >= 70:
        grade   = "🟡 Good — Minor Issues"
        summary = "Network is functional but has some sub-optimal conditions worth addressing."
        verdict = "Review the recommendations below and address medium-priority items to improve performance."
    elif score >= 50:
        grade   = "🟠 Fair — Needs Attention"
        summary = "Several issues detected that will impact routing performance and reliability."
        verdict = "Apply congestion fixes and increase redundancy before this topology goes into production."
    else:
        grade   = "🔴 Poor — Critical Problems"
        summary = "Significant network problems detected — routing may fail or be severely sub-optimal."
        verdict = "Address all critical issues immediately. Start with connectivity, then congestion, then redundancy."

    critical_count = len([m for m in metrics if m["cls"] == "danger"])
    warning_count  = len([m for m in metrics if m["cls"] == "warn"])
    ok_count       = len([m for m in metrics if m["cls"] == "ok"])

    return {
        "score":          score,
        "grade":          grade,
        "summary":        summary,
        "verdict":        verdict,
        "critical_count": critical_count,
        "warning_count":  warning_count,
        "ok_count":       ok_count,
        "metrics":        metrics,
        "topology":       topology_rows,
        "links":          links_data,
        "recommendations": recommendations,
    }
