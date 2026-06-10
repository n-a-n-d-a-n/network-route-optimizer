"""app.py — Flask application — Congestion-Aware Route Optimizer (Final Version)"""
import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from services.route_service import RouteService
from services.report_service import generate_report
from services.ip_tools import (analyse_subnet, routing_necessity,
                                simulate_nat_table, detect_network_type)
from services.routing_analysis import (get_protocol_map, get_algo_protocol,
                                        convergence_analysis, rip_hop_warning,
                                        congestion_cascade, get_all_recommendations)
from core.packet_analyzer import PacketAnalyzer
from core.algorithms import ALL_ALGORITHMS
from core.ip_network import validate_ip
from core.real_network import (real_asn_lookup, real_ping,
                                real_dns_lookup, real_https_probe,
                                real_interface_stats)

app      = Flask(__name__)
# Secret key: set CN_SECRET_KEY environment variable in production.
# Falls back to a fixed dev key when running locally.
app.secret_key = os.environ.get("CN_SECRET_KEY", "kavach-congestion-aware-g10-dev")
service  = RouteService()
analyzer = PacketAnalyzer()
ALGO_NAMES = [a.NAME for a in ALL_ALGORITHMS]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_congestion_report():
    """Return list of congested links for the home-page panel."""
    routers = service.get_all_routers()
    congested = []
    seen = set()
    for r in routers:
        for lnk in service.network.get_neighbors(r):
            key = tuple(sorted([r, lnk.destination]))
            if key not in seen and lnk.congestion > 0:
                seen.add(key)
                congested.append({
                    "src": r, "dst": lnk.destination,
                    "congestion": lnk.congestion,
                    "bandwidth": lnk.bandwidth,
                })
    return congested


def _recommend_algorithm(network):
    """Context-aware algorithm recommendation based on topology state."""
    routers = network.get_routers()
    num_routers = len(routers)

    all_links = []
    seen = set()
    for r in routers:
        for lnk in network.get_neighbors(r):
            key = tuple(sorted([r, lnk.destination]))
            if key not in seen:
                seen.add(key)
                all_links.append(lnk)

    num_congested = sum(1 for l in all_links if l.congestion > 0)
    avg_bw = (sum(l.bandwidth for l in all_links) / len(all_links)) if all_links else 100

    if num_congested >= 3:
        return {
            "algo": "Dijkstra",
            "reason": (f"{num_congested} links are congested — Dijkstra recomputes the "
                       "shortest weighted path instantly, making it ideal for real-time "
                       "congestion-aware rerouting.")
        }
    elif avg_bw < 50:
        return {
            "algo": "OSPF (Link-State)",
            "reason": (f"Average bandwidth is low ({avg_bw:.1f} Mbps) — OSPF uses a full "
                       "link-state map so it finds bandwidth-optimal paths even on "
                       "constrained topologies.")
        }
    elif num_routers > 8:
        return {
            "algo": "A* Search",
            "reason": (f"Large topology ({num_routers} routers) — A* uses a heuristic to "
                       "prune the search space and finds the optimal path faster than "
                       "exhaustive algorithms.")
        }
    elif num_congested == 1:
        return {
            "algo": "Bellman-Ford",
            "reason": ("Single congested link detected — Bellman-Ford handles negative-weight "
                       "edges and detects anomalies that Dijkstra would miss.")
        }
    else:
        return {
            "algo": "Dijkstra",
            "reason": ("Healthy topology with balanced links — Dijkstra delivers the optimal "
                       "cost path with O((V+E) log V) efficiency.")
        }



# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    routers  = service.get_all_routers()
    net_type = None
    if routers:
        delays = [
            lnk.delay
            for r in routers
            for lnk in service.network.get_neighbors(r)
        ]
        if delays:
            net_type = detect_network_type(sum(delays) / len(delays))
    congestion_report = _get_congestion_report()
    router_ip_map = service.get_router_ip_map()
    return render_template("index.html",
                           routers=routers,
                           algo_names=ALGO_NAMES,
                           net_type=net_type,
                           congestion_report=congestion_report,
                           router_ip_map=router_ip_map)


@app.route("/packet_analyzer")
def packet_analyzer():
    return render_template("packet_analyzer.html",
                           app_recommendations=get_all_recommendations())


@app.route("/routing_tables")
def routing_tables():
    routers = service.get_all_routers()
    if not routers:
        return render_template("routing_table.html",
                               tables={}, total_routes=0,
                               error="No topology built yet. "
                                     "Add links on the main page first.")
    tables = service.generate_routing_tables()
    return render_template("routing_table.html",
                           tables=tables,
                           total_routes=sum(len(t) for t in tables.values()))


@app.route("/health_report")
def health_report():
    report     = generate_report(service.network)
    cascade    = None
    # ✅ BUG 1 FIXED — real_stats always defined outside every if-block
    real_stats = None

    if report and report.get("links"):
        cong_links = [l for l in report["links"] if l["congestion"] > 0]
        if cong_links:
            worst   = max(cong_links, key=lambda l: l["congestion"])
            cascade = congestion_cascade(worst["congestion"], worst["bandwidth"])

    # Always attempt real stats — safe fallback inside the function
    try:
        real_stats = real_interface_stats()
    except Exception:
        real_stats = {"real": False, "throughput_kbps": 0,
                      "interfaces": [], "total_drops": 0}

    return render_template("report.html",
                           report=report,
                           cascade=cascade,
                           real_stats=real_stats)


# ── Topology Actions ──────────────────────────────────────────────────────────

@app.route("/add_link", methods=["POST"])
def add_link():
    try:
        source = request.form.get("source", "").strip()
        dest   = request.form.get("destination", "").strip()
        delay  = float(request.form.get("delay", 1))
        bw     = float(request.form.get("bandwidth", 100))
        if not source or not dest:
            flash("⚠ Source and destination router names cannot be empty.", "warning")
            return redirect(url_for("index"))
        service.add_link(source, dest, delay=delay, bandwidth=bw)
        flash(f"✅ Link {source.upper()} ↔ {dest.upper()} added.", "success")
    except ValueError as e:
        flash(f"⚠ {e}", "warning")
    except TypeError:
        flash("⚠ Invalid delay or bandwidth value.", "warning")
    return redirect(url_for("index"))


@app.route("/compute_route", methods=["POST"])
def compute_route():
    selected = request.form.getlist("algorithms")
    src      = request.form.get("source", "").strip()
    dst      = request.form.get("destination", "").strip()
    result   = service.compute_route(
                   src, dst,
                   selected_algos=selected if selected else None)

    protocol_map = get_protocol_map()
    rip_warn     = None
    if result and result.get("optimal") and result["optimal"].get("hops"):
        rip_warn = rip_hop_warning(result["optimal"]["hops"])

    # Gap 2 — congestion_active flag
    congestion_active = bool(_get_congestion_report())

    # Gap 3 — context-aware algorithm recommendation
    algorithm_rec = _recommend_algorithm(service.network) if not result.get("error") else None

    # Gap 4 — before/after comparison (only when congestion is active)
    comparison = service.get_comparison(src.upper(), dst.upper()) if congestion_active else None

    return render_template("result.html",
                           result=result,
                           protocol_map=protocol_map,
                           rip_warn=rip_warn,
                           congestion_active=congestion_active,
                           algorithm_rec=algorithm_rec,
                           comparison=comparison)


@app.route("/compute_ip_route", methods=["POST"])
def compute_ip_route():
    selected = request.form.getlist("ip_algorithms")
    src_ip   = request.form.get("src_ip", "").strip()
    dst_ip   = request.form.get("dst_ip", "").strip()

    result = service.compute_ip_route(
                 src_ip, dst_ip,
                 selected_algos=selected if selected else None)

    # ✅ BUG 2 FIXED — every real call wrapped in try/except individually
    # Real BGP/ASN enrichment for every traceroute hop
    if result and result.get("hops") and not result.get("error"):
        for hop in result["hops"]:
            if hop.get("ip") and hop["ip"] not in ("*", ""):
                try:
                    bgp = real_asn_lookup(hop["ip"])
                    if bgp.get("real"):
                        hop["asn"]     = bgp["asn"]
                        hop["org"]     = bgp["org"]
                        hop["country"] = bgp["country"]
                        hop["city"]    = bgp.get("city", "")
                        hop["isp"]     = bgp["org"]
                except Exception:
                    pass  # keep simulated values if API fails

    # ✅ BUG 3 FIXED — real_ping only called when result has no error
    real_ping_result = None
    if result and not result.get("error") and dst_ip:
        try:
            real_ping_result = real_ping(dst_ip, count=3)
        except Exception:
            real_ping_result = None
    if result is not None:
        result["real_ping"] = real_ping_result

    # Routing necessity + subnet + NAT analysis
    routing_info = {}
    nat_table    = []
    src_info     = {}
    dst_info     = {}
    if src_ip and dst_ip:
        try:
            routing_info = routing_necessity(src_ip, dst_ip)
        except Exception:
            routing_info = {}
        try:
            src_info = analyse_subnet(src_ip)
        except Exception:
            src_info = {}
        try:
            dst_info = analyse_subnet(dst_ip)
        except Exception:
            dst_info = {}
        if result and result.get("hops"):
            try:
                nat_table = simulate_nat_table(result["hops"])
            except Exception:
                nat_table = []

    rip_warn = None
    if result and result.get("optimal") and result["optimal"].get("hops"):
        rip_warn = rip_hop_warning(result["optimal"]["hops"])

    # Gap 6 — potential congestion detection from RTT spikes
    ip_congestion_warning = None
    if result and result.get("hops") and len(result["hops"]) >= 2:
        rtts = [h["rtt_ms"] for h in result["hops"] if h.get("rtt_ms") is not None]
        if len(rtts) >= 2:
            max_jump = max(rtts[i+1] - rtts[i] for i in range(len(rtts)-1))
            avg_rtt = sum(rtts) / len(rtts)
            if max_jump > 80 or avg_rtt > 200:
                ip_congestion_warning = (
                    f"Potential congestion detected on this path — "
                    f"RTT spike of {max_jump:.1f} ms between hops "
                    f"(avg RTT: {avg_rtt:.1f} ms)."
                )
        if not ip_congestion_warning and result.get("real_ping") and result["real_ping"].get("rtt_avg"):
            if result["real_ping"]["rtt_avg"] > 200:
                ip_congestion_warning = (
                    f"High round-trip time detected — avg ping RTT is "
                    f"{result['real_ping']['rtt_avg']} ms, indicating possible congestion."
                )

    # Gap 7 — algorithm recommendation for IP route result
    ip_algo_rec = None
    if result and result.get("hops") and not result.get("error"):
        try:
            _hops_raw = result["hops"]
            num_hops = len(_hops_raw)
            avg_rtt_val = result.get("total_rtt", 0) / max(num_hops, 1)
            if num_hops > 8:
                ip_algo_rec = {"algo": "A* Search",
                               "reason": f"Long path ({num_hops} hops) — A* prunes the search space using a heuristic, finding the optimal route faster than exhaustive methods."}
            elif ip_congestion_warning:
                ip_algo_rec = {"algo": "Dijkstra",
                               "reason": "Congestion spikes detected — Dijkstra instantly recalculates the minimum-cost path using live weighted metrics."}
            else:
                ip_algo_rec = {"algo": "OSPF (Link-State)",
                               "reason": f"Stable {num_hops}-hop path — OSPF builds a full topology map and picks the shortest path, ideal for ISP-grade routing."}
        except Exception:
            pass

    return render_template("ip_result.html",
                           result=result,
                           algo_names=ALGO_NAMES,
                           routing_info=routing_info,
                           nat_table=nat_table,
                           src_info=src_info,
                           dst_info=dst_info,
                           protocol_map=get_protocol_map(),
                           rip_warn=rip_warn,
                           ip_congestion_warning=ip_congestion_warning,
                           ip_algo_rec=ip_algo_rec)


@app.route("/apply_congestion", methods=["POST"])
def apply_congestion():
    try:
        src   = request.form.get("source", "").strip().upper()
        dst   = request.form.get("destination", "").strip().upper()
        value = float(request.form.get("value", 5))
        if not src or not dst:
            flash("⚠ Source and destination cannot be empty.", "warning")
        else:
            link = service.network.get_link(src, dst) or service.network.get_link(dst, src)
            if not link:
                flash(f"⚠ No link found between {src} and {dst}.", "warning")
            else:
                MAX = service.MAX_CONGESTION_MS
                clamped = max(0.0, min(value, MAX))
                service.apply_congestion_to_link(src, dst, clamped)
                msg = f"⚠ Congestion +{clamped:.1f} ms applied to {src} ↔ {dst}."
                if clamped < value:
                    msg += f" (clamped from {value:.1f} to {MAX:.0f} ms max)"
                flash(msg, "warning")
    except (ValueError, TypeError):
        flash("⚠ Invalid congestion value.", "warning")
    return redirect(url_for("index"))


@app.route("/remove_link", methods=["POST"])
def remove_link():
    src = request.form.get("source", "").strip().upper()
    dst = request.form.get("destination", "").strip().upper()
    if not src or not dst:
        flash("⚠ Source and destination router names cannot be empty.", "warning")
        return redirect(url_for("index"))
    link = service.network.get_link(src, dst) or service.network.get_link(dst, src)
    if not link:
        flash(f"⚠ No link found between {src} and {dst}.", "warning")
    else:
        try:
            service.remove_link(src, dst)
            flash(f"✅ Link {src} ↔ {dst} removed.", "success")
        except Exception as e:
            flash(f"⚠ Could not remove link: {e}", "warning")
    return redirect(url_for("index"))


@app.route("/simulate_traffic", methods=["POST"])
def simulate_traffic():
    service.simulate_traffic_spike()
    return redirect(url_for("index"))


@app.route("/reset")
def reset():
    service.reset_congestion()
    service._last_results.clear()  # stale before/after snapshots are invalid after a reset
    flash("✅ Congestion reset — all links restored to base metrics.", "success")
    return redirect(url_for("index"))

@app.route("/save_topology", methods=["POST"])
def save_topology():
    result = service.save_topology()
    if result.get("saved"):
        flash(f"✅ Topology saved — {result['routers']} routers, {result['links']} links.", "success")
    else:
        flash(f"⚠ Save failed: {result.get('error', 'Unknown error')}", "warning")
    return redirect(url_for("index"))


@app.route("/load_topology", methods=["POST"])
def load_topology():
    result = service.load_topology()
    if result.get("loaded"):
        msg = f"✅ Topology loaded — {result['routers']} routers, {result['links']} links."
        if result.get("errors"):
            msg += f" ({len(result['errors'])} link(s) skipped)"
        flash(msg, "success")
    else:
        flash(f"⚠ Load failed: {result.get('error', 'No saved topology found.')}", "warning")
    return redirect(url_for("index"))


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.route("/api/validate_ip", methods=["POST"])
def api_validate_ip():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    ip = str(data.get("ip") or "").strip()
    if not ip:
        return jsonify({"valid": False, "warning": "", "error": "IP address cannot be empty."})
    # Always run through validate_ip — don't partially validate
    ok, msg = validate_ip(ip)
    if not ok:
        # Distinguish warning (partial/in-progress) vs hard error (full but wrong)
        parts = ip.split('.')
        if len(parts) < 4 or not all(p for p in parts):
            # Still being typed — treat as soft warning, not error
            return jsonify({"valid": False, "warning": f"⚠ {msg}", "error": ""})
        return jsonify({"valid": False, "warning": "", "error": msg})
    return jsonify({"valid": True, "warning": "", "error": ""})


@app.route("/api/capture_packets", methods=["POST"])
def capture_packets():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    src_ip       = str(data.get("src_ip") or "192.168.1.100").strip()
    dst_ip       = str(data.get("dst_ip") or "8.8.8.8").strip()
    try:
        count = min(max(int(data.get("count", 30)), 1), 200)
    except (ValueError, TypeError):
        count = 30
    filter_proto = str(data.get("filter_proto") or "").upper().strip()

    # Validate IPs
    for label, ip in [("Source IP", src_ip), ("Destination IP", dst_ip)]:
        ok, err = validate_ip(ip)
        if not ok:
            return jsonify({"error": f"{label}: {err}"}), 400

    if src_ip == dst_ip:
        return jsonify({"error": "Source and destination IP cannot be the same."}), 400

    try:
        packets = analyzer.simulate_traffic(src_ip, dst_ip, count)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Capture failed: {e}"}), 500

    # Real HTTPS probe — inject live TLS info into first TLS packet (non-fatal)
    try:
        probe = real_https_probe(dst_ip)
        if probe.get("real") and not probe.get("error"):
            server  = probe.get("server", "")
            tls_ver = probe.get("tls_version", "")
            cn      = probe.get("cert_subject", {}).get("commonName", "")
            for p in packets:
                if getattr(p, "flags", "") == "PSH ACK" and p.dst_port == 443:
                    p.notes = (f"🔐 Real TLS — Server: {server} | "
                               f"TLS: {tls_ver} | Cert CN: {cn}")
                    break
    except Exception:
        pass  # probe failure is non-fatal — simulation notes remain

    if filter_proto:
        packets = [p for p in packets if p.protocol == filter_proto]

    stats = analyzer.get_statistics(packets)
    return jsonify({"packets": [_pd(p) for p in packets], "stats": stats})


@app.route("/api/packet_detail/<int:pid>")
def packet_detail(pid):
    pkt = next((p for p in analyzer.packets if p.packet_id == pid), None)
    if not pkt:
        return jsonify({"error": "Packet not found"}), 404
    d = _pd(pkt)
    d["layers"] = [{"name": l.name, "fields": l.fields} for l in pkt.layers]
    return jsonify(d)


@app.route("/api/network_health")
def api_network_health():
    report = generate_report(service.network)
    if not report:
        return jsonify({"error": "No topology built yet."}), 400
    return jsonify(report)


@app.route("/api/route_capture_context", methods=["POST"])
def api_route_capture_context():
    """Return src/dst IPs and congestion context for a router pair — drives auto-capture."""
    data = request.json or {}
    src  = data.get("src", "").strip().upper()
    dst  = data.get("dst", "").strip().upper()
    routers = service.network.get_routers()
    if src not in routers or dst not in routers:
        return jsonify({"error": "Routers not in topology"}), 400
    src_ip = service.network.get_router_ip(src)
    dst_ip = service.network.get_router_ip(dst)
    cong_report = _get_congestion_report()
    path_congested = any(
        (c["src"] == src and c["dst"] == dst) or
        (c["src"] == dst and c["dst"] == src)
        for c in cong_report
    )
    return jsonify({
        "src_router": src, "dst_router": dst,
        "src_ip": src_ip, "dst_ip": dst_ip,
        "congestion_active": bool(cong_report),
        "path_congested": path_congested,
        "congested_links": cong_report,
        "router_ip_map": service.get_router_ip_map(),
    })


@app.route("/api/subnet_info", methods=["POST"])
def api_subnet_info():
    """📚 Ch3 — Subnet analysis"""
    data   = request.json or {}
    ip     = data.get("ip", "").strip()
    prefix = data.get("prefix")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    ok, err = validate_ip(ip)
    if not ok:
        return jsonify({"error": err}), 400
    return jsonify(analyse_subnet(ip, int(prefix) if prefix else None))


@app.route("/api/congestion_cascade", methods=["POST"])
def api_congestion_cascade():
    """📚 Ch5 — Congestion cascade analysis"""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    try:
        cong_ms = float(data.get("congestion_ms", 10))
        bw_mbps = float(data.get("bandwidth_mbps", 100))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid numeric parameters."}), 400
    try:
        return jsonify(congestion_cascade(cong_ms, bw_mbps))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/real_dns", methods=["POST"])
def api_real_dns():
    """Live DNS query to 8.8.8.8"""
    data     = request.json or {}
    hostname = data.get("hostname", "").strip()
    if not hostname:
        return jsonify({"error": "hostname required"}), 400
    try:
        return jsonify(real_dns_lookup(hostname))
    except Exception as e:
        return jsonify({"error": str(e), "real": False}), 500


@app.route("/api/real_ping", methods=["POST"])
def api_real_ping():
    """Live ICMP ping via OS ping command"""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        data = {}
    host = str(data.get("host") or "").strip()
    try:
        count = min(max(int(data.get("count", 4)), 1), 10)
    except (ValueError, TypeError):
        count = 4
    if not host:
        return jsonify({"error": "host required"}), 400
    try:
        return jsonify(real_ping(host, count))
    except Exception as e:
        return jsonify({"error": str(e), "real": False}), 500


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pd(p):
    return {
        "id":         p.packet_id,
        "timestamp":  p.timestamp,
        "src_ip":     p.src_ip,
        "dst_ip":     p.dst_ip,
        "src_port":   p.src_port,
        "dst_port":   p.dst_port,
        "protocol":   p.protocol,
        "length":     p.length,
        "ttl":        p.ttl,
        "flags":      p.flags,
        "payload":    p.payload_preview,
        "direction":  p.direction,
        "notes":      p.notes,
        "session_id": getattr(p, "session_id", "")
    }


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": f"Endpoint not found: {request.path}"}), 404
    return render_template("index.html",
                           routers=service.get_all_routers(),
                           router_ip_map=service.get_router_ip_map(),
                           congestion_report=_get_congestion_report(),
                           error=f"Page not found: {request.path}"), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": f"Internal server error: {e}"}), 500
    return render_template("index.html",
                           routers=service.get_all_routers(),
                           router_ip_map=service.get_router_ip_map(),
                           congestion_report=_get_congestion_report(),
                           error=f"Server error: {e}"), 500


@app.errorhandler(Exception)
def unhandled_exception(e):
    import traceback, logging
    logging.error(f"Unhandled exception: {e}\n{traceback.format_exc()}")
    if request.path.startswith("/api/"):
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
    return render_template("index.html",
                           routers=service.get_all_routers(),
                           router_ip_map=service.get_router_ip_map(),
                           congestion_report=_get_congestion_report(),
                           error=f"Unexpected error: {str(e)}"), 500


if __name__ == "__main__":
    # Set CN_DEBUG=true in environment to enable Flask interactive debugger.
    # Never enable debug mode on a publicly accessible server.
    debug_mode = os.environ.get("CN_DEBUG", "false").lower() == "true"
    port = int(os.environ.get("CN_PORT", 5000))
    app.run(debug=debug_mode, port=port)
