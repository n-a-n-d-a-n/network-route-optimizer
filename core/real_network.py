# core/real_network.py
import socket, subprocess, platform, re, time
import requests
import psutil

# ── 1. Real DNS ──────────────────────────────────────────────────────
def real_dns_lookup(hostname: str) -> dict:
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']
        t0      = time.time()
        answers = resolver.resolve(hostname, 'A')
        rtt     = round((time.time() - t0) * 1000, 2)
        return {
            "query":       hostname,
            "answers":     [{"ip": str(r), "ttl": answers.rrset.ttl} for r in answers],
            "rtt_ms":      rtt,
            "nameserver":  "8.8.8.8",
            "real":        True
        }
    except Exception as e:
        # Fallback — stdlib socket
        try:
            ip = socket.gethostbyname(hostname)
            return {"query": hostname, "answers": [{"ip": ip, "ttl": 300}],
                    "rtt_ms": 0, "real": True}
        except Exception:
            return {"query": hostname, "answers": [], "error": str(e), "real": False}


# ── 2. Real HTTPS Probe ──────────────────────────────────────────────
def real_https_probe(host: str) -> dict:
    try:
        import ssl
        url = f"https://{host}" if not host.startswith("http") else host
        t0  = time.time()
        resp = requests.head(url, timeout=5, verify=True, allow_redirects=True)
        rtt  = round((time.time() - t0) * 1000, 2)

        # Real TLS certificate
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert        = ss.getpeercert()
                tls_version = ss.version()

        return {
            "status_code":  resp.status_code,
            "rtt_ms":       rtt,
            "server":       resp.headers.get("Server", ""),
            "tls_version":  tls_version,
            "cert_subject": dict(x[0] for x in cert.get("subject", [])),
            "cert_issuer":  dict(x[0] for x in cert.get("issuer", [])),
            "cert_expiry":  cert.get("notAfter", ""),
            "real":         True
        }
    except Exception as e:
        return {"error": str(e), "real": False}


# ── 3. Real Ping ─────────────────────────────────────────────────────
def real_ping(host: str, count: int = 4) -> dict:
    system = platform.system().lower()
    cmd    = (['ping','-n',str(count),host] if system=='windows'
              else ['ping','-c',str(count),'-W','2',host])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
        if system == 'windows':
            rtts      = [int(m)   for m in re.findall(r'time[=<](\d+)ms', out)]
            ttl_match = re.search(r'TTL=(\d+)', out)
        else:
            rtts      = [float(m) for m in re.findall(r'time=([\d.]+)\s*ms', out)]
            ttl_match = re.search(r'ttl=(\d+)', out)
        real_ttl = int(ttl_match.group(1)) if ttl_match else 64
        return {
            "host":             host,
            "packets_sent":     count,
            "packets_received": len(rtts),
            "packet_loss_pct":  round((count-len(rtts))/count*100, 1),
            "rtt_min":          min(rtts)  if rtts else None,
            "rtt_max":          max(rtts)  if rtts else None,
            "rtt_avg":          round(sum(rtts)/len(rtts), 2) if rtts else None,
            "real_ttl":         real_ttl,
            "reachable":        len(rtts) > 0,
            "real":             True
        }
    except Exception as e:
        return {"host": host, "reachable": False, "error": str(e), "real": False}


# ── 4. Real ASN Lookup ───────────────────────────────────────────────
def real_asn_lookup(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if r.status_code == 200:
            d = r.json()
            org_parts = d.get("org", "").split(" ", 1)
            return {
                "ip":      ip,
                "asn":     org_parts[0] if org_parts else "Unknown",
                "org":     org_parts[1] if len(org_parts) > 1 else "Unknown",
                "country": d.get("country", ""),
                "city":    d.get("city", ""),
                "real":    True
            }
    except Exception:
        pass
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,org,as,country,city",
            timeout=3)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                as_parts = d.get("as","").split(" ",1)
                return {
                    "ip":      ip,
                    "asn":     as_parts[0] if as_parts else "Unknown",
                    "org":     as_parts[1] if len(as_parts)>1 else d.get("org",""),
                    "country": d.get("country",""),
                    "city":    d.get("city",""),
                    "real":    True
                }
    except Exception:
        pass
    return {"ip": ip, "asn": "Unknown", "org": "Unknown",
            "country": "Unknown", "real": False}


# ── 5. Real Interface Stats ──────────────────────────────────────────
def real_interface_stats() -> dict:
    try:
        before = psutil.net_io_counters()
        time.sleep(1)
        after  = psutil.net_io_counters()
        per_nic    = psutil.net_io_counters(pernic=True)
        nic_stats  = psutil.net_if_stats()
        interfaces = []
        for name, io in per_nic.items():
            stat = nic_stats.get(name)
            if stat and stat.isup:
                interfaces.append({
                    "name":          name,
                    "speed_mbps":    stat.speed,
                    "mtu":           stat.mtu,
                    "bytes_sent":    io.bytes_sent,
                    "bytes_recv":    io.bytes_recv,
                    "packets_recv":  io.packets_recv,
                    "drops_in":      io.dropin,
                    "real_loss_pct": round(io.dropin/max(io.packets_recv,1)*100, 3)
                })
        return {
            "throughput_kbps":    round(
                (after.bytes_recv + after.bytes_sent -
                 before.bytes_recv - before.bytes_sent) * 8 / 1000, 2),
            "interfaces":         interfaces,
            "total_drops":        after.dropin + after.dropout,
            "real":               True
        }
    except Exception as e:
        return {"throughput_kbps": 0, "interfaces": [], "real": False,
                "error": str(e)}
