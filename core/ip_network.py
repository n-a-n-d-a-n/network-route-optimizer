"""
core/ip_network.py
Realistic IP path discovery with full validation and robust traceroute simulation.
Uses ipaddress module for correct IP handling.
"""
import socket, random, ipaddress
from dataclasses import dataclass
from typing import List, Tuple, Optional
from core.topology import NetworkTopology


@dataclass
class HopInfo:
    hop_num: int
    ip: str
    hostname: str
    rtt_ms: float
    asn: str = "Unknown"
    org: str = "Unknown"
    country: str = "Unknown"
    isp: str = "Unknown"


# ── Validation ─────────────────────────────────────────────────────────────

def validate_ip(ip: str) -> Tuple[bool, str]:
    """
    Returns (is_valid, error_message).
    Validates IP format and octet ranges (0-255).
    """
    ip = ip.strip()
    if not ip:
        return False, "IP address cannot be empty."
    try:
        obj = ipaddress.ip_address(ip)
        if obj.version == 4:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return False, "IPv4 address must have exactly 4 octets."
            for i, o in enumerate(octets):
                if o > 255:
                    return False, f"Octet {i+1} value {o} exceeds 255. Each octet must be 0–255."
                if o < 0:
                    return False, f"Octet {i+1} has negative value {o}."
        return True, ""
    except ValueError as e:
        # Try to give specific first-octet warning
        parts = ip.split('.')
        if parts:
            try:
                first = int(parts[0])
                if first > 255:
                    return False, (f"⚠ First octet value '{first}' exceeds 255. "
                                   f"IP octets must be in range 0–255. "
                                   f"Example valid IP: 192.168.1.1")
            except ValueError:
                pass
        return False, f"Invalid IP address format: {e}"


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def resolve_hostname(host: str) -> str:
    """Resolve hostname to IP, or return as-is if already an IP."""
    host = host.strip()
    valid, _ = validate_ip(host)
    if valid:
        return host
    try:
        resolved = socket.gethostbyname(host)
        return resolved
    except Exception:
        return host


# ── Realistic Traceroute Simulation ────────────────────────────────────────

# Real-world ISP/backbone hop templates — regional profiles
_ISP_PROFILES = {
    # India
    "jio":     {"asn": "AS55836", "org": "Reliance Jio",       "domains": ["jio.in", "jionet.in"],           "prefixes": ["103", "49", "157", "115"],  "country": "IN"},
    "airtel":  {"asn": "AS24560", "org": "Bharti Airtel",      "domains": ["airtelbroadband.in", "airtel.in"],"prefixes": ["122", "125", "182", "203"], "country": "IN"},
    "bsnl":    {"asn": "AS9829",  "org": "BSNL India",         "domains": ["bsnl.in"],                        "prefixes": ["117", "59", "61", "202"],   "country": "IN"},
    # USA
    "comcast": {"asn": "AS7922",  "org": "Comcast Cable",      "domains": ["comcast.net"],                    "prefixes": ["73", "96", "174", "68"],    "country": "US"},
    "att":     {"asn": "AS7018",  "org": "AT&T Services",      "domains": ["att.net", "sbcglobal.net"],       "prefixes": ["12", "99", "107", "108"],   "country": "US"},
    "verizon": {"asn": "AS701",   "org": "Verizon Business",   "domains": ["verizon.net"],                    "prefixes": ["130", "144", "165", "206"], "country": "US"},
    # Europe
    "dtag":    {"asn": "AS3320",  "org": "Deutsche Telekom",   "domains": ["t-ipnet.de", "telekom.de"],       "prefixes": ["80", "87", "217", "188"],   "country": "DE"},
    "bt":      {"asn": "AS2856",  "org": "British Telecom",    "domains": ["bt.net", "btinternet.com"],       "prefixes": ["109", "81", "148", "195"],  "country": "GB"},
    "orange":  {"asn": "AS5511",  "org": "Orange S.A.",        "domains": ["orange.net", "francetelecom.fr"], "prefixes": ["90", "193", "194", "212"],  "country": "FR"},
    # Asia-Pacific (non-India)
    "ntt":     {"asn": "AS2914",  "org": "NTT Communications", "domains": ["ntt.net"],                        "prefixes": ["129", "204", "211", "220"], "country": "JP"},
    "singtel": {"asn": "AS7473",  "org": "SingTel Optus",      "domains": ["singtel.com", "optus.com.au"],    "prefixes": ["202", "58", "101", "175"],  "country": "SG"},
    "chinanet":{"asn": "AS4134",  "org": "ChinaNet Backbone",  "domains": ["chinatelecom.cn"],                "prefixes": ["60", "119", "121", "123"],  "country": "CN"},
    # Backbone / CDN (destination profiles)
    "cloudflare": {"asn": "AS13335", "org": "Cloudflare Inc.", "domains": ["cloudflare.net"], "country": "US"},
    "google":     {"asn": "AS15169", "org": "Google LLC",      "domains": ["google.com"],     "country": "US"},
    "amazon":     {"asn": "AS16509", "org": "Amazon AWS",      "domains": ["amazonaws.com"],  "country": "US"},
    "microsoft":  {"asn": "AS8075",  "org": "Microsoft Corp.", "domains": ["microsoft.com"],  "country": "US"},
}

# Map IP first-octet ranges to likely ISP region
def _pick_isp_for_src(first_octet: int, rng) -> str:
    """Select a plausible ISP based on the source IP's first octet."""
    # Private / RFC1918 — treat as Indian (local demo context)
    if first_octet in (10, 172, 192):
        return rng.choice(["jio", "airtel", "bsnl"])
    # APNIC (Asia-Pacific) — 1, 14, 27, 36, 39, 42, 43, 49, 58-61, 101-126, 150, 175, 202-203, 210-211, 218-223
    apnic_ranges = set(range(58, 62)) | set(range(101, 127)) | set(range(218, 224)) | {1, 14, 27, 36, 39, 42, 43, 49, 150, 175, 202, 203, 210, 211}
    # India-specific APNIC blocks (Jio/Airtel/BSNL prefixes)
    india_ranges = {49, 103, 115, 117, 122, 125, 157, 182, 203}
    if first_octet in india_ranges:
        return rng.choice(["jio", "airtel", "bsnl"])
    if first_octet in apnic_ranges:
        return rng.choice(["ntt", "singtel", "chinanet"])
    # ARIN (North America) — 3, 4, 6, 7, 8, 9, 11-13, 15-44, 47, 50, 52, 54, 63-76, 96-100, 104, 107-108, 130, 135, 144, 162, 165, 166
    arin_ranges = set(range(12, 45)) | set(range(63, 77)) | set(range(96, 101)) | {3, 4, 6, 7, 8, 9, 50, 52, 54, 104, 107, 108, 130, 135, 144, 162, 165, 166}
    if first_octet in arin_ranges:
        return rng.choice(["comcast", "att", "verizon"])
    # RIPE (Europe, Middle East) — 2, 5, 25, 31, 37, 46, 62, 77-95, 109, 145, 176-195, 212-217
    ripe_ranges = set(range(77, 96)) | set(range(176, 196)) | set(range(212, 218)) | {2, 5, 25, 31, 37, 46, 62, 109, 145}
    if first_octet in ripe_ranges:
        return rng.choice(["dtag", "bt", "orange"])
    # Default fallback
    return rng.choice(["jio", "airtel", "bsnl", "comcast", "att", "dtag", "ntt"])


def _rand_ip(prefix: str, rng: random.Random) -> str:
    return f"{prefix}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"


def simulate_traceroute(src_ip: str, dst_ip: str) -> List[HopInfo]:
    """
    Simulate realistic ISP-grade traceroute hops between src and dst.
    Path: Client LAN → ISP edge → National backbone → IXP → International → Destination
    Deterministic per (src, dst) pair for consistent demo.
    """
    # Validate inputs
    for ip in (src_ip, dst_ip):
        valid, err = validate_ip(ip)
        if not valid:
            raise ValueError(f"Invalid IP '{ip}': {err}")

    seed = sum(ord(c) for c in src_ip + dst_ip)
    rng = random.Random(seed)

    src_parts = src_ip.split('.')
    dst_parts  = dst_ip.split('.')

    try:
        src_first = int(src_parts[0])
        dst_first  = int(dst_parts[0])
    except (ValueError, IndexError):
        src_first, dst_first = 192, 8

    gateway = f"{src_parts[0]}.{src_parts[1]}.{src_parts[2]}.1" if len(src_parts) == 4 else "192.168.1.1"

    # Determine ISP profile based on source IP region
    isp = _pick_isp_for_src(src_first, rng)
    isp_profile = _ISP_PROFILES[isp]

    # Determine if destination is private/local
    dst_private = is_private_ip(dst_ip)

    # Determine destination profile
    dst_profile = _ISP_PROFILES["google"]
    if dst_first in (1,):      dst_profile = _ISP_PROFILES["cloudflare"]
    elif dst_first in (13, 40): dst_profile = _ISP_PROFILES["microsoft"]
    elif dst_first in (54, 52): dst_profile = _ISP_PROFILES["amazon"]
    elif dst_first in (8, 142): dst_profile = _ISP_PROFILES["google"]

    hop_base_rtt = 0.0
    hops = []

    def add_hop(num, ip, hostname, delta_rtt, asn, org, country, isp_name=""):
        nonlocal hop_base_rtt
        hop_base_rtt += delta_rtt
        hops.append(HopInfo(
            hop_num=num, ip=ip, hostname=hostname,
            rtt_ms=round(hop_base_rtt + rng.uniform(-0.3, 0.5), 2),
            asn=asn, org=org, country=country, isp=isp_name
        ))

    # Hop 1: Local gateway — country follows ISP region
    gw_country = isp_profile.get("country", "IN")
    add_hop(1, gateway, "gateway.local", rng.uniform(0.3, 1.2),
            "Private", "LAN Gateway", gw_country, "Local")

    if dst_private:
        # Short local path for private destinations
        add_hop(2, f"{dst_parts[0]}.{dst_parts[1]}.{dst_parts[2]}.{rng.randint(2,10)}",
                "switch.local", rng.uniform(0.5, 2),
                "Private", "Local Switch", "IN", "Local")
        add_hop(3, dst_ip, dst_ip, rng.uniform(0.3, 1),
                "Private", "Destination Host", "IN", "Local")
        return hops

    # Hop 2: ISP DSL/BRAS edge
    isp_country = isp_profile.get("country", "IN")
    edge_ip = _rand_ip(rng.choice(isp_profile.get("prefixes", ["103"])), rng)
    add_hop(2, edge_ip, f"bras-edge.{isp_profile['domains'][0]}",
            rng.uniform(4, 12), isp_profile["asn"], isp_profile["org"], isp_country, isp)

    # Hop 3: ISP core router — city label matches region
    _city_map = {
        "IN": ["mum", "del", "blr"], "US": ["nyc", "lax", "chi"],
        "GB": ["lon", "man", "edi"], "DE": ["fra", "ber", "muc"],
        "FR": ["par", "lyo", "mrs"], "JP": ["tok", "osa", "ngo"],
        "SG": ["sin"],               "CN": ["sha", "pek", "can"],
    }
    core_ip = _rand_ip(rng.choice(isp_profile.get("prefixes", ["116"])), rng)
    city = rng.choice(_city_map.get(isp_country, ["hub"]))
    add_hop(3, core_ip, f"core1.{city}.{isp_profile['domains'][0]}",
            rng.uniform(8, 18), isp_profile["asn"], f"{isp_profile['org']} Core", isp_country, isp)

    # Hop 4: Regional IXP — matched to ISP country
    _ixp_map = {
        "IN": ("210", ["mum", "del", "chen"], "AS17762", "NIXI — National Internet Exchange India", "nixi-{city}.ix.in", "IN"),
        "US": ("4",   ["nyc", "chi", "lax"],  "AS6695",  "DE-CIX New York",     "de-cix-{city}.net",  "US"),
        "GB": ("195", ["lon1", "lon2"],        "AS8714",  "LINX London",         "linx-{city}.net",    "GB"),
        "DE": ("80",  ["fra1", "fra2"],        "AS6695",  "DE-CIX Frankfurt",    "de-cix-{city}.net",  "DE"),
        "FR": ("194", ["par1", "par2"],        "AS51706", "France-IX Paris",     "franceix-{city}.net","FR"),
        "JP": ("202", ["tok1", "tok2"],        "AS7500",  "JPIX Tokyo",          "jpix-{city}.net",    "JP"),
        "SG": ("175", ["sin1"],                "AS18182", "SGIX Singapore",      "sgix-{city}.net",    "SG"),
        "CN": ("219", ["sha", "pek"],          "AS24151", "CNIX Shanghai",       "cnix-{city}.net",    "CN"),
    }
    ixp = _ixp_map.get(isp_country, _ixp_map["IN"])
    ixp_ip = _rand_ip(ixp[0], rng)
    ixp_city = rng.choice(ixp[1])
    add_hop(4, ixp_ip, ixp[4].format(city=ixp_city),
            rng.uniform(5, 15), ixp[2], ixp[3], ixp[5], ixp[3].split()[0])

    # For international destinations, add backbone hops
    if dst_first not in (10, 172, 192):
        # Hop 5: NTT/Tata international gateway
        gw_ip = _rand_ip("4", rng)
        add_hop(5, gw_ip, f"ae3.r01.sin01.ntt.net",
                rng.uniform(40, 65), "AS2914", "NTT Communications", "SG", "NTT")

        # Hop 6: Regional PoP
        if dst_first < 40 or dst_first in (13, 40, 52, 54):
            # US/Europe destination
            pop_ip = _rand_ip("204", rng)
            add_hop(6, pop_ip, f"ae2.r20.sjc04.ntt.net",
                    rng.uniform(90, 130), "AS2914", "NTT San Jose PoP", "US", "NTT")

            # Hop 7: Destination CDN edge / datacenter
            cdn_ip = _rand_ip(dst_parts[0] if dst_parts else "8", rng)
            add_hop(7, cdn_ip, f"edge01.{dst_profile['domains'][0]}",
                    rng.uniform(15, 35), dst_profile["asn"], dst_profile["org"], "US",
                    dst_profile["org"])
        else:
            # Asia-Pacific destination
            pop_ip = _rand_ip("129", rng)
            add_hop(6, pop_ip, f"ae7.r01.tok01.ntt.net",
                    rng.uniform(60, 90), "AS2914", "NTT Tokyo PoP", "JP", "NTT")

    # Final hop: destination
    add_hop(len(hops) + 1, dst_ip, dst_ip,
            rng.uniform(5, 20), dst_profile["asn"], dst_profile["org"],
            "US" if dst_first < 40 else "IN", dst_profile["org"])

    return hops


def build_topology_from_hops(hops: List[HopInfo]) -> NetworkTopology:
    """Build a NetworkTopology from traceroute hops with realistic link metrics."""
    topo = NetworkTopology()
    for hop in hops:
        topo.add_router(hop.ip)
    for i in range(len(hops) - 1):
        src_hop, dst_hop = hops[i], hops[i + 1]
        delay = max(0.1, dst_hop.rtt_ms - src_hop.rtt_ms)
        # Bandwidth inversely related to RTT (long-haul links are typically slower)
        bandwidth = max(1.0, round(10_000.0 / (delay + 1), 1))
        topo.add_link(src_hop.ip, dst_hop.ip, delay=delay, bandwidth=bandwidth)
    return topo
