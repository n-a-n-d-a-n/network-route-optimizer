"""
services/ip_tools.py
Route-relevant IP tools: subnet analysis, NAT detection, network type detection.
📚 Chapter 3 — Network Layer (IPv4 Addressing, Subnetting, NAT)
"""
import ipaddress
from typing import Optional


# ── Network type detection from delay values ──────────────────────────────────
def detect_network_type(avg_delay_ms: float) -> dict:
    """
    📚 Chapter 1 — Introduction: LAN/MAN/WAN classification
    Classify topology based on average link delay.
    """
    if avg_delay_ms < 1:
        return {"type": "LAN", "full": "Local Area Network",
                "desc": "Sub-millisecond delay — local switching environment",
                "preferred_algo": "Dijkstra / OSPF (intra-domain IGP)"}
    elif avg_delay_ms <= 20:
        return {"type": "MAN", "full": "Metropolitan Area Network",
                "desc": "1–20ms delay — city-wide or campus network",
                "preferred_algo": "OSPF (Delay-Metric) / A* Search"}
    else:
        return {"type": "WAN", "full": "Wide Area Network",
                "desc": "High latency — inter-city or intercontinental links",
                "preferred_algo": "BGP (inter-domain) / Widest Path for throughput"}


# ── Subnet analysis ────────────────────────────────────────────────────────────
def analyse_subnet(ip_str: str, prefix: int = None) -> dict:
    """
    📚 Chapter 3 — Classful/Classless Addressing, Subnetting
    Given an IP (and optional prefix), return full subnet information.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return {"error": f"Invalid IP: {ip_str}"}

    # Determine address class
    first_octet = int(str(ip).split('.')[0])
    if first_octet < 128:
        ip_class = "A"; default_prefix = 8; class_range = "0.0.0.0 – 127.255.255.255"
    elif first_octet < 192:
        ip_class = "B"; default_prefix = 16; class_range = "128.0.0.0 – 191.255.255.255"
    elif first_octet < 224:
        ip_class = "C"; default_prefix = 24; class_range = "192.0.0.0 – 223.255.255.255"
    elif first_octet < 240:
        ip_class = "D (Multicast)"; default_prefix = None; class_range = "224.0.0.0 – 239.255.255.255"
    else:
        ip_class = "E (Reserved)"; default_prefix = None; class_range = "240.0.0.0 – 255.255.255.255"

    # Address type
    if ip.is_private:
        addr_type = "Private"
        nat_note  = "This IP is private — it will be translated by NAT at the network boundary before reaching the public internet."
    elif ip.is_loopback:
        addr_type = "Loopback"
        nat_note  = "Loopback address — used for local testing, never routed."
    elif ip.is_multicast:
        addr_type = "Multicast"
        nat_note  = "Multicast — used by routing protocols (e.g. OSPF uses 224.0.0.5)."
    elif str(ip) in ("255.255.255.255",):
        addr_type = "Broadcast"
        nat_note  = "Limited broadcast — never forwarded by routers."
    else:
        addr_type = "Public"
        nat_note  = "Public IP — routable on the internet without NAT."

    # Subnet calculation
    use_prefix = prefix if prefix is not None else default_prefix
    subnet_info = {}
    if use_prefix and 0 <= use_prefix <= 32:
        try:
            net = ipaddress.ip_network(f"{ip_str}/{use_prefix}", strict=False)
            hosts = list(net.hosts())
            subnet_info = {
                "network_address": str(net.network_address),
                "broadcast":       str(net.broadcast_address),
                "subnet_mask":     str(net.netmask),
                "wildcard":        str(net.hostmask),
                "first_host":      str(hosts[0]) if hosts else "N/A",
                "last_host":       str(hosts[-1]) if hosts else "N/A",
                "total_hosts":     net.num_addresses,
                "usable_hosts":    max(0, net.num_addresses - 2),
                "prefix":          use_prefix,
                "binary_mask":     _to_binary_mask(str(net.netmask)),
                "addressing":      "Classless (CIDR)" if prefix else "Classful",
            }
        except Exception as e:
            subnet_info = {"error": str(e)}

    return {
        "ip":          str(ip),
        "ip_class":    ip_class,
        "class_range": class_range,
        "addr_type":   addr_type,
        "nat_note":    nat_note,
        "is_private":  bool(ip.is_private),
        "binary_ip":   _to_binary_ip(str(ip)),
        "subnet":      subnet_info,
    }


def _to_binary_ip(ip_str: str) -> str:
    parts = ip_str.split('.')
    return '.'.join(f'{int(p):08b}' for p in parts)


def _to_binary_mask(mask_str: str) -> str:
    parts = mask_str.split('.')
    return '.'.join(f'{int(p):08b}' for p in parts)


# ── Routing necessity check ────────────────────────────────────────────────────
def routing_necessity(src_ip: str, dst_ip: str) -> dict:
    """
    📚 Chapter 3 — Delivery and Forwarding of IP Packet
    Determine if routing is needed between src and dst.
    Returns explanation of WHY routing exists.
    """
    try:
        src = ipaddress.ip_address(src_ip.strip())
        dst = ipaddress.ip_address(dst_ip.strip())
    except ValueError:
        return {"needs_routing": True, "reason": "Could not parse IPs.", "nat_boundary": False}

    # Check common private prefix
    src_info = analyse_subnet(src_ip, 24)
    dst_info = analyse_subnet(dst_ip, 24)

    src_private = src.is_private
    dst_private = dst.is_private
    nat_boundary = src_private and not dst_private

    if src == dst:
        return {"needs_routing": False,
                "reason": "Source and destination are the same host. No routing required.",
                "nat_boundary": False}

    # Check if same /24 subnet (simplified same-subnet check)
    src_parts = src_ip.strip().split('.')
    dst_parts = dst_ip.strip().split('.')
    same_24 = src_parts[:3] == dst_parts[:3]

    if same_24 and src_private and dst_private:
        return {
            "needs_routing": False,
            "reason": f"Both IPs are in the same /24 subnet ({'.'.join(src_parts[:3])}.0/24). They can communicate directly via switching — no router needed.",
            "nat_boundary": False,
            "syllabus_note": "📚 Ch3: Direct delivery — hosts in the same subnet communicate without routing."
        }
    elif nat_boundary:
        return {
            "needs_routing": True,
            "reason": f"{src_ip} is a private IP. It CANNOT reach {dst_ip} (public) directly. A router with NAT must translate the private address to a public IP at the network boundary.",
            "nat_boundary": True,
            "nat_explanation": "NAT (Network Address Translation) maps private addresses (RFC 1918) to a public IP. This is why your traceroute shows the path changing from private to public hops.",
            "syllabus_note": "📚 Ch3: NAT — private-to-public boundary requires address translation."
        }
    else:
        return {
            "needs_routing": True,
            "reason": f"{src_ip} and {dst_ip} are in different subnets. A router must forward packets between them — this is exactly the problem your Route Optimizer solves.",
            "nat_boundary": False,
            "syllabus_note": "📚 Ch3: Indirect delivery — packets cross subnet boundaries via routers."
        }


# ── NAT table simulation ───────────────────────────────────────────────────────
def simulate_nat_table(hops: list) -> list:
    """
    📚 Chapter 3 — NAT (Network Address Translation)
    Given traceroute hops, identify the NAT boundary and build a NAT translation table.
    """
    nat_table = []
    nat_found = False
    private_ip = None

    for i, hop in enumerate(hops):
        ip_str = hop.get("ip", "")
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            is_priv = ip_obj.is_private
        except Exception:
            is_priv = False

        if is_priv and not nat_found:
            private_ip = ip_str
        elif not is_priv and private_ip and not nat_found:
            # This is the NAT boundary
            nat_found = True
            nat_table.append({
                "private_ip":    private_ip,
                "public_ip":     ip_str,
                "hop_num":       hop.get("hop_num", i + 1),
                "org":           hop.get("org", "ISP Gateway"),
                "translation":   f"{private_ip} → {ip_str}",
                "type":          "Dynamic NAT / PAT",
                "explanation":   f"At hop {hop.get('hop_num', i+1)} ({hop.get('org','ISP')}), the private source IP {private_ip} is translated to public IP {ip_str}. This is NAT in action.",
                "syllabus_note": "📚 Ch3: NAT — RFC 1918 private address translated to routable public IP"
            })
        private_ip = ip_str if is_priv else private_ip

    return nat_table
