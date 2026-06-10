"""
core/packet_analyzer.py
Wireshark-inspired packet capture & analysis.
Generates EXACTLY the requested count of packets by dynamically scaling
repeatable sessions (HTTPS data, UDP stream, ICMP pings) to fill the gap.
"""
import time, random, hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6",
             47: "GRE", 89: "OSPF", 132: "SCTP"}

TCP_FLAGS_MAP = {
    "SYN":     0x002,
    "SYN ACK": 0x012,
    "ACK":     0x010,
    "PSH ACK": 0x018,
    "FIN ACK": 0x011,
    "RST":     0x004,
    "RST ACK": 0x014,
}

WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-Srv", 68: "DHCP-Cli",
    80: "HTTP", 110: "POP3", 143: "IMAP", 179: "BGP",
    443: "HTTPS", 520: "RIP", 1194: "OpenVPN", 1935: "RTMP",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS", 8080: "HTTP-Alt"
}


@dataclass
class PacketLayer:
    name: str
    fields: Dict[str, str]


@dataclass
class CapturedPacket:
    packet_id: int
    timestamp: str
    timestamp_raw: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    ttl: int
    flags: str
    payload_preview: str
    layers: List[PacketLayer] = field(default_factory=list)
    direction: str = "→"
    notes: str = ""
    session_id: str = ""


def _mac(rng):
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))

def _checksum(rng):
    return f"0x{rng.randint(0, 65535):04x}"


class PacketAnalyzer:
    def __init__(self):
        self.packets: List[CapturedPacket] = []
        self._counter = 0

    def simulate_traffic(self, src_ip: str, dst_ip: str, count: int = 30) -> List[CapturedPacket]:
        """
        Generate EXACTLY `count` packets.
        Fixed sessions (DNS, handshake, teardown) are always included once.
        Repeatable sessions (HTTPS data, UDP stream, ICMP) are scaled to
        fill the remaining slots so the total equals count precisely.
        """
        from core.ip_network import validate_ip

        count = max(1, min(count, 200))

        for ip in (src_ip, dst_ip):
            ok, err = validate_ip(ip)
            if not ok:
                raise ValueError(f"Invalid IP for packet capture: {err}")

        seed = int(hashlib.md5((src_ip + dst_ip).encode()).hexdigest(), 16) % (2 ** 32)
        rng  = random.Random(seed + int(time.time()) % 1000)

        packets     = []
        base_time   = time.time()

        # ── 1. Build ordered packet definitions to fill exactly `count` ──
        pkt_defs = self._build_exact(src_ip, dst_ip, count, rng)

        # ── 2. Materialise each definition into a CapturedPacket ─────────
        for defn in pkt_defs:
            base_time += rng.uniform(0.001, 0.05)
            pkt = self._make_packet(
                src=defn["src"], dst=defn["dst"],
                sport=defn.get("sport"), dport=defn.get("dport"),
                protocol=defn["proto"],
                length=rng.randint(defn["min_len"], defn["max_len"]),
                ttl=defn.get("ttl", rng.randint(48, 128)),
                flags=defn.get("flags", ""),
                payload=defn.get("payload", ""),
                ts=base_time,
                notes=defn.get("notes", ""),
                session_id=defn.get("session_id", ""),
                rng=rng
            )
            packets.append(pkt)

        # Reset accumulated packets so each capture session starts fresh.
        # This prevents the global analyzer object from growing unbounded
        # across hundreds of captures and keeps /api/packet_detail lookups fast.
        self.packets = packets
        return packets

    # ─────────────────────────────────────────────────────────────────────
    # Build exactly `count` packet definitions in realistic session order
    # ─────────────────────────────────────────────────────────────────────
    def _build_exact(self, src: str, dst: str, count: int, rng: random.Random) -> list:
        """
        Returns a flat ordered list of packet definition dicts,
        with len == exactly `count`.

        Fixed skeleton (always 1×):
          DNS query + reply                    = 2
          TCP SYN / SYN-ACK / ACK             = 3
          TLS ClientHello + ServerHello        = 2
          BGP keepalive pair                   = 2
          OSPF Hello                           = 1
          TCP FIN / FIN-ACK / ACK (teardown)  = 3
          ── fixed subtotal ────────────────── = 13

        Repeatable fillers (scaled to fill remaining count-13 slots):
          HTTPS app-data frames  (1 pkt each)
          UDP stream frames      (1 pkt each)
          ICMP echo req+reply    (2 pkts each)
        """
        https_sport  = rng.randint(49152, 65535)
        bgp_sport    = rng.randint(49152, 65535)
        dns_sport    = rng.randint(49152, 65535)
        stream_sport = rng.randint(49152, 65535)

        defs = []

        # ── FIXED: DNS ────────────────────────────────────────────────
        defs += [
            {"src": src, "dst": "8.8.8.8", "proto": "UDP",
             "sport": dns_sport, "dport": 53,
             "min_len": 55, "max_len": 85, "ttl": 128,
             "payload": f"DNS Query: A {dst}", "flags": "",
             "notes": f"🔍 DNS A record query → resolving {dst}",
             "session_id": f"dns-{dns_sport}"},
            {"src": "8.8.8.8", "dst": src, "proto": "UDP",
             "sport": 53, "dport": dns_sport,
             "min_len": 85, "max_len": 200, "ttl": 119,
             "payload": f"DNS Response: {dst} → {dst}", "flags": "",
             "notes": f"✅ DNS response: resolved {dst}",
             "session_id": f"dns-{dns_sport}"},
        ]

        # ── FIXED: TCP 3-way handshake ────────────────────────────────
        defs += [
            {"src": src, "dst": dst, "proto": "TCP",
             "sport": https_sport, "dport": 443,
             "min_len": 60, "max_len": 60, "ttl": 64,
             "flags": "SYN", "payload": "",
             "notes": "🤝 TCP SYN — initiating HTTPS connection",
             "session_id": f"https-{https_sport}"},
            {"src": dst, "dst": src, "proto": "TCP",
             "sport": 443, "dport": https_sport,
             "min_len": 60, "max_len": 60, "ttl": 55,
             "flags": "SYN ACK", "payload": "",
             "notes": "🤝 TCP SYN-ACK — server acknowledges",
             "session_id": f"https-{https_sport}"},
            {"src": src, "dst": dst, "proto": "TCP",
             "sport": https_sport, "dport": 443,
             "min_len": 40, "max_len": 40, "ttl": 64,
             "flags": "ACK", "payload": "",
             "notes": "🤝 TCP ACK — three-way handshake complete",
             "session_id": f"https-{https_sport}"},
        ]

        # ── FIXED: TLS ClientHello + ServerHello ──────────────────────
        defs += [
            {"src": src, "dst": dst, "proto": "TCP",
             "sport": https_sport, "dport": 443,
             "min_len": 517, "max_len": 517, "ttl": 64,
             "flags": "PSH ACK",
             "payload": "TLSv1.3 Client Hello (cipher suites, SNI, extensions)",
             "notes": "🔐 TLS 1.3 ClientHello — negotiating encryption",
             "session_id": f"https-{https_sport}"},
            {"src": dst, "dst": src, "proto": "TCP",
             "sport": 443, "dport": https_sport,
             "min_len": 1200, "max_len": 1400, "ttl": 55,
             "flags": "PSH ACK",
             "payload": "TLSv1.3 Server Hello + Certificate + Finished",
             "notes": "🔐 TLS ServerHello + X.509 certificate exchange",
             "session_id": f"https-{https_sport}"},
        ]

        # ── FIXED: BGP keepalive pair ─────────────────────────────────
        defs += [
            {"src": src, "dst": dst, "proto": "TCP",
             "sport": bgp_sport, "dport": 179,
             "min_len": 19, "max_len": 19, "ttl": 1,
             "flags": "PSH ACK",
             "payload": "BGP KEEPALIVE (type=4, len=19)",
             "notes": "🔄 BGP Keepalive — maintaining peer session (TTL=1, eBGP)",
             "session_id": f"bgp-{bgp_sport}"},
            {"src": dst, "dst": src, "proto": "TCP",
             "sport": 179, "dport": bgp_sport,
             "min_len": 19, "max_len": 19, "ttl": 1,
             "flags": "PSH ACK",
             "payload": "BGP KEEPALIVE (type=4, len=19)",
             "notes": "🔄 BGP Keepalive reply — peer confirms session alive",
             "session_id": f"bgp-{bgp_sport}"},
        ]

        # ── FIXED: OSPF Hello ─────────────────────────────────────────
        defs += [
            {"src": src, "dst": "224.0.0.5", "proto": "OSPF",
             "sport": None, "dport": None,
             "min_len": 48, "max_len": 48, "ttl": 1,
             "flags": "Hello",
             "payload": "OSPF Hello (area=0.0.0.0, priority=1, dead=40s)",
             "notes": "🔗 OSPF Hello — discovering neighbors on multicast 224.0.0.5",
             "session_id": "ospf-hello"},
        ]

        # ── FIXED: TCP teardown (FIN/FIN-ACK/ACK) ────────────────────
        defs += [
            {"src": src, "dst": dst, "proto": "TCP",
             "sport": https_sport, "dport": 443,
             "min_len": 40, "max_len": 40, "ttl": 64,
             "flags": "FIN ACK", "payload": "",
             "notes": "👋 TCP FIN — client initiating graceful connection close",
             "session_id": f"https-close-{https_sport}"},
            {"src": dst, "dst": src, "proto": "TCP",
             "sport": 443, "dport": https_sport,
             "min_len": 40, "max_len": 40, "ttl": 55,
             "flags": "FIN ACK", "payload": "",
             "notes": "👋 TCP FIN-ACK — server acknowledges connection close",
             "session_id": f"https-close-{https_sport}"},
            {"src": src, "dst": dst, "proto": "TCP",
             "sport": https_sport, "dport": 443,
             "min_len": 40, "max_len": 40, "ttl": 64,
             "flags": "ACK", "payload": "",
             "notes": "✅ TCP ACK — connection fully closed (4-way FIN complete)",
             "session_id": f"https-close-{https_sport}"},
        ]

        # ── fixed_count should now be 13 ─────────────────────────────
        fixed_count = len(defs)      # 2+3+2+2+1+3 = 13
        remaining   = count - fixed_count

        # ── FILLER: scale repeatable sessions to hit exactly `count` ──
        # Each filler "unit":
        #   https_data  = 1 pkt  (HTTPS app data frame)
        #   udp_stream  = 1 pkt  (UDP/RTP media frame)
        #   icmp_pair   = 2 pkts (echo request + reply)
        #
        # We cycle through units until remaining == 0

        filler_defs = []
        icmp_seq   = 1
        https_seq  = 1
        udp_seq    = 1

        while remaining > 0:
            # HTTPS data frame (1 pkt)
            if remaining > 0:
                filler_defs.append({
                    "src": src, "dst": dst, "proto": "TCP",
                    "sport": https_sport, "dport": 443,
                    "min_len": 800, "max_len": 1460, "ttl": 64,
                    "flags": "PSH ACK",
                    "payload": f"TLSv1.3 Application Data (HTTP/2 frame #{https_seq})",
                    "notes": f"📤 HTTPS data frame #{https_seq} — encrypted payload",
                    "session_id": f"https-{https_sport}"})
                https_seq += 1
                remaining -= 1

            # HTTPS ACK (1 pkt)
            if remaining > 0:
                filler_defs.append({
                    "src": dst, "dst": src, "proto": "TCP",
                    "sport": 443, "dport": https_sport,
                    "min_len": 900, "max_len": 1460, "ttl": 55,
                    "flags": "PSH ACK",
                    "payload": f"TLSv1.3 Application Data (HTTP/2 response #{https_seq})",
                    "notes": f"📥 HTTPS response #{https_seq} — server reply (encrypted)",
                    "session_id": f"https-{https_sport}"})
                https_seq += 1
                remaining -= 1

            # UDP stream frame (1 pkt)
            if remaining > 0:
                filler_defs.append({
                    "src": src, "dst": dst, "proto": "UDP",
                    "sport": stream_sport, "dport": 1935,
                    "min_len": 800, "max_len": 1460, "ttl": 64,
                    "payload": f"RTP/UDP media frame seq={udp_seq * 30}",
                    "notes": f"📹 UDP media stream frame #{udp_seq} — RTP video/audio",
                    "session_id": f"udp-stream-{stream_sport}"})
                udp_seq  += 1
                remaining -= 1

            # ICMP echo request (1 pkt)
            if remaining > 0:
                filler_defs.append({
                    "src": src, "dst": dst, "proto": "ICMP",
                    "sport": None, "dport": None,
                    "min_len": 84, "max_len": 84, "ttl": 64,
                    "flags": "Echo Request",
                    "payload": f"ICMP Echo Request seq={icmp_seq}",
                    "notes": f"📡 ICMP Ping #{icmp_seq} → testing reachability to {dst}",
                    "session_id": f"icmp-{icmp_seq}"})
                remaining -= 1

            # ICMP echo reply (1 pkt)
            if remaining > 0:
                filler_defs.append({
                    "src": dst, "dst": src, "proto": "ICMP",
                    "sport": None, "dport": None,
                    "min_len": 84, "max_len": 84, "ttl": 63,
                    "flags": "Echo Reply",
                    "payload": f"ICMP Echo Reply seq={icmp_seq}",
                    "notes": f"✅ ICMP Reply #{icmp_seq} ← {dst} is reachable",
                    "session_id": f"icmp-{icmp_seq}"})
                icmp_seq += 1
                remaining -= 1

        # If count < fixed skeleton, just slice the fixed defs down to count
        if count <= fixed_count:
            return defs[:count]

        # Insert fillers between the fixed handshake and teardown
        # so the session story reads: DNS → handshake → TLS → [data/stream/ping…] → teardown
        teardown_count = 3   # FIN / FIN-ACK / ACK
        teardown = defs[-teardown_count:]
        core     = defs[:-teardown_count]
        final    = core + filler_defs + teardown

        assert len(final) == count, f"BUG: built {len(final)} packets, expected {count}"
        return final

    # ─────────────────────────────────────────────────────────────────────
    # Packet construction & layer building (unchanged)
    # ─────────────────────────────────────────────────────────────────────
    def _make_packet(self, src, dst, sport, dport, protocol, length,
                     ttl, flags, payload="", ts=None, notes="",
                     session_id="", rng=None):
        if rng is None:
            rng = random.Random()
        self._counter += 1
        if ts is None:
            ts = time.time()
        dt = datetime.fromtimestamp(ts)
        timestamp_str = dt.strftime("%H:%M:%S.%f")[:-3]
        direction = "→" if src < dst else "←"
        layers = self._build_layers(src, dst, sport, dport, protocol,
                                    ttl, flags, length, payload, rng)
        return CapturedPacket(
            packet_id=self._counter, timestamp=timestamp_str, timestamp_raw=ts,
            src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
            protocol=protocol, length=length, ttl=ttl, flags=flags,
            payload_preview=payload[:80] if payload else "",
            layers=layers, direction=direction, notes=notes,
            session_id=session_id
        )

    def _build_layers(self, src_ip, dst_ip, src_port, dst_port,
                      protocol, ttl, flags, length, payload, rng):
        layers = []

        layers.append(PacketLayer("Ethernet II", {
            "Destination MAC": _mac(rng),
            "Source MAC":      _mac(rng),
            "EtherType":       "0x0800 (IPv4)",
            "Frame Length":    f"{length + 14} bytes"
        }))

        tos = "0x00 (DSCP: Default Forwarding)"
        if protocol == "OSPF":
            tos = "0xC0 (DSCP: CS6 - Routing)"
        layers.append(PacketLayer("Internet Protocol v4", {
            "Version":         "4",
            "Header Length":   "20 bytes",
            "DSCP/ToS":        tos,
            "Total Length":    f"{length} bytes",
            "Identification":  f"0x{rng.randint(0, 65535):04x}",
            "Flags":           "DF" if protocol == "TCP" else "None",
            "Fragment Offset": "0",
            "TTL":             str(ttl),
            "Protocol":        f"{protocol} ({_proto_num(protocol)})",
            "Header Checksum": _checksum(rng),
            "Source IP":       src_ip,
            "Destination IP":  dst_ip,
        }))

        if protocol == "TCP" and src_port is not None and dst_port is not None:
            flag_hex = TCP_FLAGS_MAP.get(flags, 0x010)
            layers.append(PacketLayer("Transmission Control Protocol", {
                "Source Port":      f"{src_port}  [{WELL_KNOWN_PORTS.get(src_port, 'ephemeral')}]",
                "Destination Port": f"{dst_port}  [{WELL_KNOWN_PORTS.get(dst_port, 'ephemeral')}]",
                "Sequence Number":  str(rng.randint(1_000_000, 4_000_000_000)),
                "Acknowledgment":   str(rng.randint(1_000_000, 4_000_000_000)) if "ACK" in flags else "0",
                "Header Length":    "20 bytes (5 words)",
                "Flags":            f"0x{flag_hex:03x}  ({flags})",
                "Window Size":      str(rng.choice([8192, 16384, 32768, 65535])),
                "Checksum":         _checksum(rng),
                "Urgent Pointer":   "0",
            }))

        elif protocol == "UDP" and src_port is not None and dst_port is not None:
            layers.append(PacketLayer("User Datagram Protocol", {
                "Source Port":      f"{src_port}  [{WELL_KNOWN_PORTS.get(src_port, 'ephemeral')}]",
                "Destination Port": f"{dst_port}  [{WELL_KNOWN_PORTS.get(dst_port, 'ephemeral')}]",
                "Length":           str(max(8, length - 20)),
                "Checksum":         _checksum(rng),
            }))

        elif protocol == "ICMP":
            is_req = "Request" in flags or flags == "Echo Request"
            t_val  = 8 if is_req else 0
            layers.append(PacketLayer("Internet Control Message Protocol", {
                "Type":        f"{t_val} ({'Echo Request' if is_req else 'Echo Reply'})",
                "Code":        "0",
                "Checksum":    _checksum(rng),
                "Identifier":  f"0x{rng.randint(0, 65535):04x}",
                "Sequence":    str(rng.randint(1, 500)),
                "Data Length": "56 bytes",
            }))

        elif protocol == "OSPF":
            layers.append(PacketLayer("Open Shortest Path First", {
                "Version":       "2",
                "Message Type":  "1 (Hello)",
                "Packet Length": "48",
                "Router ID":     src_ip,
                "Area ID":       "0.0.0.0 (Backbone)",
                "Checksum":      _checksum(rng),
                "Auth Type":     "0 (No Authentication)",
                "Hello Interval":    "10 seconds",
                "Dead Interval":     "40 seconds",
                "Priority":          "1",
                "Designated Router": "0.0.0.0",
            }))

        if payload:
            app_name = _app_layer_name(dst_port, payload, protocol)
            layer_fields = {
                "Content":      payload,
                "Payload Size": f"{max(0, length - 40)} bytes",
            }
            if "DNS" in payload and "Query" in payload:
                layer_fields["Query Type"]        = "A (IPv4 address)"
                layer_fields["Recursion Desired"] = "Yes"
            elif "DNS" in payload and "Response" in payload:
                layer_fields["Response Code"] = "0 (No error)"
                layer_fields["Answers"]       = "1"
                layer_fields["TTL"]           = "300 seconds"
            elif "TLS" in payload and "Hello" in payload:
                layer_fields["TLS Version"]   = "TLS 1.3 (0x0304)"
                layer_fields["Cipher Suite"]  = "TLS_AES_256_GCM_SHA384"
                layer_fields["SNI Extension"] = dst_ip
            elif "BGP" in payload:
                layer_fields["BGP Version"]   = "4"
                layer_fields["Hold Time"]     = "90 seconds"
                layer_fields["BGP Identifier"]= src_ip
            elif "RTP" in payload:
                layer_fields["RTP Version"]   = "2"
                layer_fields["Payload Type"]  = "96 (H.264)"
            layers.append(PacketLayer(app_name, layer_fields))

        return layers

    def get_statistics(self, packets: List[CapturedPacket]) -> dict:
        if not packets:
            return {}
        proto_count: Dict[str, int] = {}
        total_bytes = 0
        port_count:  Dict[str, int] = {}
        session_ids = set()

        for p in packets:
            proto_count[p.protocol] = proto_count.get(p.protocol, 0) + 1
            total_bytes += p.length
            if p.dst_port:
                svc = WELL_KNOWN_PORTS.get(p.dst_port, str(p.dst_port))
                port_count[svc] = port_count.get(svc, 0) + 1
            if p.session_id:
                session_ids.add(p.session_id)

        dur = max(packets[-1].timestamp_raw - packets[0].timestamp_raw, 0.001)
        return {
            "total_packets":          len(packets),
            "total_bytes":            total_bytes,
            "duration_sec":           round(dur, 3),
            "throughput_kbps":        round((total_bytes * 8) / dur / 1000, 2),
            "protocol_distribution":  proto_count,
            "top_services":           dict(sorted(port_count.items(), key=lambda x: -x[1])[:5]),
            "avg_packet_size":        round(total_bytes / len(packets), 1),
            "active_sessions":        len(session_ids),
            "retransmissions":        0,
            "packet_loss_pct":        round(random.uniform(0, 0.5), 2),
            "jitter_ms":              round(random.uniform(0.1, 3.5), 2),
        }


def _proto_num(protocol: str) -> int:
    return {"TCP": 6, "UDP": 17, "ICMP": 1, "OSPF": 89, "GRE": 47}.get(protocol, 0)


def _app_layer_name(dst_port: Optional[int], payload: str, protocol: str) -> str:
    if dst_port == 443 or "TLS" in payload:
        return "Transport Layer Security (TLS 1.3)"
    if dst_port == 80 or "HTTP" in payload:
        return "Hypertext Transfer Protocol (HTTP/1.1)"
    if dst_port == 53 or "DNS" in payload:
        return "Domain Name System (DNS)"
    if dst_port == 179 or "BGP" in payload:
        return "Border Gateway Protocol (BGP)"
    if protocol == "OSPF":
        return "OSPF Routing Protocol"
    if "RTP" in payload:
        return "Real-time Transport Protocol (RTP)"
    return "Application Data"
