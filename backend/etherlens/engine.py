"""EtherLens AI – Packet capture engine.

Hybrid: tries real libpcap capture via scapy; falls back to a realistic traffic
simulator so the app runs on any device (including sandboxed containers).
Also parses uploaded PCAP files.
"""
from __future__ import annotations

import asyncio
import io
import os
import random
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

# scapy imports (packet parsing is always available even without capture perms)
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Packet, rdpcap  # type: ignore
from scapy.layers.http import HTTPRequest, HTTPResponse  # type: ignore

try:
    from scapy.layers.tls.record import TLS  # type: ignore
except Exception:  # pragma: no cover - optional TLS layer
    TLS = None  # type: ignore

# ---------- Protocol parsing ----------

APP_PORTS = {
    80: "HTTP", 8080: "HTTP", 443: "HTTPS", 8443: "HTTPS", 53: "DNS",
    22: "SSH", 21: "FTP", 25: "SMTP", 587: "SMTP", 465: "SMTPS",
    110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    3389: "RDP", 5900: "VNC", 123: "NTP", 161: "SNMP", 1883: "MQTT",
    5060: "SIP", 67: "DHCP", 68: "DHCP", 69: "TFTP", 179: "BGP",
    389: "LDAP", 636: "LDAPS", 445: "SMB", 139: "NetBIOS",
}


def _tcp_flags(flags: int) -> str:
    names = []
    for bit, name in [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                      (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
                      (0x40, "ECE"), (0x80, "CWR")]:
        if flags & bit:
            names.append(name)
    return ",".join(names) if names else "-"


def dissect_packet(pkt: Packet, number: int, ts: float) -> Dict[str, Any]:
    """Return a normalized dict representation of a scapy packet."""
    # Force scapy to build the packet so computed fields (ihl, len, chksum, …) are populated.
    try:
        pkt = pkt.__class__(bytes(pkt))
    except Exception:
        pass
    length = len(pkt)
    raw_bytes = bytes(pkt)

    layers: List[Dict[str, Any]] = []
    src_ip = dst_ip = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol = "ETH"
    info = ""

    # Frame
    layers.append({
        "name": "Frame",
        "fields": {
            "Frame Number": number,
            "Arrival Time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
            "Frame Length": f"{length} bytes",
            "Capture Length": f"{length} bytes",
        },
    })

    # Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        layers.append({
            "name": "Ethernet II",
            "fields": {
                "Destination": eth.dst,
                "Source": eth.src,
                "Type": hex(eth.type),
            },
        })

    # ARP
    if ARP in pkt:
        arp = pkt[ARP]
        protocol = "ARP"
        src_ip = arp.psrc
        dst_ip = arp.pdst
        op = {1: "request", 2: "reply"}.get(arp.op, str(arp.op))
        info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"
        layers.append({
            "name": "ARP",
            "fields": {
                "Opcode": op,
                "Sender MAC": arp.hwsrc,
                "Sender IP": arp.psrc,
                "Target MAC": arp.hwdst,
                "Target IP": arp.pdst,
            },
        })

    # IPv4 / IPv6
    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        protocol = "IPv4"
        layers.append({
            "name": "Internet Protocol v4",
            "fields": {
                "Version": ip_layer.version,
                "Header Length": f"{(ip_layer.ihl or 5) * 4} bytes",
                "TOS": hex(ip_layer.tos or 0),
                "Total Length": ip_layer.len or 0,
                "Identification": hex(ip_layer.id or 0),
                "Flags": str(ip_layer.flags),
                "TTL": ip_layer.ttl,
                "Protocol": ip_layer.proto,
                "Source": ip_layer.src,
                "Destination": ip_layer.dst,
            },
        })
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        protocol = "IPv6"
        layers.append({
            "name": "Internet Protocol v6",
            "fields": {
                "Version": 6,
                "Traffic Class": hex(ip_layer.tc),
                "Flow Label": hex(ip_layer.fl),
                "Payload Length": ip_layer.plen,
                "Next Header": ip_layer.nh,
                "Hop Limit": ip_layer.hlim,
                "Source": ip_layer.src,
                "Destination": ip_layer.dst,
            },
        })

    # Transport layer
    if TCP in pkt:
        tcp = pkt[TCP]
        src_port, dst_port = tcp.sport, tcp.dport
        protocol = "TCP"
        flags = _tcp_flags(int(tcp.flags))
        info = f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
        layers.append({
            "name": "Transmission Control Protocol",
            "fields": {
                "Source Port": tcp.sport,
                "Destination Port": tcp.dport,
                "Sequence Number": tcp.seq,
                "Acknowledgment Number": tcp.ack,
                "Flags": flags,
                "Window Size": tcp.window,
                "Checksum": hex(tcp.chksum or 0),
            },
        })
        app_proto = APP_PORTS.get(tcp.dport) or APP_PORTS.get(tcp.sport)
        if app_proto:
            protocol = app_proto
    elif UDP in pkt:
        udp = pkt[UDP]
        src_port, dst_port = udp.sport, udp.dport
        protocol = "UDP"
        info = f"{udp.sport} → {udp.dport} Len={udp.len}"
        layers.append({
            "name": "User Datagram Protocol",
            "fields": {
                "Source Port": udp.sport,
                "Destination Port": udp.dport,
                "Length": udp.len,
                "Checksum": hex(udp.chksum or 0),
            },
        })
        app_proto = APP_PORTS.get(udp.dport) or APP_PORTS.get(udp.sport)
        if app_proto:
            protocol = app_proto
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        protocol = "ICMP"
        info = f"type={icmp.type} code={icmp.code}"
        layers.append({
            "name": "Internet Control Message Protocol",
            "fields": {
                "Type": icmp.type,
                "Code": icmp.code,
                "Checksum": hex(icmp.chksum or 0),
            },
        })

    # Application-layer specifics
    if DNS in pkt:
        dns = pkt[DNS]
        protocol = "DNS"
        qname = ""
        if dns.qd and hasattr(dns.qd, "qname"):
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
        info = f"Standard query {'response' if dns.qr else ''} 0x{dns.id:04x} {qname}".strip()
        layers.append({
            "name": "Domain Name System",
            "fields": {
                "Transaction ID": hex(dns.id),
                "Flags": hex(dns.flags) if hasattr(dns, "flags") else "",
                "Questions": dns.qdcount,
                "Answer RRs": dns.ancount,
                "Query": qname,
            },
        })

    try:
        if HTTPRequest in pkt:
            http = pkt[HTTPRequest]
            protocol = "HTTP"
            method = (http.Method or b"").decode(errors="ignore")
            path = (http.Path or b"").decode(errors="ignore")
            host = (http.Host or b"").decode(errors="ignore")
            info = f"{method} {host}{path}"
            layers.append({
                "name": "Hypertext Transfer Protocol",
                "fields": {
                    "Method": method,
                    "Host": host,
                    "Path": path,
                    "User-Agent": (http.User_Agent or b"").decode(errors="ignore"),
                },
            })
        elif HTTPResponse in pkt:
            http = pkt[HTTPResponse]
            protocol = "HTTP"
            code = (http.Status_Code or b"").decode(errors="ignore")
            reason = (http.Reason_Phrase or b"").decode(errors="ignore")
            info = f"HTTP/1.1 {code} {reason}"
            layers.append({
                "name": "Hypertext Transfer Protocol",
                "fields": {
                    "Status": f"{code} {reason}",
                    "Server": (http.Server or b"").decode(errors="ignore"),
                },
            })
    except Exception:
        pass

    try:
        if TLS is not None and TLS in pkt:
            protocol = "TLS"
            info = info or "TLS Application Data"
            layers.append({"name": "Transport Layer Security", "fields": {"Content": "TLS record"}})
    except Exception:
        pass

    return {
        "id": str(uuid.uuid4()),
        "number": number,
        "timestamp": ts,
        "time_str": datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
        "info": info or pkt.summary(),
        "layers": layers,
        "hex": raw_bytes.hex(),
        "flags": _tcp_flags(int(pkt[TCP].flags)) if TCP in pkt else "",
    }


# ---------- Threat detection ----------

@dataclass
class ThreatState:
    syn_counts: Dict[str, Deque[float]] = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=200)))
    port_scan: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    port_scan_ts: Dict[str, float] = field(default_factory=dict)
    icmp_counts: Dict[str, Deque[float]] = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=200)))
    dns_query_lens: Dict[str, Deque[int]] = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=50)))


def detect_threats(dp: Dict[str, Any], state: ThreatState) -> Optional[Dict[str, Any]]:
    """Rule-based anomaly detection. Returns a threat dict or None."""
    now = dp["timestamp"]
    proto = dp["protocol"]
    src = dp["src_ip"]
    dst = dp["dst_ip"]
    port = dp.get("dst_port")

    # SYN flood
    if "SYN" in dp.get("flags", "") and "ACK" not in dp.get("flags", "") and src:
        q = state.syn_counts[src]
        q.append(now)
        while q and now - q[0] > 5:
            q.popleft()
        if len(q) > 60:
            return {
                "id": str(uuid.uuid4()),
                "severity": "critical",
                "type": "SYN Flood",
                "title": f"Possible SYN flood from {src}",
                "description": f"{len(q)} SYN packets in last 5s from {src}",
                "src": src, "dst": dst, "timestamp": now,
                "packet_id": dp["id"],
            }

    # Port scan: single src probing many dst ports on same dst
    if proto in ("TCP", "HTTP", "HTTPS", "SSH", "FTP") and src and dst and port:
        key = f"{src}->{dst}"
        state.port_scan[key].add(port)
        state.port_scan_ts[key] = now
        if len(state.port_scan[key]) > 15:
            threat = {
                "id": str(uuid.uuid4()),
                "severity": "high",
                "type": "Port Scan",
                "title": f"Port scan: {src} → {dst}",
                "description": f"Probed {len(state.port_scan[key])} ports on {dst}",
                "src": src, "dst": dst, "timestamp": now,
                "packet_id": dp["id"],
            }
            state.port_scan[key] = set()
            return threat

    # ICMP flood
    if proto == "ICMP" and src:
        q = state.icmp_counts[src]
        q.append(now)
        while q and now - q[0] > 5:
            q.popleft()
        if len(q) > 50:
            return {
                "id": str(uuid.uuid4()),
                "severity": "high",
                "type": "ICMP Flood",
                "title": f"ICMP flood from {src}",
                "description": f"{len(q)} ICMP packets in last 5s",
                "src": src, "dst": dst, "timestamp": now,
                "packet_id": dp["id"],
            }

    # DNS tunneling heuristic: very long query names
    if proto == "DNS" and src:
        info = dp.get("info", "")
        if len(info) > 80:
            return {
                "id": str(uuid.uuid4()),
                "severity": "medium",
                "type": "DNS Tunneling",
                "title": f"Suspiciously long DNS query from {src}",
                "description": f"Query length {len(info)} may indicate exfiltration",
                "src": src, "dst": dst, "timestamp": now,
                "packet_id": dp["id"],
            }

    # Cleartext credentials (HTTP POST on login paths)
    if proto == "HTTP" and "POST" in dp.get("info", "") and any(k in dp.get("info", "").lower() for k in ("login", "auth", "signin", "password")):
        return {
            "id": str(uuid.uuid4()),
            "severity": "medium",
            "type": "Cleartext Credentials",
            "title": "Unencrypted authentication request",
            "description": "HTTP POST to a login endpoint without TLS",
            "src": src, "dst": dst, "timestamp": now,
            "packet_id": dp["id"],
        }

    return None


# ---------- Traffic simulator (used when live capture isn't permitted) ----------

LOCAL_HOSTS = [
    ("192.168.1.10", "AA:BB:CC:11:22:33"),
    ("192.168.1.42", "AA:BB:CC:11:22:34"),
    ("192.168.1.105", "AA:BB:CC:11:22:35"),
    ("192.168.1.200", "AA:BB:CC:11:22:36"),
    ("10.0.0.5", "AA:BB:CC:11:22:37"),
]
GATEWAY = ("192.168.1.1", "AA:BB:CC:00:00:01")
EXTERNAL = [
    ("142.250.80.46", "google.com"),
    ("151.101.1.69", "stackoverflow.com"),
    ("104.16.132.229", "cloudflare.com"),
    ("185.199.108.153", "github.com"),
    ("13.107.42.14", "microsoft.com"),
    ("52.84.150.39", "amazonaws.com"),
    ("8.8.8.8", "dns.google"),
]


def _simulate_one(number: int, ts: float, anomaly: bool = False) -> Packet:
    r = random.random()
    local = random.choice(LOCAL_HOSTS)
    ext_ip, ext_host = random.choice(EXTERNAL)
    inbound = random.random() < 0.4

    if anomaly:
        # SYN flood burst
        pkt = Ether(src=local[1], dst=GATEWAY[1]) / IP(src=local[0], dst=ext_ip) / \
            TCP(sport=random.randint(40000, 65000), dport=random.choice([80, 443, 22]), flags="S", seq=random.randint(0, 2**32 - 1))
        return pkt

    if r < 0.55:  # TCP/HTTPS
        src_ip, dst_ip = (local[0], ext_ip) if not inbound else (ext_ip, local[0])
        src_mac, dst_mac = (local[1], GATEWAY[1]) if not inbound else (GATEWAY[1], local[1])
        dport = random.choice([443, 443, 443, 80, 22, 8080])
        sport = random.randint(40000, 65000)
        flag = random.choice(["S", "SA", "A", "PA", "FA"])
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
            TCP(sport=sport, dport=dport, flags=flag, seq=random.randint(0, 2**32 - 1), ack=random.randint(0, 2**32 - 1), window=65535)
        if flag == "PA" and dport in (80, 8080):
            payload = f"GET /api/data HTTP/1.1\r\nHost: {ext_host}\r\nUser-Agent: EtherLens/1.0\r\n\r\n".encode()
            pkt = pkt / Raw(load=payload)
        elif flag == "PA":
            pkt = pkt / Raw(load=os.urandom(random.randint(64, 512)))
        return pkt
    if r < 0.75:  # UDP/DNS
        q = random.choice([ext_host, f"api.{ext_host}", f"cdn.{ext_host}"])
        pkt = Ether(src=local[1], dst=GATEWAY[1]) / IP(src=local[0], dst="8.8.8.8") / \
            UDP(sport=random.randint(40000, 65000), dport=53) / \
            DNS(rd=1, qd=[__import__("scapy.layers.dns", fromlist=["DNSQR"]).DNSQR(qname=q)])
        return pkt
    if r < 0.85:  # ICMP ping
        pkt = Ether(src=local[1], dst=GATEWAY[1]) / IP(src=local[0], dst=ext_ip) / ICMP(type=8, code=0)
        return pkt
    if r < 0.92:  # ARP
        pkt = Ether(src=local[1], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=local[1], psrc=local[0], pdst=random.choice(LOCAL_HOSTS)[0])
        return pkt
    # UDP generic (QUIC-ish)
    pkt = Ether(src=local[1], dst=GATEWAY[1]) / IP(src=local[0], dst=ext_ip) / \
        UDP(sport=random.randint(40000, 65000), dport=443) / Raw(load=os.urandom(random.randint(100, 900)))
    return pkt


# ---------- Capture session ----------

class CaptureSession:
    """Manages one capture session with ring buffers, stats and threat state."""

    MAX_PACKETS = 5000
    MAX_THREATS = 300

    def __init__(self):
        self.packets: Deque[Dict[str, Any]] = deque(maxlen=self.MAX_PACKETS)
        self.threats: Deque[Dict[str, Any]] = deque(maxlen=self.MAX_THREATS)
        self.by_id: Dict[str, Dict[str, Any]] = {}
        self.running = False
        self.mode = "idle"  # idle|simulated|live|pcap
        self.interface = ""
        self.counter = 0
        self.start_ts: Optional[float] = None
        self.threat_state = ThreatState()
        self.flows: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.timeline: Deque[Dict[str, Any]] = deque(maxlen=120)  # 1 bucket / sec
        self._task: Optional[asyncio.Task] = None
        self._subscribers: List[asyncio.Queue] = []
        self._anomaly_countdown = random.randint(80, 200)

    # ---- lifecycle ----
    async def start(self, interface: str = "simulated"):
        if self.running:
            return
        self.running = True
        self.interface = interface
        self.start_ts = time.time()
        self.mode = "live" if interface not in ("simulated", "", None) else "simulated"
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass
            self._task = None
        self.mode = "idle"

    def clear(self):
        self.packets.clear()
        self.threats.clear()
        self.by_id.clear()
        self.flows.clear()
        self.hosts.clear()
        self.timeline.clear()
        self.counter = 0
        self.threat_state = ThreatState()

    # ---- subscribers (WebSocket) ----
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def _broadcast(self, msg: Dict[str, Any]):
        dead = []
        for q in self._subscribers:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)

    # ---- ingestion ----
    def ingest(self, pkt: Packet, ts: Optional[float] = None) -> Dict[str, Any]:
        self.counter += 1
        ts = ts if ts is not None else time.time()
        dp = dissect_packet(pkt, self.counter, ts)
        self.packets.append(dp)
        self.by_id[dp["id"]] = dp

        # Update flow stats
        if dp["src_ip"] and dp["dst_ip"]:
            key = tuple(sorted([dp["src_ip"], dp["dst_ip"]]))
            f = self.flows.get(key)
            if f is None:
                f = {"a": key[0], "b": key[1], "packets": 0, "bytes": 0, "protocols": set(), "last_ts": ts}
                self.flows[key] = f
            f["packets"] += 1
            f["bytes"] += dp["length"]
            f["protocols"].add(dp["protocol"])
            f["last_ts"] = ts

            for ip in (dp["src_ip"], dp["dst_ip"]):
                h = self.hosts.get(ip)
                if h is None:
                    h = {"ip": ip, "packets": 0, "bytes": 0, "ports": set(), "last_ts": ts}
                    self.hosts[ip] = h
                h["packets"] += 1
                h["bytes"] += dp["length"]
                if dp.get("dst_port"):
                    h["ports"].add(dp["dst_port"])
                h["last_ts"] = ts

        # Timeline bucket (per second)
        bucket_t = int(ts)
        if not self.timeline or self.timeline[-1]["t"] != bucket_t:
            self.timeline.append({"t": bucket_t, "pps": 0, "bps": 0, "by_proto": {}})
        bucket = self.timeline[-1]
        bucket["pps"] += 1
        bucket["bps"] += dp["length"] * 8
        bucket["by_proto"][dp["protocol"]] = bucket["by_proto"].get(dp["protocol"], 0) + 1

        # Threats
        threat = detect_threats(dp, self.threat_state)
        if threat:
            self.threats.append(threat)
        return dp

    # ---- capture loop ----
    async def _loop(self):
        """Try live capture via scapy AsyncSniffer; fall back to simulator."""
        try:
            if self.mode == "live":
                try:
                    from scapy.all import AsyncSniffer  # type: ignore
                    loop = asyncio.get_running_loop()

                    def _cb(pkt):
                        try:
                            dp = self.ingest(pkt)
                            asyncio.run_coroutine_threadsafe(self._broadcast({"type": "packet", "data": dp}), loop)
                            # emit newest threat if any
                            if self.threats:
                                t = self.threats[-1]
                                if t.get("packet_id") == dp["id"]:
                                    asyncio.run_coroutine_threadsafe(self._broadcast({"type": "threat", "data": t}), loop)
                        except Exception:
                            pass

                    sniffer = AsyncSniffer(iface=self.interface, prn=_cb, store=False)
                    sniffer.start()
                    try:
                        while self.running:
                            await asyncio.sleep(0.5)
                    finally:
                        try:
                            sniffer.stop()
                        except Exception:
                            pass
                    return
                except Exception as e:
                    # Fall through to simulator mode, but tag note
                    self.mode = "simulated"
                    await self._broadcast({"type": "notice", "data": {
                        "message": f"Live capture unavailable ({e.__class__.__name__}): falling back to simulator"
                    }})

            # Simulator loop
            while self.running:
                # 1–8 packets per tick (every 70ms) ≈ ~70 pps
                burst = random.randint(1, 8)
                for _ in range(burst):
                    anomaly = False
                    self._anomaly_countdown -= 1
                    if self._anomaly_countdown <= 0:
                        anomaly = True
                        self._anomaly_countdown = random.randint(150, 400)
                        burst_size = random.randint(60, 120)
                        for _b in range(burst_size):
                            pkt = _simulate_one(0, time.time(), anomaly=True)
                            dp = self.ingest(pkt)
                            await self._broadcast({"type": "packet", "data": dp})
                            if self.threats and self.threats[-1].get("packet_id") == dp["id"]:
                                await self._broadcast({"type": "threat", "data": self.threats[-1]})
                        continue
                    pkt = _simulate_one(0, time.time(), anomaly=anomaly)
                    dp = self.ingest(pkt)
                    await self._broadcast({"type": "packet", "data": dp})
                    if self.threats and self.threats[-1].get("packet_id") == dp["id"]:
                        await self._broadcast({"type": "threat", "data": self.threats[-1]})
                await asyncio.sleep(0.07)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger_fallback = __import__("logging").getLogger("etherlens.engine")
            logger_fallback.exception("capture loop crashed: %s", e)

    # ---- PCAP import ----
    def ingest_pcap_bytes(self, data: bytes) -> int:
        buf = io.BytesIO(data)
        pkts = rdpcap(buf)
        n = 0
        for p in pkts:
            ts = float(p.time) if hasattr(p, "time") and p.time else time.time()
            self.ingest(p, ts=ts)
            n += 1
        self.mode = "pcap"
        return n

    # ---- serialisation ----
    def stats(self) -> Dict[str, Any]:
        now = time.time()
        total = len(self.packets)
        total_bytes = sum(p["length"] for p in self.packets)
        proto_counts: Dict[str, int] = {}
        for p in self.packets:
            proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        duration = max(1.0, now - (self.start_ts or now))
        return {
            "running": self.running,
            "mode": self.mode,
            "interface": self.interface,
            "total_packets": total,
            "total_bytes": total_bytes,
            "pps": round(total / duration, 1),
            "mbps": round((total_bytes * 8) / (duration * 1_000_000), 3),
            "threats": len(self.threats),
            "unique_hosts": len(self.hosts),
            "unique_flows": len(self.flows),
            "protocol_counts": proto_counts,
            "duration_sec": round(duration, 1),
        }

    def timeline_series(self) -> List[Dict[str, Any]]:
        return [{"t": b["t"], "pps": b["pps"], "bps": b["bps"], "by_proto": b["by_proto"]} for b in self.timeline]

    def top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        rows = sorted(self.hosts.values(), key=lambda h: h["bytes"], reverse=True)[:limit]
        return [{"ip": h["ip"], "packets": h["packets"], "bytes": h["bytes"], "ports": sorted(h["ports"])[:10]} for h in rows]

    def topology(self) -> Dict[str, Any]:
        nodes = []
        for ip, h in self.hosts.items():
            is_local = ip.startswith(("10.", "192.168.", "172.")) or ip in ("127.0.0.1",)
            nodes.append({
                "id": ip,
                "packets": h["packets"],
                "bytes": h["bytes"],
                "ports": sorted(h["ports"])[:8],
                "type": "local" if is_local else "external",
            })
        edges = []
        for (a, b), f in self.flows.items():
            edges.append({
                "source": a, "target": b,
                "packets": f["packets"], "bytes": f["bytes"],
                "protocols": sorted(list(f["protocols"]))[:4],
            })
        return {"nodes": nodes, "edges": edges}

    def list_packets(self, limit: int = 500, protocol: Optional[str] = None, q: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        proto = (protocol or "").upper().strip()
        qs = (q or "").lower().strip()
        for p in reversed(self.packets):
            if proto and p["protocol"].upper() != proto:
                continue
            if qs:
                hay = f"{p['src_ip']} {p['dst_ip']} {p['protocol']} {p['info']} {p.get('src_port','')} {p.get('dst_port','')}".lower()
                if qs not in hay:
                    continue
            out.append({k: v for k, v in p.items() if k != "layers" and k != "hex"})
            if len(out) >= limit:
                break
        return out

    def list_threats(self) -> List[Dict[str, Any]]:
        return list(reversed(self.threats))

    def get_packet(self, pid: str) -> Optional[Dict[str, Any]]:
        return self.by_id.get(pid)
