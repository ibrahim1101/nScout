"""nScout packet/connection intelligence helpers.

Pure analysis functions used by live captures and imported PCAP investigations.
They intentionally operate on nScout's normalized packet dictionaries so they
remain portable across Windows, Linux and Docker deployments.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

TCP_PROTOCOLS = {"TCP", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP", "SMTPS", "POP3", "POP3S", "IMAP", "IMAPS"}


def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()):
            return layer.get("fields", {}) or {}
    return {}


def _endpoint_key(ip: str, port: Any) -> Tuple[str, int]:
    try:
        return ip or "", int(port or 0)
    except (TypeError, ValueError):
        return ip or "", 0


def _flow_key(p: Dict[str, Any]) -> Tuple[Tuple[str, int], Tuple[str, int]]:
    a = _endpoint_key(p.get("src_ip", ""), p.get("src_port"))
    b = _endpoint_key(p.get("dst_ip", ""), p.get("dst_port"))
    return tuple(sorted((a, b)))  # type: ignore[return-value]


def annotate_tcp_health(packets: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Infer packet-level TCP health events without modifying input packets."""
    out: Dict[str, Dict[str, Any]] = {}
    seen_ranges: Dict[Tuple[str, int, str, int], List[Tuple[int, int]]] = defaultdict(list)
    last_seq: Dict[Tuple[str, int, str, int], int] = {}
    dup_acks: Dict[Tuple[str, int, str, int, int], int] = defaultdict(int)

    for p in sorted(packets, key=lambda x: (x.get("timestamp", 0), x.get("number", 0))):
        if p.get("protocol") not in TCP_PROTOCOLS:
            continue
        tcp = _layer(p, "Transmission Control Protocol")
        if not tcp:
            continue
        src, dst = p.get("src_ip", ""), p.get("dst_ip", "")
        sport, dport = int(p.get("src_port") or 0), int(p.get("dst_port") or 0)
        direction = (src, sport, dst, dport)
        flags = str(p.get("flags", ""))
        seq = int(tcp.get("Sequence Number") or 0)
        ack = int(tcp.get("Acknowledgment Number") or 0)
        payload = int(p.get("payload_size") or 0)
        events: List[str] = []

        if "RST" in flags:
            events.append("tcp.reset")
        if int(tcp.get("Window Size") or 0) == 0 and "RST" not in flags:
            events.append("tcp.zero_window")
        if payload:
            end = seq + payload
            if any(seq < old_end and end > old_start for old_start, old_end in seen_ranges[direction]):
                events.append("tcp.retransmission")
            elif direction in last_seq and seq < last_seq[direction]:
                events.append("tcp.out_of_order")
            seen_ranges[direction].append((seq, end))
            last_seq[direction] = max(last_seq.get(direction, seq), end)
        if "ACK" in flags and payload == 0:
            ack_key = (src, sport, dst, dport, ack)
            dup_acks[ack_key] += 1
            if dup_acks[ack_key] >= 3:
                events.append("tcp.duplicate_ack")

        if events:
            out[str(p.get("id"))] = {"events": sorted(set(events)), "healthy": False}
    return out


def connection_intelligence(packets: List[Dict[str, Any]], limit: int = 500) -> List[Dict[str, Any]]:
    health = annotate_tcp_health(packets)
    groups: Dict[Any, Dict[str, Any]] = {}
    for p in packets:
        if not p.get("src_ip") or not p.get("dst_ip"):
            continue
        key = _flow_key(p)
        row = groups.setdefault(key, {
            "a_ip": key[0][0], "a_port": key[0][1], "b_ip": key[1][0], "b_port": key[1][1],
            "packets": 0, "bytes": 0, "a_to_b_bytes": 0, "b_to_a_bytes": 0,
            "first_seen": p.get("timestamp", 0), "last_seen": p.get("timestamp", 0),
            "protocols": set(), "retransmissions": 0, "duplicate_acks": 0,
            "out_of_order": 0, "zero_windows": 0, "resets": 0, "state": "observed",
        })
        row["packets"] += 1
        size = int(p.get("length") or 0)
        row["bytes"] += size
        if _endpoint_key(p.get("src_ip", ""), p.get("src_port")) == key[0]:
            row["a_to_b_bytes"] += size
        else:
            row["b_to_a_bytes"] += size
        row["first_seen"] = min(row["first_seen"], p.get("timestamp", 0))
        row["last_seen"] = max(row["last_seen"], p.get("timestamp", 0))
        row["protocols"].add(p.get("protocol", "unknown"))
        events = health.get(str(p.get("id")), {}).get("events", [])
        row["retransmissions"] += int("tcp.retransmission" in events)
        row["duplicate_acks"] += int("tcp.duplicate_ack" in events)
        row["out_of_order"] += int("tcp.out_of_order" in events)
        row["zero_windows"] += int("tcp.zero_window" in events)
        row["resets"] += int("tcp.reset" in events)
        flags = str(p.get("flags", ""))
        if "SYN" in flags and "ACK" not in flags:
            row["state"] = "connecting"
        if "SYN" in flags and "ACK" in flags:
            row["state"] = "established"
        if "FIN" in flags:
            row["state"] = "closing"
        if "RST" in flags:
            row["state"] = "reset"

    rows = []
    for row in groups.values():
        row["duration_ms"] = round(max(0, row["last_seen"] - row["first_seen"]) * 1000, 3)
        row["protocols"] = sorted(row["protocols"])
        rows.append(row)
    return sorted(rows, key=lambda r: (r["bytes"], r["packets"]), reverse=True)[:limit]


def protocol_dashboard(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    protocols = Counter(str(p.get("protocol") or "Unknown") for p in packets)
    ports = Counter()
    endpoints = Counter()
    for p in packets:
        if p.get("src_ip"):
            endpoints[p["src_ip"]] += int(p.get("length") or 0)
        if p.get("dst_ip"):
            endpoints[p["dst_ip"]] += int(p.get("length") or 0)
        for port in (p.get("src_port"), p.get("dst_port")):
            if port:
                ports[int(port)] += 1
    total = sum(protocols.values()) or 1
    return {
        "total_packets": len(packets),
        "total_bytes": sum(int(p.get("length") or 0) for p in packets),
        "protocols": [{"protocol": k, "packets": v, "percent": round(v * 100 / total, 2)} for k, v in protocols.most_common()],
        "top_ports": [{"port": k, "packets": v} for k, v in ports.most_common(15)],
        "top_endpoints": [{"ip": k, "bytes": v} for k, v in endpoints.most_common(15)],
    }


def investigation_summary(packets: List[Dict[str, Any]], threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    connections = connection_intelligence(packets)
    health = annotate_tcp_health(packets)
    health_counts = Counter(event for value in health.values() for event in value.get("events", []))
    interesting = [
        {"packet_id": pid, **value}
        for pid, value in health.items()
    ][:100]
    return {
        "overview": protocol_dashboard(packets),
        "connections": connections[:50],
        "tcp_health": dict(health_counts),
        "threats": threats[:100],
        "interesting_packets": interesting,
    }
