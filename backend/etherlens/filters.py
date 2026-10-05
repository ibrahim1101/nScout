"""Smart packet filtering for nScout investigations.

Supports simple analyst-friendly expressions without eval(), for example:
  protocol:dns src:10.0.0.5
  port:443 bytes>1000
  tcp.reset
  dns.query:example.com
  http.host:api.example.com
Multiple tokens are ANDed. A leading ! negates a token.
"""
from __future__ import annotations

import shlex
from typing import Any, Dict, Iterable, List


def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()):
            return layer.get("fields", {}) or {}
    return {}


def _contains(value: Any, needle: str) -> bool:
    return needle.lower() in str(value or "").lower()


def _numeric_compare(actual: Any, op: str, expected: str) -> bool:
    try:
        a, b = float(actual or 0), float(expected)
    except (TypeError, ValueError):
        return False
    return {">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b, "=": a == b}[op]


def _match(packet: Dict[str, Any], token: str, health: Dict[str, Any] | None = None) -> bool:
    low = token.lower()
    for field, key in (("protocol:", "protocol"), ("src:", "src_ip"), ("dst:", "dst_ip"), ("info:", "info")):
        if low.startswith(field):
            return _contains(packet.get(key), token[len(field):])
    if low.startswith("port:"):
        value = token[5:]
        return value in {str(packet.get("src_port") or ""), str(packet.get("dst_port") or "")}
    for name, actual in (("bytes", packet.get("length")), ("length", packet.get("length")), ("srcport", packet.get("src_port")), ("dstport", packet.get("dst_port"))):
        for op in (">=", "<=", ">", "<", "="):
            prefix = name + op
            if low.startswith(prefix):
                return _numeric_compare(actual, op, token[len(prefix):])
    dns = _layer(packet, "Domain Name System")
    http = _layer(packet, "Hypertext Transfer Protocol")
    if low.startswith("dns.query:"):
        return _contains(dns.get("Query"), token[10:])
    if low.startswith("dns.rcode:"):
        return str(dns.get("Response Code", "")).lower() == token[10:].lower()
    if low.startswith("http.host:"):
        return _contains(http.get("Host"), token[10:])
    if low.startswith("http.method:"):
        return str(http.get("Method", "")).lower() == token[12:].lower()
    if low.startswith("http.status:"):
        return str(http.get("Status", "")).lower().startswith(token[12:].lower())
    if low.startswith("tcp."):
        events = (health or {}).get(str(packet.get("id")), {}).get("events", [])
        return low in {str(e).lower() for e in events}
    # Free-text fallback searches common packet metadata.
    return any(_contains(packet.get(k), token) for k in ("protocol", "src_ip", "dst_ip", "info", "flags"))


def filter_packets(packets: Iterable[Dict[str, Any]], expression: str, health: Dict[str, Any] | None = None, limit: int = 500) -> List[Dict[str, Any]]:
    """Filter packets with a small, safe query language. Invalid quoting returns no matches."""
    try:
        tokens = shlex.split(expression or "")
    except ValueError:
        return []
    if not tokens:
        return list(packets)[:limit]
    out: List[Dict[str, Any]] = []
    for packet in packets:
        ok = True
        for raw in tokens:
            negate = raw.startswith("!") and len(raw) > 1
            token = raw[1:] if negate else raw
            matched = _match(packet, token, health)
            if matched == negate:
                ok = False
                break
        if ok:
            out.append(packet)
            if len(out) >= limit:
                break
    return out
