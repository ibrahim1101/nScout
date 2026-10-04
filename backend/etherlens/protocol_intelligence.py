"""Protocol-level intelligence for nScout investigations."""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any, Dict, List


def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()):
            return layer.get("fields", {}) or {}
    return {}


def tls_intelligence(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize visible TLS metadata without claiming encrypted payload access."""
    events = []
    servers = Counter()
    versions = Counter()
    warnings = []
    for p in packets:
        tls = _layer(p, "Transport Layer Security")
        # HTTPS-by-port is useful context, but is not proof that a TLS layer was decoded.
        if not tls and p.get("protocol") not in ("TLS", "HTTPS"):
            continue
        sni = str(tls.get("SNI") or tls.get("Server Name") or "")
        version = str(tls.get("Version") or "")
        alpn = tls.get("ALPN") or tls.get("Application Protocol")
        event = {
            "packet_id": p.get("id"), "timestamp": p.get("timestamp"),
            "src_ip": p.get("src_ip"), "src_port": p.get("src_port"),
            "dst_ip": p.get("dst_ip"), "dst_port": p.get("dst_port"),
            "sni": sni, "version": version, "cipher": tls.get("Cipher Suite"),
            "alpn": alpn, "handshake": tls.get("Handshake"),
            "certificate_issuer": tls.get("Certificate Issuer"),
            "certificate_expiry": tls.get("Certificate Expiry"),
            "decoded": bool(tls),
        }
        events.append(event)
        if sni: servers[sni] += 1
        if version: versions[version] += 1
        if version in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"):
            warnings.append({"packet_id": p.get("id"), "type": "legacy_tls", "detail": version})
    return {
        "events": events,
        "top_server_names": [{"server_name": k, "packets": v} for k, v in servers.most_common(25)],
        "versions": [{"version": k, "packets": v} for k, v in versions.most_common()],
        "warnings": warnings,
        "note": "TLS metadata is derived only from visible handshake/record information; encrypted application payload is not decrypted.",
    }


def packet_timeline(packets: List[Dict[str, Any]], bucket_seconds: float = 1.0) -> List[Dict[str, Any]]:
    """Create investigation timeline buckets with protocol and event counts."""
    if not packets:
        return []
    bucket_seconds = max(0.1, float(bucket_seconds))
    origin = min(float(p.get("timestamp") or 0) for p in packets)
    buckets = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocols": Counter(), "events": Counter()})
    for p in packets:
        ts = float(p.get("timestamp") or origin)
        index = int((ts - origin) / bucket_seconds)
        b = buckets[index]
        b["packets"] += 1
        b["bytes"] += int(p.get("length") or 0)
        proto = str(p.get("protocol") or "Unknown")
        b["protocols"][proto] += 1
        flags = str(p.get("flags") or "")
        if "SYN" in flags and "ACK" not in flags: b["events"]["connection_start"] += 1
        if "FIN" in flags: b["events"]["connection_close"] += 1
        if "RST" in flags: b["events"]["tcp_reset"] += 1
        if proto == "DNS": b["events"]["dns"] += 1
    out = []
    for index in sorted(buckets):
        b = buckets[index]
        out.append({
            "start": origin + index * bucket_seconds,
            "end": origin + (index + 1) * bucket_seconds,
            "packets": b["packets"], "bytes": b["bytes"],
            "protocols": dict(b["protocols"]), "events": dict(b["events"]),
        })
    return out


def packet_ascii(packet: Dict[str, Any]) -> str:
    """Return a safe printable ASCII representation of captured raw bytes."""
    raw_hex = str(packet.get("hex") or "")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return ""
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
