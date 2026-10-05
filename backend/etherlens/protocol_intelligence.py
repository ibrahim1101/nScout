"""Protocol-level intelligence for nScout investigations."""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List


def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()):
            return layer.get("fields", {}) or {}
    return {}


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value if v not in (None, ""))
    return str(value)


def _expiry_is_past(value: Any) -> bool:
    """Best-effort expiry check for already-decoded certificate timestamps."""
    text = _as_text(value).strip()
    if not text:
        return False
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed < datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False


def tls_intelligence(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize only TLS metadata visible in decoded handshake/record fields.

    Port 443/8443 traffic remains useful context even when no TLS handshake was
    decoded, but such packets are explicitly marked decoded=False. This function
    never infers or exposes encrypted application payload contents.
    """
    events = []
    servers = Counter()
    versions = Counter()
    alpns = Counter()
    ciphers = Counter()
    handshakes = Counter()
    warnings = []
    for p in packets:
        tls = _layer(p, "Transport Layer Security")
        if not tls and p.get("protocol") not in ("TLS", "HTTPS"):
            continue
        sni = _as_text(tls.get("SNI") or tls.get("Server Name"))
        version = _as_text(tls.get("Version") or tls.get("TLS Version"))
        alpn = _as_text(tls.get("ALPN") or tls.get("Application Protocol"))
        cipher = _as_text(tls.get("Cipher Suite") or tls.get("Cipher"))
        handshake = _as_text(tls.get("Handshake") or tls.get("Handshake Type"))
        issuer = _as_text(tls.get("Certificate Issuer"))
        subject = _as_text(tls.get("Certificate Subject"))
        expiry = _as_text(tls.get("Certificate Expiry") or tls.get("Certificate Not After"))
        event = {
            "packet_id": p.get("id"), "timestamp": p.get("timestamp"),
            "src_ip": p.get("src_ip"), "src_port": p.get("src_port"),
            "dst_ip": p.get("dst_ip"), "dst_port": p.get("dst_port"),
            "sni": sni, "version": version, "cipher": cipher,
            "alpn": alpn, "handshake": handshake,
            "certificate_issuer": issuer, "certificate_subject": subject,
            "certificate_expiry": expiry, "decoded": bool(tls),
        }
        events.append(event)
        if sni: servers[sni] += 1
        if version: versions[version] += 1
        if alpn: alpns[alpn] += 1
        if cipher: ciphers[cipher] += 1
        if handshake: handshakes[handshake] += 1
        if version.upper().replace("V", "") in ("SSL2", "SSL3", "TLS 1.0", "TLS 1.1"):
            warnings.append({"packet_id": p.get("id"), "type": "legacy_tls", "detail": version})
        if _expiry_is_past(expiry):
            warnings.append({"packet_id": p.get("id"), "type": "expired_certificate", "detail": expiry})
    return {
        "events": events,
        "top_server_names": [{"server_name": k, "packets": v} for k, v in servers.most_common(25)],
        "versions": [{"version": k, "packets": v} for k, v in versions.most_common()],
        "alpns": [{"alpn": k, "packets": v} for k, v in alpns.most_common()],
        "cipher_suites": [{"cipher": k, "packets": v} for k, v in ciphers.most_common(25)],
        "handshakes": [{"handshake": k, "packets": v} for k, v in handshakes.most_common()],
        "warnings": warnings,
        "decoded_events": sum(1 for event in events if event["decoded"]),
        "metadata_only_events": sum(1 for event in events if not event["decoded"]),
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
