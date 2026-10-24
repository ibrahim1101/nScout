"""Protocol-level intelligence for nScout investigations."""
from __future__ import annotations
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
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


def _parse_time(value: Any) -> datetime | None:
    text = _as_text(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _tls_version(value: int) -> str:
    return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(value, f"0x{value:04x}")


def _is_grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and (value >> 8) == (value & 0xFF)


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise ValueError("truncated TLS field")
    return int.from_bytes(data[offset:offset + 2], "big")


def _vector(data: bytes, offset: int, width: int = 2) -> tuple[bytes, int]:
    if offset + width > len(data):
        raise ValueError("truncated TLS vector")
    length = int.from_bytes(data[offset:offset + width], "big")
    start, end = offset + width, offset + width + length
    if end > len(data):
        raise ValueError("truncated TLS vector")
    return data[start:end], end


def _extensions(data: bytes) -> tuple[List[tuple[int, bytes]], List[int], List[int]]:
    rows, groups, point_formats = [], [], []
    offset = 0
    while offset + 4 <= len(data):
        kind, size = _u16(data, offset), _u16(data, offset + 2)
        offset += 4
        if offset + size > len(data):
            raise ValueError("truncated TLS extension")
        value = data[offset:offset + size]
        rows.append((kind, value)); offset += size
        if kind == 10 and len(value) >= 2:
            vector, _ = _vector(value, 0)
            groups = [_u16(vector, index) for index in range(0, len(vector) - 1, 2)]
        elif kind == 11 and value:
            vector, _ = _vector(value, 0, 1)
            point_formats = list(vector)
    return rows, groups, point_formats


def _sni(value: bytes) -> str:
    try:
        names, _ = _vector(value, 0)
        if len(names) < 3 or names[0] != 0:
            return ""
        name, _ = _vector(names, 1)
        return name.decode("idna", errors="strict")[:253]
    except (UnicodeError, ValueError):
        return ""


def _alpn(value: bytes) -> List[str]:
    try:
        protocols, _ = _vector(value, 0)
        rows, offset = [], 0
        while offset < len(protocols):
            item, offset = _vector(protocols, offset, 1)
            rows.append(item.decode("ascii", errors="replace")[:64])
        return rows[:20]
    except ValueError:
        return []


def decode_tls_payload(payload: bytes) -> Dict[str, Any]:
    """Decode bounded, visible ClientHello/ServerHello metadata from one TLS record."""
    if not isinstance(payload, (bytes, bytearray)) or len(payload) < 9 or len(payload) > 1024 * 1024:
        return {}
    data = bytes(payload)
    if data[0] != 22 or data[1] != 3:
        return {}
    record_length = _u16(data, 3)
    if record_length < 4 or record_length > len(data) - 5:
        return {}
    handshake_type = data[5]
    handshake_length = int.from_bytes(data[6:9], "big")
    if handshake_type not in (1, 2) or handshake_length > record_length - 4 or 9 + handshake_length > len(data):
        return {}
    body = data[9:9 + handshake_length]
    try:
        if len(body) < 35:
            return {}
        legacy_version = _u16(body, 0)
        offset = 34
        session_id, offset = _vector(body, offset, 1)
        fields: Dict[str, Any] = {"Record Version": _tls_version(_u16(data, 1)),
                                  "Handshake": "Client Hello" if handshake_type == 1 else "Server Hello"}
        if handshake_type == 1:
            cipher_data, offset = _vector(body, offset)
            ciphers = [_u16(cipher_data, index) for index in range(0, len(cipher_data) - 1, 2)]
            _, offset = _vector(body, offset, 1)
        else:
            if offset + 3 > len(body):
                return {}
            ciphers = [_u16(body, offset)]; offset += 3
        extension_rows, groups, points = [], [], []
        if offset < len(body):
            extension_data, offset = _vector(body, offset)
            extension_rows, groups, points = _extensions(extension_data)
        extension_types = [kind for kind, _ in extension_rows]
        offered_versions = []
        for kind, value in extension_rows:
            if kind == 0:
                fields["SNI"] = _sni(value)
            elif kind == 16:
                fields["ALPN"] = _alpn(value)
            elif kind == 43:
                if handshake_type == 1 and value:
                    versions, _ = _vector(value, 0, 1)
                    offered_versions = [_u16(versions, index) for index in range(0, len(versions) - 1, 2)]
                elif len(value) == 2:
                    offered_versions = [_u16(value, 0)]
        visible_versions = offered_versions or [legacy_version]
        fields["Version"] = _tls_version(visible_versions[0])
        fields["Offered Versions"] = [_tls_version(value) for value in visible_versions]
        fields["Cipher Suites"] = [f"0x{value:04x}" for value in ciphers[:256]]
        fields["Cipher Suite"] = fields["Cipher Suites"][0] if handshake_type == 2 and ciphers else ""
        clean_ciphers = [value for value in ciphers if not _is_grease(value)]
        clean_extensions = [value for value in extension_types if not _is_grease(value)]
        clean_groups = [value for value in groups if not _is_grease(value)]
        if handshake_type == 1:
            ja3 = ",".join((str(legacy_version), "-".join(map(str, clean_ciphers)),
                            "-".join(map(str, clean_extensions)), "-".join(map(str, clean_groups)),
                            "-".join(map(str, points))))
            fields["JA3"] = hashlib.md5(ja3.encode("ascii"), usedforsecurity=False).hexdigest()
        else:
            ja3s = ",".join((str(visible_versions[0]), str(clean_ciphers[0] if clean_ciphers else 0),
                             "-".join(map(str, clean_extensions))))
            fields["JA3S"] = hashlib.md5(ja3s.encode("ascii"), usedforsecurity=False).hexdigest()
        return {key: value for key, value in fields.items() if value not in (None, "", [])}
    except (IndexError, ValueError):
        return {}


def tls_intelligence(packets: List[Dict[str, Any]], now: datetime | None = None) -> Dict[str, Any]:
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
    fingerprints = Counter()
    warnings = []
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
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
        not_before = _as_text(tls.get("Certificate Not Before"))
        offered_versions = tls.get("Offered Versions") or []
        offered_ciphers = tls.get("Cipher Suites") or []
        ja3 = _as_text(tls.get("JA3")); ja3s = _as_text(tls.get("JA3S"))
        event = {
            "packet_id": p.get("id"), "timestamp": p.get("timestamp"),
            "src_ip": p.get("src_ip"), "src_port": p.get("src_port"),
            "dst_ip": p.get("dst_ip"), "dst_port": p.get("dst_port"),
            "sni": sni, "version": version, "cipher": cipher,
            "alpn": alpn, "handshake": handshake,
            "certificate_issuer": issuer, "certificate_subject": subject,
            "certificate_expiry": expiry, "decoded": bool(tls),
            "certificate_not_before": not_before,
            "offered_versions": offered_versions if isinstance(offered_versions, list) else [offered_versions],
            "offered_ciphers": offered_ciphers if isinstance(offered_ciphers, list) else [offered_ciphers],
            "ja3": ja3, "ja3s": ja3s,
        }
        events.append(event)
        if sni: servers[sni] += 1
        if version: versions[version] += 1
        if alpn: alpns[alpn] += 1
        if cipher: ciphers[cipher] += 1
        if handshake: handshakes[handshake] += 1
        if ja3: fingerprints[f"ja3:{ja3}"] += 1
        if ja3s: fingerprints[f"ja3s:{ja3s}"] += 1
        if version.upper().replace("V", "") in ("SSL2", "SSL 2.0", "SSL3", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
            warnings.append({"packet_id": p.get("id"), "type": "legacy_tls", "detail": version})
        expiry_time = _parse_time(expiry)
        not_before_time = _parse_time(not_before)
        if expiry_time and expiry_time < now:
            warnings.append({"packet_id": p.get("id"), "type": "expired_certificate", "detail": expiry})
        elif expiry_time and expiry_time <= now + timedelta(days=30):
            warnings.append({"packet_id": p.get("id"), "type": "certificate_expiring_soon", "detail": expiry})
        if not_before_time and not_before_time > now:
            warnings.append({"packet_id": p.get("id"), "type": "certificate_not_yet_valid", "detail": not_before})
        if subject and issuer and subject.strip().casefold() == issuer.strip().casefold():
            warnings.append({"packet_id": p.get("id"), "type": "self_signed_certificate", "detail": subject})
    return {
        "events": events,
        "top_server_names": [{"server_name": k, "packets": v} for k, v in servers.most_common(25)],
        "versions": [{"version": k, "packets": v} for k, v in versions.most_common()],
        "alpns": [{"alpn": k, "packets": v} for k, v in alpns.most_common()],
        "cipher_suites": [{"cipher": k, "packets": v} for k, v in ciphers.most_common(25)],
        "handshakes": [{"handshake": k, "packets": v} for k, v in handshakes.most_common()],
        "fingerprints": [{"fingerprint": k, "packets": v} for k, v in fingerprints.most_common(50)],
        "warning_counts": dict(Counter(warning["type"] for warning in warnings)),
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
