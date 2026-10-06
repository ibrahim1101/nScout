"""Chronological, filterable investigation events for nScout."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _layer(packet: Dict[str, Any], *prefixes: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        name = str(layer.get("name", "")).lower()
        if any(name.startswith(prefix.lower()) for prefix in prefixes):
            return layer.get("fields", {}) or {}
    return {}


def _endpoint(ip: Any, port: Any) -> str:
    ip = str(ip or "")
    try:
        port = int(port or 0)
    except (TypeError, ValueError):
        port = 0
    return f"{ip}:{port}" if port else ip


def _connection_id(packet: Dict[str, Any]) -> str:
    endpoints = sorted((_endpoint(packet.get("src_ip"), packet.get("src_port")),
                        _endpoint(packet.get("dst_ip"), packet.get("dst_port"))))
    return " ↔ ".join(value for value in endpoints if value)


def _event(packet: Dict[str, Any], event_type: str, category: str, title: str,
           detail: str = "", domain: str = "", severity: str = "info", **extra) -> Dict[str, Any]:
    return {
        "timestamp": float(packet.get("timestamp") or 0), "packet_id": packet.get("id"),
        "event_type": event_type, "category": category, "title": title, "detail": detail,
        "src_ip": packet.get("src_ip"), "src_port": packet.get("src_port"),
        "dst_ip": packet.get("dst_ip"), "dst_port": packet.get("dst_port"),
        "protocol": str(packet.get("protocol") or "Unknown"), "domain": domain,
        "connection_id": _connection_id(packet), "severity": severity, **extra,
    }


def _packet_events(packets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    domains_by_ip = defaultdict(Counter)
    for packet in sorted(packets, key=lambda row: (float(row.get("timestamp") or 0), int(row.get("number") or 0))):
        dns = _layer(packet, "Domain Name System", "DNS")
        query = str(dns.get("Query") or dns.get("Query Name") or dns.get("QNAME") or "").rstrip(".").lower()
        info = str(packet.get("info") or "")
        is_dns_response = bool(dns.get("Response")) or "response" in info.lower()
        if dns and query:
            answers = dns.get("Answers") or []
            answer_values = []
            for answer in answers:
                value = answer.get("value") if isinstance(answer, dict) else answer
                value = str(value or "")
                if value:
                    answer_values.append(value)
                    domains_by_ip[value][query] += 1
            events.append(_event(
                packet, "dns.response" if is_dns_response else "dns.query", "dns",
                f"DNS {'response' if is_dns_response else 'query'}: {query}",
                ", ".join(answer_values) if answer_values else "Name resolution request",
                domain=query, response_code=dns.get("Response Code"), answers=answer_values,
            ))

        inferred_domain = ""
        destination = str(packet.get("dst_ip") or "")
        source = str(packet.get("src_ip") or "")
        if domains_by_ip[destination]:
            inferred_domain = domains_by_ip[destination].most_common(1)[0][0]
        elif domains_by_ip[source]:
            inferred_domain = domains_by_ip[source].most_common(1)[0][0]

        flags = str(packet.get("flags") or "")
        if "SYN" in flags and "ACK" not in flags:
            events.append(_event(packet, "connection.start", "connection", "TCP connection started",
                                 f"{_endpoint(packet.get('src_ip'), packet.get('src_port'))} → {_endpoint(packet.get('dst_ip'), packet.get('dst_port'))}",
                                 domain=inferred_domain))
        if "RST" in flags:
            events.append(_event(packet, "connection.reset", "connection", "TCP connection reset",
                                 "A reset terminated or rejected the connection.", domain=inferred_domain, severity="low"))
        elif "FIN" in flags:
            events.append(_event(packet, "connection.close", "connection", "TCP connection closed",
                                 "A graceful TCP close was observed.", domain=inferred_domain))

        tls = _layer(packet, "Transport Layer Security", "TLS")
        if tls:
            sni = str(tls.get("SNI") or tls.get("Server Name") or inferred_domain)
            handshake = str(tls.get("Handshake") or tls.get("Handshake Type") or "TLS record")
            version = str(tls.get("Version") or tls.get("TLS Version") or "")
            events.append(_event(packet, "tls.handshake", "tls", f"TLS: {handshake}",
                                 " · ".join(value for value in (version, sni) if value), domain=sni,
                                 tls_version=version, handshake=handshake))

        http = _layer(packet, "Hypertext Transfer Protocol", "HTTP")
        if http:
            host = str(http.get("Host") or inferred_domain)
            method = str(http.get("Method") or "")
            status = str(http.get("Status") or http.get("Status Code") or "")
            path = str(http.get("Path") or "")
            title = f"HTTP {method} {host}{path}".strip() if method else f"HTTP response {status}".strip()
            events.append(_event(packet, "http.request" if method else "http.response", "http", title,
                                 f"Status {status}" if status else "Visible HTTP metadata", domain=host,
                                 method=method, status=status, path=path))
    return events


def investigation_timeline(
    packets: List[Dict[str, Any]], findings: Optional[List[Dict[str, Any]]] = None,
    host: str = "", domain: str = "", connection: str = "", protocol: str = "",
    min_severity: str = "info", start: Optional[float] = None, end: Optional[float] = None,
    limit: int = 1000,
) -> Dict[str, Any]:
    """Create a correlated event stream and apply investigation filters."""
    events = _packet_events(packets)
    packet_by_id = {str(packet.get("id")): packet for packet in packets}
    for finding in findings or []:
        sample = packet_by_id.get(str(finding.get("packet_id"))) or {
            "id": finding.get("packet_id"), "timestamp": finding.get("timestamp"),
            "src_ip": finding.get("src_ip"), "dst_ip": finding.get("dst_ip"),
            "protocol": finding.get("protocol") or "Security",
        }
        events.append(_event(
            sample, "security.finding", "security", str(finding.get("title") or finding.get("type") or "Security finding"),
            str(finding.get("detail") or finding.get("description") or "Review supporting evidence."),
            domain=str(finding.get("domain") or finding.get("query") or ""),
            severity=str(finding.get("severity") or "medium").lower(), finding_type=finding.get("type"),
            confidence=finding.get("confidence"), state=finding.get("state", "new"), evidence=finding.get("evidence", []),
        ))

    host = host.strip().lower(); domain = domain.strip().lower(); connection = connection.strip().lower(); protocol = protocol.strip().lower()
    minimum = SEVERITY_RANK.get(min_severity.lower(), 0)
    filtered = []
    for event in events:
        if host and host not in (str(event.get("src_ip") or "").lower(), str(event.get("dst_ip") or "").lower()):
            continue
        if domain and domain not in str(event.get("domain") or "").lower():
            continue
        if connection and connection not in str(event.get("connection_id") or "").lower():
            continue
        if protocol and protocol not in (str(event.get("protocol") or "").lower(), str(event.get("category") or "").lower()):
            continue
        if SEVERITY_RANK.get(str(event.get("severity") or "info").lower(), 0) < minimum:
            continue
        if start is not None and event["timestamp"] < start:
            continue
        if end is not None and event["timestamp"] > end:
            continue
        filtered.append(event)
    filtered.sort(key=lambda row: (row["timestamp"], row.get("packet_id") or ""))
    filtered = filtered[:max(1, min(int(limit), 5000))]
    return {
        "events": filtered,
        "counts": dict(Counter(event["category"] for event in filtered)),
        "severities": dict(Counter(event["severity"] for event in filtered)),
        "total": len(filtered),
    }
