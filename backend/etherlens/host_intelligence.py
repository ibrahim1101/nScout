"""Host-centric network investigation profiles for nScout."""
from __future__ import annotations

from collections import Counter, defaultdict
from ipaddress import ip_address
from typing import Any, Dict, Iterable, List


SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 12, "low": 4}
CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.8, "low": 0.5}


def _layer(packet: Dict[str, Any], *prefixes: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        name = str(layer.get("name", "")).lower()
        if any(name.startswith(prefix.lower()) for prefix in prefixes):
            return layer.get("fields", {}) or {}
    return {}


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _is_local(ip: str) -> bool:
    try:
        address = ip_address(ip)
        return bool(address.is_private or address.is_loopback or address.is_link_local)
    except ValueError:
        return False


def _dns_correlations(packets: Iterable[Dict[str, Any]]):
    """Return domains queried by hosts and DNS-answer IP-to-name candidates."""
    domains_by_host = defaultdict(Counter)
    names_by_ip = defaultdict(Counter)
    for packet in packets:
        dns = _layer(packet, "Domain Name System", "DNS")
        if not dns:
            continue
        query = str(dns.get("Query") or dns.get("Query Name") or dns.get("QNAME") or "").rstrip(".").lower()
        src = str(packet.get("src_ip") or "")
        info = str(packet.get("info") or "").lower()
        is_response = bool(dns.get("Response")) or "response" in info
        if query and src and not is_response:
            domains_by_host[src][query] += 1
        if query:
            for answer in dns.get("Answers") or []:
                value = answer.get("value") if isinstance(answer, dict) else answer
                value = str(value or "").strip()
                try:
                    ip_address(value)
                except ValueError:
                    continue
                names_by_ip[value][query] += 1
    return domains_by_host, names_by_ip


def _risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    points = 0
    for finding in findings:
        severity = str(finding.get("severity") or "low").lower()
        confidence = str(finding.get("confidence") or "medium").lower()
        points += round(SEVERITY_POINTS.get(severity, 4) * CONFIDENCE_MULTIPLIER.get(confidence, 0.8))
    score = min(100, points)
    level = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low" if score else "none"
    return {"score": score, "level": level}


def host_intelligence(
    packets: List[Dict[str, Any]], findings: List[Dict[str, Any]] | None = None,
    connection_limit_per_host: int = 25,
) -> List[Dict[str, Any]]:
    """Build investigation-ready host profiles from passive capture evidence."""
    findings = findings or []
    domains_by_host, names_by_ip = _dns_correlations(packets)
    profiles: Dict[str, Dict[str, Any]] = {}
    peers = defaultdict(lambda: defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set(), "protocols": set(), "first_seen": None, "last_seen": None}))

    for packet in packets:
        timestamp = float(packet.get("timestamp") or 0)
        length = _as_int(packet.get("length"))
        protocol = str(packet.get("protocol") or "Unknown")
        eth = _layer(packet, "Ethernet II", "Ethernet")
        endpoints = (
            (str(packet.get("src_ip") or ""), str(eth.get("Source") or ""), "sent", packet.get("dst_ip"), packet.get("src_port"), packet.get("dst_port")),
            (str(packet.get("dst_ip") or ""), str(eth.get("Destination") or ""), "received", packet.get("src_ip"), packet.get("dst_port"), packet.get("src_port")),
        )
        for host_ip, mac, direction, peer_ip, endpoint_port, peer_port in endpoints:
            if not host_ip:
                continue
            row = profiles.setdefault(host_ip, {
                "ip": host_ip, "mac": mac, "hostname": "", "is_local": _is_local(host_ip),
                "first_seen": timestamp, "last_seen": timestamp, "packets_sent": 0,
                "packets_received": 0, "bytes_sent": 0, "bytes_received": 0,
                "protocols": set(), "services": set(),
            })
            if mac and not row["mac"]:
                row["mac"] = mac
            row["first_seen"] = min(row["first_seen"], timestamp)
            row["last_seen"] = max(row["last_seen"], timestamp)
            row["protocols"].add(protocol)
            row[f"packets_{direction}"] += 1
            row[f"bytes_{direction}"] += length
            if direction == "received" and endpoint_port:
                row["services"].add((int(endpoint_port), protocol))
            if peer_ip:
                peer = peers[host_ip][str(peer_ip)]
                peer["packets"] += 1
                peer["bytes"] += length
                peer["protocols"].add(protocol)
                if peer_port:
                    peer["ports"].add(int(peer_port))
                peer["first_seen"] = timestamp if peer["first_seen"] is None else min(peer["first_seen"], timestamp)
                peer["last_seen"] = timestamp if peer["last_seen"] is None else max(peer["last_seen"], timestamp)

        http = _layer(packet, "Hypertext Transfer Protocol", "HTTP")
        http_host = str(http.get("Host") or "").strip().lower()
        if http_host and packet.get("src_ip"):
            domains_by_host[str(packet["src_ip"])][http_host] += 1
        tls = _layer(packet, "Transport Layer Security", "TLS")
        sni = str(tls.get("SNI") or tls.get("Server Name") or "").strip().lower()
        if sni and packet.get("src_ip"):
            domains_by_host[str(packet["src_ip"])][sni] += 1

    findings_by_host = defaultdict(list)
    for finding in findings:
        involved = {str(finding.get("src_ip") or ""), str(finding.get("dst_ip") or ""), str(finding.get("ip") or ""), str(finding.get("target") or "")}
        for host_ip in involved - {""}:
            findings_by_host[host_ip].append(finding)

    result = []
    for host_ip, row in profiles.items():
        row["hostname"] = names_by_ip[host_ip].most_common(1)[0][0] if names_by_ip[host_ip] else ""
        row["protocols"] = sorted(row["protocols"])
        row["services"] = [{"port": port, "protocol": protocol} for port, protocol in sorted(row["services"])]
        row["domains"] = [{"domain": name, "observations": count} for name, count in domains_by_host[host_ip].most_common(25)]
        host_peers = []
        for peer_ip, data in peers[host_ip].items():
            host_peers.append({"peer_ip": peer_ip, "packets": data["packets"], "bytes": data["bytes"],
                               "ports": sorted(data["ports"]), "protocols": sorted(data["protocols"]),
                               "first_seen": data["first_seen"], "last_seen": data["last_seen"]})
        row["connections"] = sorted(host_peers, key=lambda item: (item["bytes"], item["packets"]), reverse=True)[:connection_limit_per_host]
        row["findings"] = findings_by_host[host_ip][:50]
        row["finding_count"] = len(findings_by_host[host_ip])
        row["risk"] = _risk(findings_by_host[host_ip])
        row["total_packets"] = row["packets_sent"] + row["packets_received"]
        row["total_bytes"] = row["bytes_sent"] + row["bytes_received"]
        result.append(row)
    return sorted(result, key=lambda item: (item["risk"]["score"], item["total_bytes"]), reverse=True)
