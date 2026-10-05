"""Defensive traffic-analysis heuristics for nScout investigations."""
from __future__ import annotations
from collections import Counter, defaultdict
from ipaddress import ip_address
from statistics import median
from typing import Any, Dict, List


def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()):
            return layer.get("fields", {}) or {}
    return {}


def _finding(kind: str, severity: str, title: str, detail: str, packet=None, confidence="medium", evidence=None, **extra):
    p = packet or {}
    return {
        "type": kind, "severity": severity, "confidence": confidence, "state": "new",
        "title": title, "detail": detail, "packet_id": p.get("id"),
        "timestamp": p.get("timestamp"), "src_ip": p.get("src_ip"),
        "dst_ip": p.get("dst_ip"), "evidence": evidence or [], **extra,
    }


def _dns_name(packet: Dict[str, Any]) -> str:
    dns = _layer(packet, "DNS")
    for key in ("Query Name", "Name", "QNAME", "Host", "Domain"):
        if dns.get(key):
            return str(dns[key]).strip().rstrip(".").lower()
    return ""


def security_intelligence(packets: List[Dict[str, Any]], existing_threats=None) -> Dict[str, Any]:
    """Return explainable passive findings. Heuristics are leads, not proof of compromise."""
    findings = []
    existing_threats = existing_threats or []
    ordered = sorted(packets, key=lambda p: float(p.get("timestamp") or 0))

    # ARP identity changes: one IP observed claiming multiple sender MACs.
    arp_claims = defaultdict(dict)
    for p in ordered:
        arp = _layer(p, "ARP")
        ip, mac = str(arp.get("Sender IP") or ""), str(arp.get("Sender MAC") or "").lower()
        if ip and mac:
            arp_claims[ip].setdefault(mac, p)
    for ip, claims in arp_claims.items():
        if len(claims) > 1:
            sample = list(claims.values())[-1]
            findings.append(_finding("arp.identity_change", "high", "ARP identity changed",
                f"{ip} was observed with {len(claims)} different MAC addresses.", sample,
                confidence="high", evidence=[{"ip": ip, "mac_addresses": sorted(claims)}],
                ip=ip, mac_addresses=sorted(claims)))

    # TCP flow health and failed connection attempts.
    flows = defaultdict(lambda: {"syn": None, "synack": False, "reset": None})
    failed_by_source = Counter()
    for p in ordered:
        flags = str(p.get("flags") or "")
        if not flags or not p.get("src_ip") or not p.get("dst_ip"): continue
        key = tuple(sorted(((str(p.get("src_ip")), int(p.get("src_port") or 0)),
                            (str(p.get("dst_ip")), int(p.get("dst_port") or 0)))))
        row = flows[key]
        if "SYN" in flags and "ACK" not in flags and row["syn"] is None: row["syn"] = p
        if "SYN" in flags and "ACK" in flags: row["synack"] = True
        if "RST" in flags: row["reset"] = p
    for row in flows.values():
        if row["syn"] and row["reset"] and not row["synack"]:
            p = row["syn"]
            failed_by_source[str(p.get("src_ip"))] += 1
            findings.append(_finding("tcp.failed_connection", "medium", "Failed TCP connection",
                "A connection attempt was reset before a SYN/ACK was observed.", p,
                evidence=[{"destination": p.get("dst_ip"), "port": p.get("dst_port")}]))
    for src, count in failed_by_source.items():
        if count >= 10:
            sample = next((p for p in reversed(ordered) if str(p.get("src_ip")) == src), None)
            findings.append(_finding("tcp.excessive_failures", "high", "Excessive failed connections",
                f"{src} generated {count} failed TCP connection attempts.", sample,
                confidence="high", evidence=[{"failed_connections": count}], failed_connections=count))

    # SYN/port scan lead: one source probing many destination ports on a host.
    scan_targets = defaultdict(lambda: {"ports": set(), "rows": []})
    for p in ordered:
        flags = str(p.get("flags") or "")
        if "SYN" in flags and "ACK" not in flags and p.get("src_ip") and p.get("dst_ip"):
            key = (str(p["src_ip"]), str(p["dst_ip"]))
            scan_targets[key]["ports"].add(int(p.get("dst_port") or 0))
            scan_targets[key]["rows"].append(p)
    for (src, dst), data in scan_targets.items():
        ports = sorted(p for p in data["ports"] if p)
        if len(ports) >= 12:
            rows = data["rows"]
            span = float(rows[-1].get("timestamp") or 0) - float(rows[0].get("timestamp") or 0)
            if span <= 60:
                findings.append(_finding("network.port_scan", "high", "Possible TCP port scan",
                    f"{src} probed {len(ports)} TCP ports on {dst} within {max(span, 0):.1f}s.", rows[-1],
                    confidence="high", evidence=[{"target": dst, "ports": ports[:50], "window_seconds": round(max(span, 0), 3)}],
                    target=dst, unique_ports=len(ports), window_seconds=round(max(span, 0), 3)))

    # Beaconing lead: repeated destination contacts with unusually regular intervals.
    contacts = defaultdict(list)
    for p in ordered:
        flags = str(p.get("flags") or "")
        if "SYN" in flags and "ACK" not in flags and p.get("src_ip") and p.get("dst_ip"):
            contacts[(str(p["src_ip"]), str(p["dst_ip"]), int(p.get("dst_port") or 0))].append(p)
    for (src, dst, port), rows in contacts.items():
        if len(rows) < 6: continue
        times = [float(p.get("timestamp") or 0) for p in rows]
        gaps = [b-a for a,b in zip(times, times[1:]) if b > a]
        if len(gaps) < 5: continue
        med = median(gaps)
        if med < 2 or med > 3600: continue
        deviation = median(abs(g-med) for g in gaps)
        if deviation <= max(0.25, med * 0.12):
            findings.append(_finding("traffic.beaconing", "medium", "Regular outbound connection pattern",
                f"{len(rows)} connection attempts to {dst}:{port} had a median interval of {med:.1f}s.", rows[-1],
                evidence=[{"destination": dst, "port": port, "median_interval_seconds": round(med, 3), "observations": len(rows)}],
                interval_seconds=round(med, 3), observations=len(rows)))

    # DNS anomaly leads: unusually long labels/names and high query fan-out per source.
    dns_by_source = defaultdict(list)
    for p in ordered:
        name = _dns_name(p)
        if not name: continue
        dns_by_source[str(p.get("src_ip") or "unknown")].append((name, p))
        labels = name.split(".")
        longest = max((len(x) for x in labels), default=0)
        if len(name) >= 120 or longest >= 55:
            findings.append(_finding("dns.long_query", "medium", "Unusually long DNS query",
                f"DNS query for {name[:80]}{'...' if len(name) > 80 else ''} is unusually long.", p,
                evidence=[{"query_length": len(name), "longest_label": longest}],
                query=name, query_length=len(name)))
    for src, rows in dns_by_source.items():
        unique = {name for name, _ in rows}
        if len(rows) >= 50 and len(unique) >= 40:
            sample = rows[-1][1]
            findings.append(_finding("dns.high_fanout", "medium", "High DNS query fan-out",
                f"{src} issued {len(rows)} DNS queries covering {len(unique)} unique names.", sample,
                evidence=[{"queries": len(rows), "unique_names": len(unique)}], queries=len(rows), unique_names=len(unique)))

    # Traffic spikes: compare one-second buckets with the median non-empty bucket.
    buckets = Counter(int(float(p.get("timestamp") or 0)) for p in ordered)
    if len(buckets) >= 5:
        baseline = median(buckets.values())
        threshold = max(50, baseline * 5)
        for second, count in buckets.items():
            if count >= threshold:
                p = next((x for x in ordered if int(float(x.get("timestamp") or 0)) == second), None)
                findings.append(_finding("traffic.spike", "medium", "Traffic spike",
                    f"Observed {count} packets in one second versus a median of {baseline:g}.", p,
                    evidence=[{"packets_per_second": count, "baseline_packets_per_second": baseline}],
                    packets_per_second=count, baseline_packets_per_second=baseline))

    # Large transfer lead, aggregated by directional IP pair.
    pair_bytes = Counter()
    pair_sample = {}
    for p in ordered:
        if p.get("src_ip") and p.get("dst_ip"):
            key = (str(p["src_ip"]), str(p["dst_ip"]))
            pair_bytes[key] += max(0, int(p.get("length") or 0))
            pair_sample[key] = p
    for (src, dst), total in pair_bytes.items():
        if total >= 100 * 1024 * 1024:
            findings.append(_finding("traffic.large_transfer", "medium", "Large directional data transfer",
                f"Observed at least {total / (1024*1024):.1f} MiB from {src} to {dst} in this capture.", pair_sample[(src, dst)],
                evidence=[{"bytes": total}], bytes=total))

    # Suspicious destination is intentionally conservative: only clearly invalid/special ranges.
    for p in ordered:
        dst = str(p.get("dst_ip") or "")
        if not dst: continue
        try: addr = ip_address(dst)
        except ValueError: continue
        if addr.is_unspecified or addr.is_reserved:
            findings.append(_finding("destination.special_range", "low", "Special-use destination",
                f"Traffic targeted special/reserved address {dst}; verify whether this is expected.", p,
                confidence="low", evidence=[{"destination": dst}]))

    counts = Counter(f["type"] for f in findings)
    severities = Counter(f["severity"] for f in findings)
    confidences = Counter(f["confidence"] for f in findings)
    return {
        "findings": findings[:250], "counts": dict(counts), "severities": dict(severities),
        "confidences": dict(confidences), "existing_threat_count": len(existing_threats),
        "note": "Passive heuristics identify investigation leads and are not proof of malicious activity.",
    }
