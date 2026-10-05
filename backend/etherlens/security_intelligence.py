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


def _finding(kind: str, severity: str, title: str, detail: str, packet=None, **extra):
    p = packet or {}
    return {
        "type": kind, "severity": severity, "title": title, "detail": detail,
        "packet_id": p.get("id"), "timestamp": p.get("timestamp"),
        "src_ip": p.get("src_ip"), "dst_ip": p.get("dst_ip"), **extra,
    }


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
                ip=ip, mac_addresses=sorted(claims)))

    # Failed TCP connections: SYN attempts followed by reset, with no SYN/ACK observed.
    flows = defaultdict(lambda: {"syn": None, "synack": False, "reset": None})
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
            findings.append(_finding("tcp.failed_connection", "medium", "Failed TCP connection",
                "A connection attempt was reset before a SYN/ACK was observed.", p))

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
                interval_seconds=round(med, 3), observations=len(rows)))

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
                    packets_per_second=count, baseline_packets_per_second=baseline))

    # Suspicious destination is intentionally conservative: only clearly invalid/special ranges.
    for p in ordered:
        dst = str(p.get("dst_ip") or "")
        if not dst: continue
        try: addr = ip_address(dst)
        except ValueError: continue
        if addr.is_unspecified or addr.is_reserved:
            findings.append(_finding("destination.special_range", "low", "Special-use destination",
                f"Traffic targeted special/reserved address {dst}; verify whether this is expected.", p))

    counts = Counter(f["type"] for f in findings)
    severities = Counter(f["severity"] for f in findings)
    return {
        "findings": findings[:250],
        "counts": dict(counts), "severities": dict(severities),
        "existing_threat_count": len(existing_threats),
        "note": "Passive heuristics identify investigation leads and are not proof of malicious activity.",
    }
