"""Bounded, side-effect-free PCAP comparison for investigation workflows."""
from __future__ import annotations

import hashlib
import io
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scapy.all import PcapReader  # type: ignore

from . import intelligence
from .engine import CaptureSession

MAX_PCAP_BYTES = 50 * 1024 * 1024
MAX_COMPARISON_PACKETS = 100_000


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _delta(before: Any, after: Any) -> Dict[str, Any]:
    left, right = _number(before), _number(after)
    change = right - left
    percent = None if left == 0 else round(change * 100 / left, 2)
    return {"baseline": before or 0, "current": after or 0, "delta": change, "percent_change": percent}


def _set_delta(before: Iterable[Any], after: Iterable[Any]) -> Dict[str, List[str]]:
    left = {str(item) for item in before if str(item)}
    right = {str(item) for item in after if str(item)}
    return {"added": sorted(right - left), "removed": sorted(left - right), "shared": sorted(left & right)}


def _counter_delta(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for key in sorted(set(before) | set(after)):
        row = {"name": key, **_delta(before.get(key, 0), after.get(key, 0))}
        if row["delta"] or row["baseline"] or row["current"]:
            rows.append(row)
    return sorted(rows, key=lambda item: (abs(item["delta"]), item["current"]), reverse=True)


def _summary_profile(summary: Dict[str, Any]) -> Dict[str, Any]:
    overview = summary.get("overview") or {}
    protocols = {str(row.get("protocol")): int(row.get("packets") or 0) for row in overview.get("protocols", [])}
    domains = {str(row.get("domain")): int(row.get("queries") or 0) for row in (summary.get("dns") or {}).get("top_domains", []) if row.get("domain")}
    ports = {str(row.get("port")): int(row.get("packets") or 0) for row in overview.get("top_ports", [])}
    hosts = {str(row.get("ip")) for row in summary.get("hosts", []) if row.get("ip")}
    findings = Counter(str(row.get("type") or "unknown") for row in (summary.get("security") or {}).get("findings", []))
    severities = Counter(str(row.get("severity") or "unknown") for row in (summary.get("security") or {}).get("findings", []))
    connections = {
        "|".join(map(str, (row.get("a_ip", ""), row.get("a_port", 0), row.get("b_ip", ""), row.get("b_port", 0))))
        for row in summary.get("connections", [])
    }
    return {
        "packets": int(overview.get("total_packets") or 0),
        "bytes": int(overview.get("total_bytes") or 0),
        "protocols": protocols,
        "domains": domains,
        "ports": ports,
        "hosts": hosts,
        "connections": connections,
        "findings": dict(findings),
        "severities": dict(severities),
        "tcp_health": dict(summary.get("tcp_health") or {}),
    }


def compare_summaries(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two investigation summaries without inferring malicious intent."""
    left, right = _summary_profile(baseline), _summary_profile(current)
    return {
        "metrics": {
            "packets": _delta(left["packets"], right["packets"]),
            "bytes": _delta(left["bytes"], right["bytes"]),
            "hosts": _delta(len(left["hosts"]), len(right["hosts"])),
            "connections": _delta(len(left["connections"]), len(right["connections"])),
            "domains": _delta(len(left["domains"]), len(right["domains"])),
            "findings": _delta(sum(left["findings"].values()), sum(right["findings"].values())),
        },
        "protocols": _counter_delta(left["protocols"], right["protocols"]),
        "ports": _counter_delta(left["ports"], right["ports"]),
        "finding_types": _counter_delta(left["findings"], right["findings"]),
        "finding_severities": _counter_delta(left["severities"], right["severities"]),
        "tcp_health": _counter_delta(left["tcp_health"], right["tcp_health"]),
        "hosts": _set_delta(left["hosts"], right["hosts"]),
        "domains": _set_delta(left["domains"], right["domains"]),
        "connections": _set_delta(left["connections"], right["connections"]),
        "interpretation": "Differences are observations for analyst review, not proof of compromise.",
    }


def summarize_pcap(data: bytes, filename: str, packet_limit: int = MAX_COMPARISON_PACKETS) -> Dict[str, Any]:
    if not data:
        raise ValueError("PCAP is empty")
    if len(data) > MAX_PCAP_BYTES:
        raise ValueError("PCAP exceeds the 50 MB comparison limit")
    if packet_limit < 1 or packet_limit > MAX_COMPARISON_PACKETS:
        raise ValueError(f"packet_limit must be between 1 and {MAX_COMPARISON_PACKETS}")
    capture = CaptureSession()
    capture.configure_packet_limit(max(CaptureSession.MIN_PACKET_LIMIT, packet_limit))
    truncated = False
    try:
        with PcapReader(io.BytesIO(data)) as reader:
            for index, packet in enumerate(reader):
                if index >= packet_limit:
                    truncated = True
                    break
                timestamp = float(packet.time) if getattr(packet, "time", None) is not None else None
                capture.ingest(packet, timestamp)
    except Exception as exc:
        raise ValueError(f"Invalid or unsupported PCAP: {exc}") from exc
    packets = list(capture.packets)
    if not packets:
        raise ValueError("PCAP contains no readable packets")
    summary = intelligence.investigation_summary(packets, capture.list_threats())
    start, end = packets[0].get("timestamp"), packets[-1].get("timestamp")
    return {
        "file": {
            "name": (Path(filename).name or "capture.pcap")[:255],
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "packets_analyzed": len(packets),
            "packet_limit": packet_limit,
            "truncated": truncated,
            "start_timestamp": start,
            "end_timestamp": end,
            "duration_seconds": round(max(0.0, _number(end) - _number(start)), 6),
        },
        "summary": summary,
    }


def compare_pcap_bytes(baseline: bytes, current: bytes, baseline_name: str, current_name: str) -> Dict[str, Any]:
    left = summarize_pcap(baseline, baseline_name)
    right = summarize_pcap(current, current_name)
    comparison = compare_summaries(left["summary"], right["summary"])
    comparison["metrics"]["duration_seconds"] = _delta(left["file"]["duration_seconds"], right["file"]["duration_seconds"])
    return {
        "schema": "nscout.pcap-comparison.v1",
        "baseline": left["file"],
        "current": right["file"],
        "comparison": comparison,
    }
