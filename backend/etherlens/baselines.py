"""Persistent network profiles and deterministic, explainable deviation analysis."""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List

from . import intelligence

MAX_BASELINES = 100
MAX_ENTITIES = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
_SAFE_ID = re.compile(r"^[0-9a-f]{32}$")


class BaselineNotFound(KeyError):
    pass


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _bounded(values: Iterable[Any]) -> List[str]:
    return sorted({str(value) for value in values if str(value)})[:MAX_ENTITIES]


def build_profile(packets: List[Dict[str, Any]], threats: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Reduce a capture to bounded metadata; raw packet contents are not persisted."""
    if not packets:
        raise ValueError("Capture contains no packets to baseline")
    summary = intelligence.investigation_summary(packets, threats)
    overview = summary.get("overview") or {}
    timestamps = [_number(packet.get("timestamp")) for packet in packets if packet.get("timestamp") is not None]
    start = min(timestamps) if timestamps else 0.0
    end = max(timestamps) if timestamps else start
    duration = max(0.0, end - start)
    packet_count = int(overview.get("total_packets") or len(packets))
    byte_count = int(overview.get("total_bytes") or 0)
    protocols = {str(row.get("protocol") or "Unknown"): int(row.get("packets") or 0)
                 for row in overview.get("protocols", [])}
    ports = {str(row.get("port")): int(row.get("packets") or 0)
             for row in overview.get("top_ports", []) if row.get("port") is not None}
    domains = {str(row.get("domain")): int(row.get("queries") or 0)
               for row in (summary.get("dns") or {}).get("top_domains", []) if row.get("domain")}
    hosts = _bounded(row.get("ip") for row in summary.get("hosts", []))
    connections = _bounded("|".join(map(str, (row.get("a_ip", ""), row.get("a_port", 0),
                                                    row.get("b_ip", ""), row.get("b_port", 0))))
                           for row in summary.get("connections", []))
    findings = Counter(str(row.get("type") or "unknown")
                       for row in (summary.get("security") or {}).get("findings", []))
    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "start_timestamp": start,
        "end_timestamp": end,
        "duration_seconds": round(duration, 6),
        "packet_rate": round(packet_count / duration, 4) if duration >= 1 else None,
        "byte_rate": round(byte_count / duration, 4) if duration >= 1 else None,
        "protocols": protocols,
        "ports": ports,
        "hosts": hosts,
        "domains": sorted(domains)[:MAX_ENTITIES],
        "domain_counts": dict(sorted(domains.items())[:MAX_ENTITIES]),
        "connections": connections,
        "finding_types": dict(findings),
        "tcp_health": {str(key): int(value or 0) for key, value in (summary.get("tcp_health") or {}).items()},
    }


def _reason(kind: str, title: str, observed: Any, baseline: Any, threshold: str,
            score: int, severity: str, evidence: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {"type": kind, "title": title, "observed": observed, "baseline": baseline,
            "threshold": threshold, "score": score, "severity": severity,
            "evidence": evidence or {}}


def compare_profile(baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """Return transparent heuristic deviations; this is not a compromise verdict."""
    reasons: List[Dict[str, Any]] = []
    for key, label, weight in (("hosts", "host", 4), ("domains", "domain", 3)):
        added = sorted(set(current.get(key) or []) - set(baseline.get(key) or []))[:50]
        if added:
            score = min(20, len(added) * weight)
            reasons.append(_reason(f"new_{label}", f"{len(added)} new {label}{'s' if len(added) != 1 else ''}",
                                   len(added), 0, "Any entity absent from the saved baseline", score,
                                   "medium" if len(added) >= 5 else "low", {"added": added}))
    added_ports = sorted(set(current.get("ports") or {}) - set(baseline.get("ports") or {}), key=lambda value: int(value))[:50]
    if added_ports:
        score = min(15, len(added_ports) * 3)
        reasons.append(_reason("new_service_port", f"{len(added_ports)} new service port{'s' if len(added_ports) != 1 else ''}",
                               len(added_ports), 0, "Any port absent from the saved baseline", score,
                               "medium" if len(added_ports) >= 4 else "low", {"added": added_ports}))

    base_packets = max(1, int(baseline.get("packet_count") or 0))
    current_packets = max(1, int(current.get("packet_count") or 0))
    for protocol in sorted(set(baseline.get("protocols") or {}) | set(current.get("protocols") or {})):
        before = 100 * int((baseline.get("protocols") or {}).get(protocol, 0)) / base_packets
        after = 100 * int((current.get("protocols") or {}).get(protocol, 0)) / current_packets
        shift = after - before
        if abs(shift) >= 15 and int((current.get("protocols") or {}).get(protocol, 0)) >= 5:
            reasons.append(_reason("protocol_share_shift", f"{protocol} share shifted by {shift:+.1f} percentage points",
                                   round(after, 2), round(before, 2), "Absolute share change ≥ 15 percentage points",
                                   min(15, max(5, round(abs(shift) / 3))), "medium" if abs(shift) >= 30 else "low",
                                   {"protocol": protocol, "percentage_point_change": round(shift, 2)}))

    for key, label in (("packet_rate", "Packet rate"), ("byte_rate", "Byte rate")):
        before, after = baseline.get(key), current.get(key)
        if before is None or after is None or _number(before) <= 0:
            continue
        change = (_number(after) - _number(before)) * 100 / _number(before)
        if abs(change) >= 100:
            reasons.append(_reason(f"{key}_deviation", f"{label} changed by {change:+.0f}%", after, before,
                                   "Absolute relative change ≥ 100%; both captures span at least one second",
                                   min(15, max(5, round(abs(change) / 50))), "medium" if abs(change) >= 300 else "low",
                                   {"percent_change": round(change, 2)}))

    for key, label in (("finding_types", "finding type"), ("tcp_health", "TCP-health signal")):
        previous, observed = baseline.get(key) or {}, current.get(key) or {}
        added = [{"name": name, "count": int(count or 0)} for name, count in sorted(observed.items())
                 if int(count or 0) > int(previous.get(name, 0) or 0)]
        if added:
            increase = sum(item["count"] - int(previous.get(item["name"], 0) or 0) for item in added)
            reasons.append(_reason(f"increased_{key}", f"Increased {label}{'s' if len(added) != 1 else ''}",
                                   increase, 0, "Count exceeds the saved baseline", min(20, 5 + increase),
                                   "high" if key == "finding_types" else "medium", {"increases": added[:50]}))

    reasons.sort(key=lambda row: (row["score"], row["severity"], row["type"]), reverse=True)
    score = min(100, sum(int(row["score"]) for row in reasons))
    level = "high" if score >= 60 else "elevated" if score >= 30 else "low" if score else "none"
    return {
        "schema": "nscout.baseline-comparison.v1",
        "score": score,
        "level": level,
        "reasons": reasons,
        "baseline_packet_count": int(baseline.get("packet_count") or 0),
        "current_packet_count": int(current.get("packet_count") or 0),
        "interpretation": "Deviations are heuristic analyst leads from one saved capture, not proof of compromise or a learned normal model.",
    }


class BaselineStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self._lock = threading.RLock()

    def _path(self, baseline_id: str) -> Path:
        if not _SAFE_ID.fullmatch(str(baseline_id)):
            raise ValueError("Invalid baseline identifier")
        return self.directory / f"{baseline_id}.json"

    def _read_path(self, path: Path) -> Dict[str, Any]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("Baseline record is too large")
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise BaselineNotFound(path.stem) from exc
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError("Baseline record is unreadable") from exc
        if not isinstance(record, dict) or record.get("id") != path.stem or not isinstance(record.get("profile"), dict):
            raise ValueError("Baseline record is invalid")
        return record

    def create(self, name: str, profile: Dict[str, Any]) -> Dict[str, Any]:
        name = str(name or "").strip()
        if not name or len(name) > 160:
            raise ValueError("Baseline name must be between 1 and 160 characters")
        with self._lock:
            if len(self.list()) >= MAX_BASELINES:
                raise ValueError(f"At most {MAX_BASELINES} baselines may be stored")
            baseline_id = uuid.uuid4().hex
            record = {"schema": "nscout.network-baseline.v1", "id": baseline_id, "name": name,
                      "created_at": time.time(), "profile": deepcopy(profile)}
            self.directory.mkdir(parents=True, exist_ok=True)
            target = self._path(baseline_id)
            temporary = target.with_suffix(".tmp")
            temporary.write_text(json.dumps(record, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            os.replace(temporary, target)
            return deepcopy(record)

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            if not self.directory.exists():
                return []
            rows = []
            for path in self.directory.glob("*.json"):
                try:
                    record = self._read_path(path)
                except (BaselineNotFound, ValueError):
                    continue
                profile = record["profile"]
                rows.append({"id": record["id"], "name": record["name"], "created_at": record["created_at"],
                             "packet_count": profile.get("packet_count", 0), "duration_seconds": profile.get("duration_seconds", 0),
                             "host_count": len(profile.get("hosts") or []), "domain_count": len(profile.get("domains") or [])})
            return sorted(rows, key=lambda row: row["created_at"], reverse=True)[:MAX_BASELINES]

    def get(self, baseline_id: str) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._read_path(self._path(baseline_id)))

    def delete(self, baseline_id: str) -> None:
        with self._lock:
            try:
                self._path(baseline_id).unlink()
            except FileNotFoundError as exc:
                raise BaselineNotFound(baseline_id) from exc
