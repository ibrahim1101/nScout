"""Durable analyst metadata and observation history for Live Hosts."""
from __future__ import annotations

import json
import os
import threading
import time
from copy import deepcopy
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


MAX_HISTORY = 100
MAX_FILE_BYTES = 16 * 1024 * 1024


def _host_id(value: str) -> str:
    try:
        return str(ip_address(str(value).strip()))
    except ValueError as exc:
        raise ValueError("Host must be a valid IP address") from exc


def activity_state(last_seen: Any, now: Optional[float] = None) -> str:
    """Describe passive observation recency without claiming reachability."""
    try:
        age = max(0.0, float(now if now is not None else time.time()) - float(last_seen))
    except (TypeError, ValueError):
        return "inactive"
    if age <= 60:
        return "active"
    if age <= 15 * 60:
        return "recently_seen"
    return "inactive"


class HostProfileStore:
    """Persist aliases, watchlist state and bounded host sightings atomically."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    def _read(self) -> Dict[str, Dict[str, Any]]:
        try:
            if self.path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("Host profile data is too large")
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError("Host profile data is unreadable") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("hosts", {}), dict):
            raise ValueError("Host profile data is invalid")
        return payload.get("hosts", {})

    def _write(self, hosts: Dict[str, Dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"version": 1, "hosts": hosts}, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        os.replace(temporary, self.path)

    @staticmethod
    def _blank(host_id: str) -> Dict[str, Any]:
        return {"ip": host_id, "alias": "", "watchlisted": False, "first_seen": None,
                "last_seen": None, "hostname": "", "mac": "", "is_local": False,
                "activity": []}

    def update(self, host: str, alias: Optional[str] = None,
               watchlisted: Optional[bool] = None) -> Dict[str, Any]:
        host_id = _host_id(host)
        if alias is not None:
            alias = alias.strip()
            if len(alias) > 120:
                raise ValueError("Alias must be 120 characters or fewer")
        with self._lock:
            hosts = self._read()
            record = hosts.setdefault(host_id, self._blank(host_id))
            if alias is not None:
                record["alias"] = alias
            if watchlisted is not None:
                record["watchlisted"] = bool(watchlisted)
            self._write(hosts)
            return deepcopy(record)

    def enrich(self, profiles: Iterable[Dict[str, Any]], now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Merge current evidence and append one sighting per new last-seen value."""
        current_time = float(now if now is not None else time.time())
        with self._lock:
            hosts = self._read()
            changed = False
            result = []
            observed = set()
            for profile in profiles:
                row = deepcopy(profile)
                try:
                    host_id = _host_id(row.get("ip", ""))
                except ValueError:
                    row.update({"alias": "", "watchlisted": False, "activity": [],
                                "activity_state": activity_state(row.get("last_seen"), current_time)})
                    result.append(row)
                    continue
                record = hosts.setdefault(host_id, self._blank(host_id))
                observed.add(host_id)
                first_seen = row.get("first_seen")
                last_seen = row.get("last_seen")
                for field in ("hostname", "mac", "is_local"):
                    if row.get(field) not in (None, "") and record.get(field) != row.get(field):
                        record[field] = row.get(field)
                        changed = True
                if first_seen is not None and (record.get("first_seen") is None or float(first_seen) < float(record["first_seen"])):
                    record["first_seen"] = first_seen
                    changed = True
                if last_seen is not None and (record.get("last_seen") is None or float(last_seen) > float(record["last_seen"])):
                    record["last_seen"] = last_seen
                    activity = list(record.get("activity") or [])
                    activity.append({"first_seen": first_seen, "last_seen": last_seen,
                                     "packets": int(row.get("total_packets") or 0),
                                     "bytes": int(row.get("total_bytes") or 0)})
                    record["activity"] = activity[-MAX_HISTORY:]
                    changed = True
                row.update({"alias": str(record.get("alias") or ""),
                            "watchlisted": bool(record.get("watchlisted")),
                            "activity": deepcopy(record.get("activity") or []),
                            "activity_state": activity_state(row.get("last_seen"), current_time)})
                result.append(row)
            for host_id, record in hosts.items():
                if host_id in observed:
                    continue
                result.append({"ip": host_id, "alias": str(record.get("alias") or ""),
                               "watchlisted": bool(record.get("watchlisted")),
                               "hostname": str(record.get("hostname") or ""),
                               "mac": str(record.get("mac") or ""),
                               "is_local": bool(record.get("is_local")),
                               "first_seen": record.get("first_seen"), "last_seen": record.get("last_seen"),
                               "activity": deepcopy(record.get("activity") or []),
                               "activity_state": activity_state(record.get("last_seen"), current_time),
                               "total_packets": 0, "total_bytes": 0, "packets_sent": 0,
                               "packets_received": 0, "bytes_sent": 0, "bytes_received": 0,
                               "protocols": [], "services": [], "domains": [], "connections": [],
                               "findings": [], "finding_count": 0,
                               "risk": {"score": 0, "level": "none"}})
            if changed:
                self._write(hosts)
        state_rank = {"active": 2, "recently_seen": 1, "inactive": 0}
        return sorted(result, key=lambda item: (bool(item.get("watchlisted")),
                                                state_rank.get(item.get("activity_state"), 0),
                                                item.get("risk", {}).get("score", 0),
                                                item.get("last_seen") or 0), reverse=True)
