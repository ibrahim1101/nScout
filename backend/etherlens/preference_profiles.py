"""Local, non-secret nScout preference profiles."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import threading
import time
import uuid
from typing import Any, Dict, List

MAX_FILE_BYTES = 1024 * 1024
MAX_PROFILES = 50
_SAFE_ID = re.compile(r"^[a-f0-9]{16}$")
_PRESETS = {"conservative", "balanced", "sensitive"}
_SEVERITIES = {"low", "medium", "high", "critical"}


def normalize_preferences(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Profile preferences must be an object")
    packet_limit = value.get("packetLimit", 50000)
    if isinstance(packet_limit, bool) or not isinstance(packet_limit, int):
        raise ValueError("Packet retention limit must be an integer")
    if not 1000 <= packet_limit <= 1000000:
        raise ValueError("Packet retention limit must be between 1,000 and 1,000,000")
    preset = value.get("detectionPreset", "balanced")
    severity = value.get("alertSeverity", "high")
    if preset not in _PRESETS:
        raise ValueError("Unknown detection preset")
    if severity not in _SEVERITIES:
        raise ValueError("Unknown alert severity")
    return {
        "preservePackets": bool(value.get("preservePackets", True)),
        "autoRestore": bool(value.get("autoRestore", True)),
        "redactReports": bool(value.get("redactReports", False)),
        "packetLimit": packet_limit,
        "detectionPreset": preset,
        "alertSeverity": severity,
    }


class PreferenceProfileStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "profiles": []}
        if self.path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("Preference profile data is too large")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Preference profile data is unreadable") from exc
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("profiles"), list):
            raise ValueError("Preference profile data is invalid")
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            profiles = self._load()["profiles"]
            valid = [item for item in profiles if isinstance(item, dict) and _SAFE_ID.fullmatch(str(item.get("id", "")))]
            return deepcopy(sorted(valid, key=lambda item: item.get("updated_at", 0), reverse=True))

    def create(self, name: str, preferences: Dict[str, Any]) -> Dict[str, Any]:
        clean_name = str(name or "").strip()
        if not clean_name or len(clean_name) > 80:
            raise ValueError("Profile name must contain 1 to 80 characters")
        normalized = normalize_preferences(preferences)
        with self._lock:
            data = self._load()
            if len(data["profiles"]) >= MAX_PROFILES:
                raise ValueError(f"At most {MAX_PROFILES} local profiles are supported")
            now = time.time()
            profile = {"id": uuid.uuid4().hex[:16], "name": clean_name, "created_at": now,
                       "updated_at": now, "preferences": normalized}
            data["profiles"].append(profile)
            self._save(data)
            return deepcopy(profile)

    def delete(self, profile_id: str) -> None:
        if not _SAFE_ID.fullmatch(str(profile_id or "")):
            raise KeyError(profile_id)
        with self._lock:
            data = self._load()
            retained = [item for item in data["profiles"] if item.get("id") != profile_id]
            if len(retained) == len(data["profiles"]):
                raise KeyError(profile_id)
            data["profiles"] = retained
            self._save(data)
