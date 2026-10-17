"""Atomic local persistence for the active, non-secret detection preset."""
from __future__ import annotations

import json
from pathlib import Path
import threading
from typing import Dict

PRESETS = {"conservative", "balanced", "sensitive"}
DEFAULT_PRESET = "balanced"
MAX_FILE_BYTES = 16 * 1024


def normalize_preset(value: str) -> str:
    preset = str(value or "").strip().lower()
    if preset not in PRESETS:
        raise ValueError("Unknown detection preset")
    return preset


class DetectionSettingsStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    def load(self) -> Dict[str, str | int]:
        with self._lock:
            if not self.path.exists():
                return {"version": 1, "preset": DEFAULT_PRESET}
            if self.path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("Detection settings data is too large")
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError("Detection settings data is unreadable") from exc
            if not isinstance(data, dict) or data.get("version") != 1:
                raise ValueError("Detection settings data is invalid")
            return {"version": 1, "preset": normalize_preset(data.get("preset"))}

    def save(self, preset: str) -> Dict[str, str | int]:
        data = {"version": 1, "preset": normalize_preset(preset)}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(
                json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
            )
            temporary.replace(self.path)
        return data.copy()
