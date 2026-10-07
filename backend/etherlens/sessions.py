"""Save and replay capture snapshots using local or legacy MongoDB storage.

A "session" is a snapshot of the current capture: packets (as parsed dicts incl.
hex payload) + threats. Reloading a session re-ingests the raw bytes through the
same dissector so analytics, flows, topology, follow-stream and AI explain all
work exactly as they did live.
"""
from __future__ import annotations

import time
import uuid
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from scapy.all import Ether  # type: ignore

from etherlens.engine import CaptureSession

MAX_SAVED_PACKETS = 100_000
MAX_SESSION_FILE_BYTES = 256 * 1024 * 1024


class CaptureSessionNotFound(KeyError):
    pass


def _packet_doc(p: Dict[str, Any]) -> Dict[str, Any]:
    # Keep only the fields needed to replay / display. Hex is the source of truth.
    return {
        "number": p.get("number"),
        "timestamp": p.get("timestamp"),
        "hex": p.get("hex"),
        "protocol": p.get("protocol"),
        "src_ip": p.get("src_ip"),
        "dst_ip": p.get("dst_ip"),
        "src_port": p.get("src_port"),
        "dst_port": p.get("dst_port"),
        "length": p.get("length"),
        "info": p.get("info"),
    }


def capture_session_document(
    session: CaptureSession,
    name: str,
    max_packets: int = MAX_SAVED_PACKETS,
) -> Dict[str, Any]:
    pkts = list(session.packets)
    if not pkts:
        raise ValueError("No packets to save")
    source_packet_count = len(pkts)
    pkts = pkts[-max_packets:]
    return {
        "_id": str(uuid.uuid4()),
        "schema_version": 1,
        "name": (name or "Untitled").strip()[:120] or "Untitled",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "packet_count": len(pkts),
        "source_packet_count": source_packet_count,
        "truncated": source_packet_count > len(pkts),
        "threat_count": len(session.threats),
        "duration_sec": session.stats().get("duration_sec"),
        "source_capture_id": session.capture_id,
        "source_interface": session.interface,
        "source_mode": session.mode,
        "packet_limit": session.packet_limit,
        "evicted_packets": session.dropped_packets,
        "interface_history": list(session.interface_history),
        "packets": [_packet_doc(p) for p in pkts],
        "threats": list(session.threats),
    }


def session_summary(doc: Dict[str, Any], storage: str) -> Dict[str, Any]:
    return {
        "id": doc["_id"],
        "name": doc.get("name", "Untitled"),
        "created_at": doc.get("created_at"),
        "packet_count": doc.get("packet_count", 0),
        "source_packet_count": doc.get("source_packet_count", doc.get("packet_count", 0)),
        "truncated": bool(doc.get("truncated", False)),
        "threat_count": doc.get("threat_count", 0),
        "duration_sec": doc.get("duration_sec"),
        "source_capture_id": doc.get("source_capture_id"),
        "source_interface": doc.get("source_interface"),
        "source_mode": doc.get("source_mode"),
        "evicted_packets": doc.get("evicted_packets", 0),
        "storage": storage,
    }


class LocalCaptureSessionStore:
    """Atomic, bounded capture snapshots for self-contained installations."""

    def __init__(self, root: Path, max_packets: int = MAX_SAVED_PACKETS):
        self.root = Path(root)
        self.max_packets = max(1, min(int(max_packets), MAX_SAVED_PACKETS))
        self._lock = threading.RLock()

    @staticmethod
    def _validated_id(session_id: str) -> str:
        try:
            return str(uuid.UUID(str(session_id)))
        except (ValueError, TypeError, AttributeError) as exc:
            raise CaptureSessionNotFound(session_id) from exc

    def _path(self, session_id: str) -> Path:
        return self.root / f"{self._validated_id(session_id)}.json"

    def save(self, session: CaptureSession, name: str) -> Dict[str, Any]:
        doc = capture_session_document(session, name, self.max_packets)
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(doc["_id"])
        temporary = path.with_suffix(f".{uuid.uuid4().hex}.tmp")
        payload = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
        if len(payload.encode("utf-8")) > MAX_SESSION_FILE_BYTES:
            raise ValueError("Capture session is too large to save locally")
        with self._lock:
            try:
                temporary.write_text(payload, encoding="utf-8")
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        return session_summary(doc, "local")

    def get(self, session_id: str) -> Dict[str, Any]:
        path = self._path(session_id)
        with self._lock:
            try:
                if path.stat().st_size > MAX_SESSION_FILE_BYTES:
                    raise ValueError("Capture session is too large to load")
                doc = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError as exc:
                raise CaptureSessionNotFound(session_id) from exc
            except (OSError, ValueError, TypeError) as exc:
                raise ValueError("Capture session data is unreadable") from exc
        if doc.get("_id") != self._validated_id(session_id) or not isinstance(doc.get("packets"), list):
            raise ValueError("Capture session data is invalid")
        return doc

    def delete(self, session_id: str) -> bool:
        path = self._path(session_id)
        with self._lock:
            try:
                path.unlink()
            except FileNotFoundError:
                return False
        return True

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            if not self.root.exists():
                return []
            rows = []
            for path in self.root.glob("*.json"):
                try:
                    if path.stat().st_size > MAX_SESSION_FILE_BYTES:
                        continue
                    doc = json.loads(path.read_text(encoding="utf-8"))
                    self._validated_id(doc.get("_id"))
                    rows.append(session_summary(doc, "local"))
                except (OSError, ValueError, TypeError, KeyError, CaptureSessionNotFound):
                    continue
        return sorted(rows, key=lambda row: row.get("created_at") or "", reverse=True)[:100]


async def save_session(db, session: CaptureSession, name: str) -> Dict[str, Any]:
    """Legacy MongoDB save retained for compatibility and migration access."""
    doc = capture_session_document(session, name)
    await db.etherlens_sessions.insert_one(doc)
    return session_summary(doc, "mongo")


async def list_sessions(db) -> List[Dict[str, Any]]:
    cursor = db.etherlens_sessions.find({}, {"packets": 0, "threats": 0}).sort("created_at", -1).limit(100)
    rows = []
    async for doc in cursor:
        rows.append(session_summary(doc, "mongo"))
    return rows


async def delete_session(db, sid: str) -> bool:
    r = await db.etherlens_sessions.delete_one({"_id": sid})
    return r.deleted_count > 0


async def restore_capture_session(session: CaptureSession, doc: Dict[str, Any]) -> Dict[str, Any]:
    # Stop any running capture and reset the in-memory session.
    await session.stop()
    session.clear()
    session.mode = "replay"
    session.requested_mode = "replay"
    session.interface = f"session:{doc.get('name','?')}"
    session.start_ts = time.time()

    # Re-ingest each saved packet through the dissector so all state is rebuilt.
    for p in doc.get("packets", []):
        try:
            raw = bytes.fromhex(p.get("hex") or "")
            if not raw:
                continue
            pkt = Ether(raw)
            session.ingest(pkt, ts=p.get("timestamp") or time.time())
        except Exception:
            continue

    # Restore saved threats verbatim (they already carry packet_ids referencing new ids;
    # we rebuild a looser mapping by regenerating ids on ingest, so just append them
    # and let the UI show them under "AI Threats" tab).
    for t in doc.get("threats", []):
        session.threats.append(t)

    return {
        "id": doc.get("_id"),
        "name": doc.get("name"),
        "packet_count": len(session.packets),
        "threat_count": len(session.threats),
    }


async def load_session(db, session: CaptureSession, sid: str) -> Dict[str, Any]:
    """Load a legacy MongoDB snapshot."""
    doc = await db.etherlens_sessions.find_one({"_id": sid})
    if not doc:
        raise KeyError("not found")
    return await restore_capture_session(session, doc)
