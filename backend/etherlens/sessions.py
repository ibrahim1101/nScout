"""Save & replay captured sessions in MongoDB.

A "session" is a snapshot of the current capture: packets (as parsed dicts incl.
hex payload) + threats. Reloading a session re-ingests the raw bytes through the
same dissector so analytics, flows, topology, follow-stream and AI explain all
work exactly as they did live.
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from scapy.all import Ether  # type: ignore

from etherlens.engine import CaptureSession


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


async def save_session(db, session: CaptureSession, name: str) -> Dict[str, Any]:
    pkts = list(session.packets)
    if not pkts:
        raise ValueError("No packets to save")
    doc = {
        "_id": str(uuid.uuid4()),
        "name": (name or "Untitled").strip()[:120] or "Untitled",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "packet_count": len(pkts),
        "threat_count": len(session.threats),
        "duration_sec": session.stats().get("duration_sec"),
        "packets": [_packet_doc(p) for p in pkts],
        "threats": list(session.threats),
    }
    await db.etherlens_sessions.insert_one(doc)
    return {"id": doc["_id"], "name": doc["name"], "packet_count": doc["packet_count"]}


async def list_sessions(db) -> List[Dict[str, Any]]:
    cursor = db.etherlens_sessions.find({}, {"packets": 0, "threats": 0}).sort("created_at", -1).limit(100)
    rows = []
    async for doc in cursor:
        rows.append({
            "id": doc["_id"],
            "name": doc.get("name", "Untitled"),
            "created_at": doc.get("created_at"),
            "packet_count": doc.get("packet_count", 0),
            "threat_count": doc.get("threat_count", 0),
            "duration_sec": doc.get("duration_sec"),
        })
    return rows


async def delete_session(db, sid: str) -> bool:
    r = await db.etherlens_sessions.delete_one({"_id": sid})
    return r.deleted_count > 0


async def load_session(db, session: CaptureSession, sid: str) -> Dict[str, Any]:
    doc = await db.etherlens_sessions.find_one({"_id": sid})
    if not doc:
        raise KeyError("not found")

    # Stop any running capture and reset the in-memory session.
    await session.stop()
    session.clear()
    session.mode = "replay"
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
        "id": sid,
        "name": doc.get("name"),
        "packet_count": len(session.packets),
        "threat_count": len(session.threats),
    }
