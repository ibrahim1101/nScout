import asyncio
import json
from types import SimpleNamespace

import pytest
from scapy.all import Ether, IP, TCP

from etherlens.engine import CaptureSession
from etherlens.sessions import (
    CaptureSessionNotFound,
    LocalCaptureSessionStore,
    restore_capture_session,
)


def fake_session(packet_count=3):
    packets = []
    for index in range(packet_count):
        raw = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + index, dport=443))
        packets.append({"number": index + 1, "timestamp": 1000 + index, "hex": raw.hex(), "protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1000 + index, "dst_port": 443, "length": len(raw), "info": "test"})
    return SimpleNamespace(
        packets=packets,
        threats=[{"id": "threat-1", "severity": "high"}],
        capture_id="capture-1",
        interface="Ethernet",
        mode="live",
        packet_limit=50_000,
        dropped_packets=2,
        interface_history=[{"interface": "Ethernet"}],
        stats=lambda: {"duration_sec": 12.5},
    )


def test_local_capture_session_round_trip_and_delete(tmp_path):
    store = LocalCaptureSessionStore(tmp_path)
    saved = store.save(fake_session(), "Incident capture")

    assert saved["storage"] == "local"
    assert saved["packet_count"] == 3
    assert store.list()[0]["source_capture_id"] == "capture-1"
    assert store.get(saved["id"])["name"] == "Incident capture"
    assert store.delete(saved["id"]) is True
    assert store.list() == []


def test_local_capture_session_keeps_newest_packets_and_marks_truncated(tmp_path):
    store = LocalCaptureSessionStore(tmp_path, max_packets=2)
    saved = store.save(fake_session(4), "Bounded")
    doc = store.get(saved["id"])

    assert saved["truncated"] is True
    assert saved["source_packet_count"] == 4
    assert [packet["number"] for packet in doc["packets"]] == [3, 4]


def test_local_capture_session_rejects_unsafe_id(tmp_path):
    store = LocalCaptureSessionStore(tmp_path)
    with pytest.raises(CaptureSessionNotFound):
        store.get("../../outside")


def test_local_capture_session_listing_isolates_corrupt_record(tmp_path):
    store = LocalCaptureSessionStore(tmp_path)
    saved = store.save(fake_session(), "Valid")
    (tmp_path / "broken.json").write_text("{not-json", encoding="utf-8")

    assert [row["id"] for row in store.list()] == [saved["id"]]


def test_local_capture_session_rejects_mismatched_document_id(tmp_path):
    store = LocalCaptureSessionStore(tmp_path)
    saved = store.save(fake_session(), "Mismatch")
    path = tmp_path / f"{saved['id']}.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["_id"] = "00000000-0000-0000-0000-000000000000"
    path.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid"):
        store.get(saved["id"])


def test_restore_capture_session_rebuilds_engine_state(tmp_path):
    store = LocalCaptureSessionStore(tmp_path)
    saved = store.save(fake_session(2), "Replay me")
    target = CaptureSession()

    meta = asyncio.run(restore_capture_session(target, store.get(saved["id"])))

    assert meta["packet_count"] == 2
    assert meta["threat_count"] == 1
    assert target.mode == "replay"
    assert target.interface == "session:Replay me"
