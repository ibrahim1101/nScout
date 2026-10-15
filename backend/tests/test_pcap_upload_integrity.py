"""Regression tests for safe PCAP replacement."""
import asyncio
import io

import pytest
from fastapi import HTTPException, UploadFile
from scapy.all import Ether, IP, TCP, wrpcap

import server
from etherlens.engine import CaptureSession


def _upload(data):
    return UploadFile(file=io.BytesIO(data), filename="sample.pcap")


def test_invalid_upload_preserves_existing_capture(monkeypatch):
    active = CaptureSession()
    original = active.ingest(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(), ts=100.0)
    capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)

    def fail_after_partial_ingest(self, data):
        self.ingest(Ether()/IP()/TCP(), ts=101.0)
        raise ValueError("malformed packet")

    monkeypatch.setattr(CaptureSession, "ingest_pcap_bytes", fail_after_partial_ingest)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(b"invalid")))
    assert error.value.status_code == 400
    assert active.capture_id == capture_id
    assert len(active.packets) == 1
    assert active.get_packet(original["id"]) is original


def test_successful_upload_replaces_evidence_and_preserves_subscribers(monkeypatch):
    active = CaptureSession()
    original = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    subscriber = active.subscribe()
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server.intelligence, "investigation_summary", lambda *args: {"ok": True})

    def parse(self, data):
        self.ingest(Ether()/IP(src="192.0.2.1", dst="192.0.2.2")/TCP(), ts=100.0)
        self.mode = "pcap"
        return 1

    monkeypatch.setattr(CaptureSession, "ingest_pcap_bytes", parse)
    # The parser is mocked, but the upload still must pass structural validation.
    import struct
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    result = asyncio.run(server.upload_pcap(_upload(header)))
    assert result["packets"] == 1
    assert result["stats"]["mode"] == "pcap"
    assert result["stats"]["requested_mode"] == "pcap"
    assert result["stats"]["capture_id"] == active.capture_id
    assert active.get_packet(original["id"]) is None
    assert active.packets[0]["src_ip"] == "192.0.2.1"
    assert subscriber in active._subscribers


def test_empty_parsed_capture_does_not_erase_evidence(monkeypatch):
    active = CaptureSession()
    active.ingest(Ether()/IP()/TCP(), ts=90.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(CaptureSession, "ingest_pcap_bytes", lambda self, data: 0)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(b"header-only")))
    assert error.value.status_code == 400
    assert len(active.packets) == 1


def test_oversized_upload_rejected_without_erasing_evidence(monkeypatch):
    active = CaptureSession()
    active.ingest(Ether()/IP()/TCP(), ts=90.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server, "MAX_PCAP_BYTES", 4)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(b"12345")))
    assert error.value.status_code == 413
    assert len(active.packets) == 1


def test_real_pcap_roundtrip_import(monkeypatch):
    active = CaptureSession()
    active.ingest(Ether()/IP(src="10.0.0.3", dst="10.0.0.4")/TCP(), ts=80.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server.intelligence, "investigation_summary", lambda *args: {"ok": True})
    # Scapy's wrpcap closes file-like objects; use its bytes-returning writer.
    from scapy.utils import PcapWriter
    buffer = io.BytesIO()
    writer = PcapWriter(buffer, sync=True)
    writer.write(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.10", dst="192.0.2.20")/TCP())
    data = buffer.getvalue()
    result = asyncio.run(server.upload_pcap(_upload(data)))
    assert result["packets"] == 1
    assert result["stats"]["total_packets"] == 1
    assert result["stats"]["mode"] == "pcap"
    assert result["stats"]["requested_mode"] == "pcap"
    assert active.packets[0]["src_ip"] == "192.0.2.10"


@pytest.mark.parametrize("payload", [
    b"not-a-pcap",
    b"\\xd4\\xc3\\xb2",
    b"\\xd4\\xc3\\xb2\\xa1" + b"\\x00" * 10,
])
def test_malformed_or_truncated_pcap_preserves_evidence(monkeypatch, payload):
    active = CaptureSession()
    previous = active.ingest(Ether()/IP(src="10.0.0.10", dst="10.0.0.11")/TCP(), ts=100.0)
    original_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(payload)))
    assert error.value.status_code == 400
    assert active.capture_id == original_id
    assert active.get_packet(previous["id"]) is previous
    assert len(active.packets) == 1


def test_pcap_with_truncated_packet_record_preserves_evidence(monkeypatch):
    import struct

    active = CaptureSession()
    previous = active.ingest(Ether()/IP()/TCP(), ts=100.0)
    monkeypatch.setattr(server, "session", active)
    # Valid little-endian PCAP header followed by a record claiming 60 captured
    # bytes, with only three bytes actually present.
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record_header = struct.pack("<IIII", 100, 0, 60, 60)
    payload = global_header + record_header + b"\\x00\\x01\\x02"
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(payload)))
    assert error.value.status_code == 400
    assert active.get_packet(previous["id"]) is previous
