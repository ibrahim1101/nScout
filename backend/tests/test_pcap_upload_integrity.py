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
    b"\xd4\xc3\xb2",
    b"\xd4\xc3\xb2\xa1" + b"\x00" * 10,
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
    payload = global_header + record_header + b"\x00\x01\x02"
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(payload)))
    assert error.value.status_code == 400
    assert active.get_packet(previous["id"]) is previous


def _pcapng_sample(endian="<"):
    import struct

    def block(kind, body):
        padding = b"\x00" * ((-len(body)) % 4)
        length = 12 + len(body) + len(padding)
        return struct.pack(endian + "II", kind, length) + body + padding + struct.pack(endian + "I", length)

    bom = struct.pack(endian + "I", 0x1A2B3C4D)
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    packet = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.31", dst="192.0.2.32") / TCP())
    enhanced = block(6, struct.pack(endian + "IIIII", 0, 0, 0, len(packet), len(packet)) + packet)
    return section + interface + enhanced


@pytest.mark.parametrize("endian", ["<", ">"])
def test_real_pcapng_import_both_endian_modes(monkeypatch, endian):
    active = CaptureSession()
    active.ingest(Ether()/IP()/TCP(), ts=90.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server.intelligence, "investigation_summary", lambda *args: {"ok": True})
    result = asyncio.run(server.upload_pcap(_upload(_pcapng_sample(endian))))
    assert result["packets"] == 1
    assert result["stats"]["mode"] == "pcap"
    assert active.packets[0]["src_ip"] == "192.0.2.31"


@pytest.mark.parametrize("corrupt", ["truncated", "trailer", "byte_order"])
def test_corrupt_pcapng_preserves_existing_evidence(monkeypatch, corrupt):
    active = CaptureSession()
    previous = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    payload = bytearray(_pcapng_sample())
    if corrupt == "truncated":
        payload = payload[:-3]
    elif corrupt == "trailer":
        payload[-4:] = b"\x00" * 4
    else:
        payload[8:12] = b"\x00" * 4
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(bytes(payload))))
    assert error.value.status_code == 400
    assert active.capture_id == capture_id
    assert active.get_packet(previous["id"]) is previous


@pytest.mark.parametrize("captured,original", [(65535, 65535), (60, 30)])
def test_pcapng_invalid_enhanced_packet_lengths_preserve_evidence(monkeypatch, captured, original):
    import struct
    active = CaptureSession()
    previous = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    original_capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    payload = bytearray(_pcapng_sample())
    # Enhanced Packet Block is last; its captured/original lengths start 20/24 bytes
    # after the block header. Locate it by walking the valid little-endian blocks.
    offset = 0
    while offset < len(payload):
        kind, length = struct.unpack_from("<II", payload, offset)
        if kind == 6:
            struct.pack_into("<II", payload, offset + 20, captured, original)
            break
        offset += length
    else:
        pytest.fail("Enhanced Packet Block missing from test fixture")
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(bytes(payload))))
    assert error.value.status_code == 400
    assert active.capture_id == original_capture_id
    assert active.get_packet(previous["id"]) is previous


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_enhanced_packet_options_remain_compatible(monkeypatch, endian):
    import struct

    active = CaptureSession()
    active.ingest(Ether()/IP()/TCP(), ts=90.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server.intelligence, "investigation_summary", lambda *args: {"ok": True})
    payload = _pcapng_sample(endian)
    # Add a valid comment option and the end-of-options marker to the final EPB.
    option = struct.pack(endian + "HH", 1, 4) + b"note"
    end_options = struct.pack(endian + "HH", 0, 0)
    extra = option + end_options
    original_block_length = struct.unpack_from(endian + "I", payload, len(payload) - 4)[0]
    start = len(payload) - original_block_length
    new_length = original_block_length + len(extra)
    enhanced = bytearray(payload[start:])
    struct.pack_into(endian + "I", enhanced, 4, new_length)
    enhanced = enhanced[:-4] + extra + struct.pack(endian + "I", new_length)
    result = asyncio.run(server.upload_pcap(_upload(payload[:start] + enhanced)))
    assert result["packets"] == 1
    assert active.packets[0]["src_ip"] == "192.0.2.31"


@pytest.mark.parametrize("corruption", ["truncated_option", "invalid_end_marker"])
def test_pcapng_invalid_options_preserve_evidence(monkeypatch, corruption):
    import struct

    active = CaptureSession()
    previous = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    payload = _pcapng_sample("<")
    block_length = struct.unpack_from("<I", payload, len(payload) - 4)[0]
    start = len(payload) - block_length
    block = bytearray(payload[start:-4])
    if corruption == "truncated_option":
        options = struct.pack("<HH", 1, 100) + b"abcd"
    else:
        options = struct.pack("<HH", 0, 4) + b"abcd"
    new_length = block_length + len(options)
    struct.pack_into("<I", block, 4, new_length)
    invalid = payload[:start] + block + options + struct.pack("<I", new_length)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(invalid)))
    assert error.value.status_code == 400
    assert active.capture_id == capture_id
    assert active.get_packet(previous["id"]) is previous


@pytest.mark.parametrize("block_type", [0x0A0D0D0A, 1])
def test_pcapng_invalid_section_or_interface_options_preserve_evidence(monkeypatch, block_type):
    import struct

    active = CaptureSession()
    previous = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    payload = _pcapng_sample("<")
    offset = 0
    while offset < len(payload):
        kind, length = struct.unpack_from("<II", payload, offset)
        if kind == block_type:
            # Option declares eight bytes but supplies only four before block trailer.
            bad_option = struct.pack("<HH", 1, 8) + b"abcd"
            block = bytearray(payload[offset:offset + length - 4])
            struct.pack_into("<I", block, 4, length + len(bad_option))
            malformed = (
                payload[:offset] + block + bad_option
                + struct.pack("<I", length + len(bad_option))
                + payload[offset + length:]
            )
            break
        offset += length
    else:
        pytest.fail("Requested PCAP-NG block missing")
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(malformed)))
    assert error.value.status_code == 400
    assert active.capture_id == capture_id
    assert active.get_packet(previous["id"]) is previous


@pytest.mark.parametrize("endian,nanosecond", [
    ("<", False), (">", False), ("<", True), (">", True),
])
def test_classic_pcap_magic_variants_roundtrip(monkeypatch, endian, nanosecond):
    import struct

    active = CaptureSession()
    active.ingest(Ether()/IP()/TCP(), ts=90.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server.intelligence, "investigation_summary", lambda *args: {"ok": True})
    packet = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                   / IP(src="192.0.2.41", dst="192.0.2.42") / TCP())
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 100, 0, len(packet), len(packet))
    result = asyncio.run(server.upload_pcap(_upload(header + record + packet)))
    assert result["packets"] == 1
    assert active.packets[0]["src_ip"] == "192.0.2.41"


@pytest.mark.parametrize("endian", ["<", ">"])
def test_classic_pcap_truncated_record_preserves_evidence_for_both_endians(monkeypatch, endian):
    import struct

    active = CaptureSession()
    previous = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    header = struct.pack(endian + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 100, 0, 64, 64)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(header + record + bytes(4))))
    assert error.value.status_code == 400
    assert active.capture_id == capture_id
    assert active.get_packet(previous["id"]) is previous



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nanosecond", [False, True])
def test_classic_pcap_endian_and_timestamp_precision_import(monkeypatch, endian, nanosecond):
    """Classic PCAP imports must work with either byte order and timestamp precision."""
    import struct

    active = CaptureSession()
    active.ingest(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(), ts=90.0)
    monkeypatch.setattr(server, "session", active)
    monkeypatch.setattr(server.intelligence, "investigation_summary", lambda *args: {"ok": True})
    packet = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                   / IP(src="192.0.2.40", dst="192.0.2.41") / TCP())
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 100, 0, len(packet), len(packet))
    result = asyncio.run(server.upload_pcap(_upload(header + record + packet)))
    assert result["packets"] == 1
    assert active.packets[0]["src_ip"] == "192.0.2.40"


@pytest.mark.parametrize("endian", ["<", ">"])
def test_classic_pcap_invalid_packet_length_preserves_evidence(monkeypatch, endian):
    """Malformed record lengths must never replace the investigation capture."""
    import struct

    active = CaptureSession()
    original = active.ingest(Ether()/IP()/TCP(), ts=90.0)
    capture_id = active.capture_id
    monkeypatch.setattr(server, "session", active)
    header = struct.pack(endian + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 100, 0, 80, 40)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.upload_pcap(_upload(header + record + b"\x00" * 80)))
    assert error.value.status_code == 400
    assert active.capture_id == capture_id
    assert active.get_packet(original["id"]) is original



@pytest.mark.parametrize("oversized_side", ["baseline", "current"])
def test_compare_pcap_rejects_oversized_input_before_comparison(monkeypatch, oversized_side):
    """Both comparison inputs must be bounded before reaching the comparison engine."""
    monkeypatch.setattr(server, "MAX_PCAP_BYTES", 4)

    def unexpected_comparison(*args, **kwargs):
        pytest.fail("Comparison engine must not run for oversized uploads")

    monkeypatch.setattr(server, "compare_pcap_bytes", unexpected_comparison)
    baseline = _upload(b"12345" if oversized_side == "baseline" else b"abcd")
    current = _upload(b"12345" if oversized_side == "current" else b"abcd")
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.compare_pcaps(baseline, current))
    assert error.value.status_code == 413


def test_compare_pcap_reads_no_more_than_limit_plus_one(monkeypatch):
    """An oversized stream must not be consumed beyond the detection threshold."""
    monkeypatch.setattr(server, "MAX_PCAP_BYTES", 4)

    class BoundedUpload:
        def __init__(self, payload):
            self.payload = payload
            self.read_sizes = []
            self.filename = "capture.pcap"

        async def read(self, size=-1):
            self.read_sizes.append(size)
            assert size == 5, "Comparison must not read the full upload"
            return self.payload[:size]

    baseline = BoundedUpload(b"123456789")
    current = BoundedUpload(b"abcd")
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.compare_pcaps(baseline, current))
    assert error.value.status_code == 413
    assert baseline.read_sizes == [5]
    assert current.read_sizes == []



@pytest.mark.parametrize("invalid_side", ["baseline", "current"])
@pytest.mark.parametrize("format_name", ["pcap", "pcapng"])
def test_compare_rejects_malformed_capture_before_engine(monkeypatch, invalid_side, format_name):
    """A malformed comparison input must never reach the comparison engine."""
    import struct

    monkeypatch.setattr(server, "MAX_PCAP_BYTES", 1024 * 1024)

    def unexpected_comparison(*args, **kwargs):
        pytest.fail("Malformed comparison input reached the comparison engine")

    monkeypatch.setattr(server, "compare_pcap_bytes", unexpected_comparison)
    if format_name == "pcap":
        valid = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        invalid = valid + struct.pack("<IIII", 100, 0, 60, 60) + b"abc"
    else:
        valid = _pcapng_sample()
        invalid = valid[:-3]
    baseline = _upload(invalid if invalid_side == "baseline" else valid)
    current = _upload(invalid if invalid_side == "current" else valid)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.compare_pcaps(baseline, current))
    assert error.value.status_code == 400
    assert "Invalid pcap" in str(error.value.detail)
