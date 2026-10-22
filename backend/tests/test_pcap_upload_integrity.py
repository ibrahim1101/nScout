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



@pytest.mark.parametrize("empty_side", ["baseline", "current"])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_compare_rejects_metadata_only_pcapng(monkeypatch, empty_side, endian):
    """A valid PCAP-NG section and interface without packets is not evidence."""
    import struct

    valid = _pcapng_sample(endian)
    offset = 0
    # Preserve only the section and interface blocks from the valid fixture.
    for _ in range(2):
        length = struct.unpack_from(endian + "I", valid, offset + 4)[0]
        offset += length
    metadata_only = valid[:offset]

    def unexpected_comparison(*args, **kwargs):
        pytest.fail("Metadata-only PCAP-NG reached comparison engine")

    monkeypatch.setattr(server, "compare_pcap_bytes", unexpected_comparison)
    baseline = _upload(metadata_only if empty_side == "baseline" else valid)
    current = _upload(metadata_only if empty_side == "current" else valid)
    with pytest.raises(HTTPException) as error:
        asyncio.run(server.compare_pcaps(baseline, current))
    assert error.value.status_code == 400
    assert f"{empty_side} PCAP-NG contains no packets" in str(error.value.detail)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("defect", ["short_block", "truncated_payload", "captured_exceeds_original"])
def test_pcapng_obsolete_packet_block_rejects_invalid_framing(endian, defect):
    """Type-2 packet blocks must be validated, not merely counted as packets."""
    import struct

    def block(block_type, body):
        size = 12 + len(body)
        return struct.pack(endian + "II", block_type, size) + body + struct.pack(endian + "I", size)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    if defect == "short_block":
        packet = block(2, b"\x00" * 16)
    else:
        captured = 8 if defect == "truncated_payload" else 4
        original = 8 if defect == "truncated_payload" else 2
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, captured, original) + b"abcd")
    with pytest.raises(ValueError, match="obsolete packet"):
        server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_obsolete_packet_block_valid_framing(endian):
    """A well-framed obsolete packet block is accepted and counted as evidence."""
    import struct

    def block(block_type, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    payload = b"abcd"
    packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, len(payload), len(payload)) + payload)
    capture = section + interface + packet
    server._validate_pcapng_blocks(capture)
    assert server._pcapng_has_packet_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("lengths", [(0, 0), (0, 4), (4, 0)])
def test_pcapng_obsolete_packet_rejects_zero_lengths(endian, lengths):
    """Type-2 blocks must not treat empty packet records as evidence."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    captured, original = lengths
    packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, captured, original) + b"abcd")
    with pytest.raises(ValueError, match="Invalid PCAP-NG obsolete packet length"):
        server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_rejects_packet_interface_without_definition(endian, packet_type):
    """Packet blocks must reference an interface in their own section."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    payload = b"abcd"
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 1, 0, 0, 0, 4, 4) + payload)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 1, 0, 0, 4, 4) + payload)
    with pytest.raises(ValueError, match="interface ID"):
        server._validate_pcapng_blocks(section + interface + packet)
    # A new section invalidates interface IDs declared in the previous section.
    with pytest.raises(ValueError, match="interface ID"):
        server._validate_pcapng_blocks(section + interface + section + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_accepts_defined_packet_interface(endian, packet_type):
    """Valid packet blocks may reference the second interface of a section."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    payload = b"abcd"
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 1, 0, 0, 0, 4, 4) + payload)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 1, 0, 0, 4, 4) + payload)
    capture = section + interface + interface + packet
    server._validate_pcapng_blocks(capture)
    assert server._pcapng_has_packet_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_interface_ids_restart_at_each_section(endian, packet_type):
    """A new section's first interface must have ID zero, not the prior count."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"abcd")
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"abcd")
    capture = section + interface + interface + section + interface + packet
    server._validate_pcapng_blocks(capture)
    assert server._pcapng_has_packet_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_accepts_unlimited_interface_snapshot_length(endian):
    """Zero snaplen means unlimited in PCAP-NG interface descriptions."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 0))
    enhanced = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 8, 8) + b"abcdefgh")
    obsolete = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 8, 8) + b"abcdefgh")
    simple = block(3, struct.pack(endian + "I", 8) + b"abcdefgh")
    server._validate_pcapng_blocks(section + interface + enhanced + obsolete + simple)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("snaplen", [64, 65535])
def test_pcapng_accepts_nonzero_interface_snapshot_length(endian, snaplen):
    """Ordinary nonzero interface snapshot lengths must remain valid."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, snaplen))
    server._validate_pcapng_blocks(section + interface)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_rejects_packet_larger_than_interface_snaplen(endian, packet_type):
    """A packet's captured length cannot exceed its interface snapshot limit."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 2))
    payload = b"abcd"
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + payload)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + payload)
    with pytest.raises(ValueError, match="packet length"):
        server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_accepts_packet_at_interface_snaplen(endian, packet_type):
    """Captured lengths equal to the interface snapshot limit are valid."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 4))
    payload = b"abcd"
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + payload)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + payload)
    server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_uses_referenced_interface_snaplen(endian, packet_type):
    """Packet limits are looked up by interface ID, not the latest interface."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interfaces = (
        block(1, struct.pack(endian + "HHI", 1, 0, 2))
        + block(1, struct.pack(endian + "HHI", 1, 0, 8))
    )

    def packet(interface_id):
        if packet_type == 2:
            body = struct.pack(endian + "HHIIII", interface_id, 0, 0, 0, 4, 4)
        else:
            body = struct.pack(endian + "IIIII", interface_id, 0, 0, 4, 4)
        return block(packet_type, body + b"abcd")

    server._validate_pcapng_blocks(section + interfaces + packet(1))
    with pytest.raises(ValueError, match="packet length"):
        server._validate_pcapng_blocks(section + interfaces + packet(0))



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_resets_snapshot_limits_between_sections(endian, packet_type):
    """Interface snapshot limits must not leak from one section to the next."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    large_interface = block(1, struct.pack(endian + "HHI", 1, 0, 8))
    small_interface = block(1, struct.pack(endian + "HHI", 1, 0, 2))
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"abcd")
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"abcd")

    server._validate_pcapng_blocks(section + large_interface + packet)
    with pytest.raises(ValueError, match="packet length"):
        server._validate_pcapng_blocks(
            section + large_interface + packet + section + small_interface + packet
        )



@pytest.mark.parametrize("payload", [
    bytes.fromhex("0a0d0d0a"),
    bytes.fromhex("0a0d0d0a") + bytes(4),
    bytes.fromhex("0a0d0d0a") + bytes.fromhex("1c000000") + bytes.fromhex("4d3c"),
    bytes.fromhex("0a0d0d0a") + bytes.fromhex("1c000000") + bytes.fromhex("00000000") + bytes(16),
])
def test_pcapng_rejects_truncated_or_invalid_section_byte_order(payload):
    """Malformed section byte-order metadata must raise ValueError, never IndexError."""
    with pytest.raises(ValueError):
        server._validate_pcapng_blocks(payload)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_rejects_truncated_section_header(endian):
    """A section claiming a complete 28-byte header cannot be truncated."""
    import struct

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    payload = (
        bytes.fromhex("0a0d0d0a")
        + struct.pack(endian + "I", 28)
        + bom
        + struct.pack(endian + "HH", 1, 0)
    )
    with pytest.raises(ValueError, match="block length"):
        server._validate_pcapng_blocks(payload)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("trailing_bytes", [1, 4, 8, 11])
def test_pcapng_rejects_incomplete_trailing_block_header(endian, trailing_bytes):
    """Any trailing bytes shorter than a full block header invalidate the capture."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    with pytest.raises(ValueError, match="Truncated PCAP-NG block header"):
        server._validate_pcapng_blocks(section + interface + bytes(trailing_bytes))



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("declared_length", [0, 8, 13, 1024])
def test_pcapng_rejects_invalid_interface_block_lengths(endian, declared_length):
    """Interface blocks cannot have undersized, unaligned, or oversized lengths."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    malformed = interface[:4] + struct.pack(endian + "I", declared_length) + interface[8:]
    with pytest.raises(ValueError, match="block length"):
        server._validate_pcapng_blocks(section + malformed)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_rejects_mismatched_interface_block_trailer(endian):
    """The final block-length field must match the block header."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    malformed = interface[:-4] + struct.pack(endian + "I", 24)
    with pytest.raises(ValueError, match="trailer mismatch"):
        server._validate_pcapng_blocks(section + malformed)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("bad_option", [
    bytes.fromhex("01010404"),
    bytes.fromhex("01010808") + bytes.fromhex("aabb"),
    bytes.fromhex("00000100") + bytes.fromhex("00000000"),
    bytes.fromhex("00000000") + bytes.fromhex("01000000"),
])
def test_pcapng_rejects_malformed_interface_options(endian, bad_option):
    """Malformed option framing and end markers must be rejected."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface_body = struct.pack(endian + "HHI", 1, 0, 65535)
    padding = bytes((-len(bad_option)) % 4)
    with pytest.raises(ValueError, match="PCAP-NG option|end-of-options"):
        server._validate_pcapng_blocks(
            section + block(1, interface_body + bad_option + padding)
        )



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("option_value", [b"abc", b"abcd"])
def test_pcapng_accepts_valid_padded_interface_options(endian, option_value):
    """Correctly padded interface options and end markers remain accepted."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    option = (
        struct.pack(endian + "HH", 2, len(option_value))
        + option_value
        + bytes((-len(option_value)) % 4)
        + struct.pack(endian + "HH", 0, 0)
    )
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + option)
    server._validate_pcapng_blocks(section + interface)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_rejects_malformed_packet_options(endian, packet_type):
    """Packet blocks must reject options whose declared values exceed the block."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    if packet_type == 2:
        header = struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4)
    else:
        header = struct.pack(endian + "IIIII", 0, 0, 0, 4, 4)
    malformed_option = struct.pack(endian + "HH", 1, 8) + b"abcd"
    packet = block(packet_type, header + b"data" + malformed_option)
    with pytest.raises(ValueError, match="Truncated PCAP-NG option value"):
        server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
@pytest.mark.parametrize("option_value", [b"abc", b"abcd"])
def test_pcapng_accepts_valid_packet_options(endian, packet_type, option_value):
    """Packet options with correct padding and terminators must be accepted."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    if packet_type == 2:
        header = struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4)
    else:
        header = struct.pack(endian + "IIIII", 0, 0, 0, 4, 4)
    option = (
        struct.pack(endian + "HH", 1, len(option_value))
        + option_value
        + bytes((-len(option_value)) % 4)
        + struct.pack(endian + "HH", 0, 0)
    )
    packet = block(packet_type, header + b"data" + option)
    server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("bad_option", [
    bytes.fromhex("01010404"),
    bytes.fromhex("01010808") + bytes.fromhex("aabb"),
    bytes.fromhex("00000100") + bytes.fromhex("00000000"),
    bytes.fromhex("00000000") + bytes.fromhex("01000000"),
])
def test_pcapng_rejects_malformed_section_options(endian, bad_option):
    """Section headers must reject malformed option framing and terminators."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    padding = bytes((-len(bad_option)) % 4)
    section = block(
        0x0A0D0D0A,
        bom + struct.pack(endian + "HHq", 1, 0, -1) + bad_option + padding,
    )
    with pytest.raises(ValueError, match="PCAP-NG option|end-of-options"):
        server._validate_pcapng_blocks(section)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("option_value", [b"abc", b"abcd"])
def test_pcapng_accepts_valid_section_header_options(endian, option_value):
    """Valid section-header options with correct padding must be accepted."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    option = (
        struct.pack(endian + "HH", 2, len(option_value))
        + option_value
        + bytes((-len(option_value)) % 4)
        + struct.pack(endian + "HH", 0, 0)
    )
    section = block(
        0x0A0D0D0A,
        bom + struct.pack(endian + "HHq", 1, 0, -1) + option,
    )
    server._validate_pcapng_blocks(section)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("major,minor", [(0, 0), (1, 1), (2, 0), (65535, 65535)])
def test_pcapng_rejects_unsupported_section_versions(endian, major, minor):
    """Only supported PCAP-NG section version 1.0 may be imported."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(
        0x0A0D0D0A,
        bom + struct.pack(endian + "HHq", major, minor, -1),
    )
    with pytest.raises(ValueError, match="Unsupported PCAP-NG version"):
        server._validate_pcapng_blocks(section)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_rejects_unsupported_version_in_later_section(endian):
    """A later section must be version-checked independently of earlier sections."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    valid = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    invalid = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 2, 0, -1))
    server._validate_pcapng_blocks(valid)
    with pytest.raises(ValueError, match="Unsupported PCAP-NG version"):
        server._validate_pcapng_blocks(valid + invalid)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("original,snaplen,payload", [
    (4, 4, b"abcd"),
    (8, 4, b"abcd"),
    (3, 8, b"abc" + bytes(1)),
])
def test_pcapng_accepts_valid_simple_packet_lengths(endian, original, snaplen, payload):
    """Simple packet data is bounded by original length and interface snaplen."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, snaplen))
    simple_packet = block(3, struct.pack(endian + "I", original) + payload)
    server._validate_pcapng_blocks(section + interface + simple_packet)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("original,snaplen,payload", [
    (4, 4, b""),
    (4, 4, b"abcdefgh"),
    (0, 4, b"abcd"),
])
def test_pcapng_rejects_invalid_simple_packet_lengths(endian, original, snaplen, payload):
    """Simple packet blocks cannot omit, overrun, or claim zero-length data."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, snaplen))
    simple_packet = block(3, struct.pack(endian + "I", original) + payload)
    with pytest.raises(ValueError, match="simple packet"):
        server._validate_pcapng_blocks(section + interface + simple_packet)



@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_rejects_simple_packet_without_interface(endian):
    """Simple packets refer to interface zero and require its declaration."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    packet = block(3, struct.pack(endian + "I", 4) + b"data")
    with pytest.raises(ValueError, match="simple packet missing interface"):
        server._validate_pcapng_blocks(section + packet)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_rejects_simple_packet_after_section_resets_interfaces(endian):
    """An interface in a previous section cannot authorize a simple packet."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    packet = block(3, struct.pack(endian + "I", 4) + b"data")
    server._validate_pcapng_blocks(section + interface + packet)
    with pytest.raises(ValueError, match="simple packet missing interface"):
        server._validate_pcapng_blocks(section + interface + packet + section + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_simple_packet_uses_first_interface_snaplen(endian):
    """A simple packet uses interface zero, not the most recently declared interface."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    first_interface = block(1, struct.pack(endian + "HHI", 1, 0, 4))
    second_interface = block(1, struct.pack(endian + "HHI", 1, 0, 8))
    packet = block(3, struct.pack(endian + "I", 8) + b"abcd")
    server._validate_pcapng_blocks(section + first_interface + second_interface + packet)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_simple_packet_rejects_payload_using_second_interface_snaplen(endian):
    """A larger snaplen on interface one cannot expand simple packet data."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    first_interface = block(1, struct.pack(endian + "HHI", 1, 0, 4))
    second_interface = block(1, struct.pack(endian + "HHI", 1, 0, 8))
    packet = block(3, struct.pack(endian + "I", 8) + b"abcdefgh")
    with pytest.raises(ValueError, match="Invalid PCAP-NG simple packet length"):
        server._validate_pcapng_blocks(section + first_interface + second_interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_unlimited_snaplen_resets_across_sections(endian):
    """An unlimited interface in a new section must not inherit the prior limit."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    limited = block(1, struct.pack(endian + "HHI", 1, 0, 4))
    unlimited = block(1, struct.pack(endian + "HHI", 1, 0, 0))
    packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 8, 8) + b"abcdefgh")
    with pytest.raises(ValueError, match="Invalid PCAP-NG enhanced packet length"):
        server._validate_pcapng_blocks(section + limited + packet)
    server._validate_pcapng_blocks(section + limited + section + unlimited + packet)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_limited_snaplen_resets_after_unlimited_section(endian):
    """A later limited interface must enforce its own snapshot limit."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    limited = block(1, struct.pack(endian + "HHI", 1, 0, 4))
    unlimited = block(1, struct.pack(endian + "HHI", 1, 0, 0))
    packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 8, 8) + b"abcdefgh")
    server._validate_pcapng_blocks(section + unlimited + packet)
    with pytest.raises(ValueError, match="Invalid PCAP-NG enhanced packet length"):
        server._validate_pcapng_blocks(section + unlimited + packet + section + limited + packet)



@pytest.mark.parametrize("first_endian,second_endian", [("<", ">"), (">", "<")])
def test_pcapng_accepts_mixed_endian_sections(first_endian, second_endian):
    """Each PCAP-NG section independently determines the byte order of its blocks."""
    import struct

    def capture_section(endian):
        def block(kind, body):
            length = 12 + len(body)
            return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

        bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
        section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
        interface = block(1, struct.pack(endian + "HHI", 1, 0, 4))
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data")
        return section + interface + packet

    capture = capture_section(first_endian) + capture_section(second_endian)
    server._validate_pcapng_blocks(capture)
    assert server._pcapng_has_packet_blocks(capture)


@pytest.mark.parametrize("first_endian,second_endian", [("<", ">"), (">", "<")])
def test_pcapng_mixed_endian_sections_enforce_new_snaplen(first_endian, second_endian):
    """A new section's byte order and interface snapshot limit both take effect."""
    import struct

    def block(endian, kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    def section(endian):
        bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
        return block(endian, 0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))

    first = section(first_endian) + block(first_endian, 1, struct.pack(first_endian + "HHI", 1, 0, 8))
    second = section(second_endian) + block(second_endian, 1, struct.pack(second_endian + "HHI", 1, 0, 4))
    oversized = block(second_endian, 6, struct.pack(second_endian + "IIIII", 0, 0, 0, 8, 8) + b"abcdefgh")
    with pytest.raises(ValueError, match="Invalid PCAP-NG enhanced packet length"):
        server._validate_pcapng_blocks(first + second + oversized)



@pytest.mark.parametrize("first_endian,second_endian", [("<", ">"), (">", "<")])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_mixed_endian_section_rejects_previous_interface_id(first_endian, second_endian, packet_type):
    """An interface declared in one section cannot be referenced by a later section."""
    import struct

    def block(endian, kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    def section(endian):
        bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
        return block(endian, 0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))

    first = section(first_endian)
    first += block(first_endian, 1, struct.pack(first_endian + "HHI", 1, 0, 65535))
    first += block(first_endian, 1, struct.pack(first_endian + "HHI", 1, 0, 65535))
    second = section(second_endian)
    second += block(second_endian, 1, struct.pack(second_endian + "HHI", 1, 0, 65535))
    if packet_type == 2:
        packet = block(second_endian, 2, struct.pack(second_endian + "HHIIII", 1, 0, 0, 0, 4, 4) + b"data")
    else:
        packet = block(second_endian, 6, struct.pack(second_endian + "IIIII", 1, 0, 0, 4, 4) + b"data")
    with pytest.raises(ValueError, match="interface ID"):
        server._validate_pcapng_blocks(first + second + packet)



@pytest.mark.parametrize("first_endian,second_endian", [("<", ">"), (">", "<")])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_mixed_endian_section_accepts_local_second_interface(first_endian, second_endian, packet_type):
    """Interface ID one remains valid when declared within the new section."""
    import struct

    def block(endian, kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    def section(endian):
        bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
        return block(endian, 0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))

    first = section(first_endian)
    first += block(first_endian, 1, struct.pack(first_endian + "HHI", 1, 0, 4))
    second = section(second_endian)
    second += block(second_endian, 1, struct.pack(second_endian + "HHI", 1, 0, 4))
    second += block(second_endian, 1, struct.pack(second_endian + "HHI", 1, 0, 8))
    if packet_type == 2:
        packet = block(second_endian, 2, struct.pack(second_endian + "HHIIII", 1, 0, 0, 0, 8, 8) + b"abcdefgh")
    else:
        packet = block(second_endian, 6, struct.pack(second_endian + "IIIII", 1, 0, 0, 8, 8) + b"abcdefgh")
    server._validate_pcapng_blocks(first + second + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_packet_options_allow_nonzero_padding_bytes(endian, packet_type):
    """Option padding is framing, not payload, and need not be zeroed."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    options = struct.pack(endian + "HH", 1, 1) + bytes.fromhex("61aabbcc")
    options += struct.pack(endian + "HH", 0, 0)
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"data" + options)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data" + options)
    server._validate_pcapng_blocks(section + interface + packet)


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("packet_type", [2, 6])
def test_pcapng_packet_options_reject_truncated_padded_value(endian, packet_type):
    """Declared option value lengths must fit before the block trailer."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    options = struct.pack(endian + "HH", 1, 5) + b"abcd"
    if packet_type == 2:
        packet = block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"data" + options)
    else:
        packet = block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data" + options)
    with pytest.raises(ValueError, match="Truncated PCAP-NG option value"):
        server._validate_pcapng_blocks(section + interface + packet)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("value_length", [1, 2, 3])
def test_pcapng_interface_options_allow_nonzero_padding(endian, value_length):
    """Interface option padding may contain arbitrary bytes without affecting framing."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    option = struct.pack(endian + "HH", 2, value_length)
    option += b"a" * value_length + b"\xff" * (4 - value_length)
    option += struct.pack(endian + "HH", 0, 0)
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + option)
    server._validate_pcapng_blocks(section + interface)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("value_length", [1, 2, 3])
def test_pcapng_section_options_allow_nonzero_padding(endian, value_length):
    """Section header option padding may contain nonzero bytes."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    option = struct.pack(endian + "HH", 2, value_length)
    option += b"a" * value_length + bytes([255]) * (4 - value_length)
    option += struct.pack(endian + "HH", 0, 0)
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1) + option)
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    server._validate_pcapng_blocks(section + interface)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("block_kind", ["section", "interface", "enhanced", "obsolete"])
def test_pcapng_accepts_options_without_end_marker(endian, block_kind):
    """An option list may end at the block boundary without an end marker."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    options = struct.pack(endian + "HH", 2, 3) + b"abc" + bytes([255])
    section_body = bom + struct.pack(endian + "HHq", 1, 0, -1)
    section = block(0x0A0D0D0A, section_body + (options if block_kind == "section" else b""))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + (options if block_kind == "interface" else b""))
    capture = section + interface
    if block_kind == "enhanced":
        capture += block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data" + options)
    elif block_kind == "obsolete":
        capture += block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"data" + options)
    server._validate_pcapng_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("block_kind", ["section", "interface", "enhanced", "obsolete"])
@pytest.mark.parametrize("end_marker", [False, True])
def test_pcapng_accepts_consecutive_options_with_mixed_padding(endian, block_kind, end_marker):
    """Consecutive options must advance by each padded value length."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    options = struct.pack(endian + "HH", 2, 1) + b"a" + bytes.fromhex("fefdfc")
    options += struct.pack(endian + "HH", 3, 4) + b"bcde"
    options += struct.pack(endian + "HH", 4, 2) + b"fg" + bytes.fromhex("aabb")
    if end_marker:
        options += struct.pack(endian + "HH", 0, 0)
    section_body = bom + struct.pack(endian + "HHq", 1, 0, -1)
    section = block(0x0A0D0D0A, section_body + (options if block_kind == "section" else b""))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + (options if block_kind == "interface" else b""))
    capture = section + interface
    if block_kind == "enhanced":
        capture += block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data" + options)
    elif block_kind == "obsolete":
        capture += block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"data" + options)
    server._validate_pcapng_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("block_kind", ["section", "interface", "enhanced", "obsolete"])
@pytest.mark.parametrize("bad_end", ["nonzero_length", "trailing_option"])
def test_pcapng_rejects_invalid_end_marker_after_valid_option(endian, block_kind, bad_end):
    """An end marker must have zero length and be the last option."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    options = struct.pack(endian + "HH", 2, 1) + b"a" + bytes(3)
    if bad_end == "nonzero_length":
        options += struct.pack(endian + "HH", 0, 4) + b"data"
    else:
        options += struct.pack(endian + "HH", 0, 0)
        options += struct.pack(endian + "HH", 3, 0)
    section_body = bom + struct.pack(endian + "HHq", 1, 0, -1)
    section = block(0x0A0D0D0A, section_body + (options if block_kind == "section" else b""))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + (options if block_kind == "interface" else b""))
    capture = section + interface
    if block_kind == "enhanced":
        capture += block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data" + options)
    elif block_kind == "obsolete":
        capture += block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"data" + options)
    with pytest.raises(ValueError, match="Invalid PCAP-NG end-of-options marker"):
        server._validate_pcapng_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("block_kind", ["section", "interface", "enhanced", "obsolete"])
def test_pcapng_rejects_truncated_option_value_after_valid_option(endian, block_kind):
    """A second option header cannot claim a value beyond its block boundary."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    options = struct.pack(endian + "HH", 2, 1) + b"a" + bytes(3)
    options += struct.pack(endian + "HH", 3, 5)
    section_body = bom + struct.pack(endian + "HHq", 1, 0, -1)
    section = block(0x0A0D0D0A, section_body + (options if block_kind == "section" else b""))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + (options if block_kind == "interface" else b""))
    capture = section + interface
    if block_kind == "enhanced":
        capture += block(6, struct.pack(endian + "IIIII", 0, 0, 0, 4, 4) + b"data" + options)
    elif block_kind == "obsolete":
        capture += block(2, struct.pack(endian + "HHIIII", 0, 0, 0, 0, 4, 4) + b"data" + options)
    with pytest.raises(ValueError, match="Truncated PCAP-NG option value"):
        server._validate_pcapng_blocks(capture)



@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("captured,original", [(0, 0), (0, 4)])
def test_pcapng_rejects_empty_enhanced_packet(endian, captured, original):
    """Enhanced packet blocks must contain captured packet bytes."""
    import struct

    def block(kind, body):
        length = 12 + len(body)
        return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)

    bom = bytes.fromhex("4d3c2b1a") if endian == "<" else bytes.fromhex("1a2b3c4d")
    section = block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    enhanced = block(6, struct.pack(endian + "IIIII", 0, 0, 0, captured, original))
    with pytest.raises(ValueError, match="Invalid PCAP-NG enhanced packet length"):
        server._validate_pcapng_blocks(section + interface + enhanced)



@pytest.mark.parametrize("endian,magic", [
    ("<", bytes.fromhex("d4c3b2a1")),
    (">", bytes.fromhex("a1b2c3d4")),
    ("<", bytes.fromhex("4d3cb2a1")),
    (">", bytes.fromhex("a1b23c4d")),
])
@pytest.mark.parametrize("captured,original", [(0, 0), (0, 4)])
def test_classic_pcap_rejects_empty_packet_record(endian, magic, captured, original):
    """Empty packet records are invalid in both byte orders and time precisions."""
    import struct

    header = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 0, 0, captured, original)
    with pytest.raises(ValueError, match="Invalid PCAP packet length"):
        server._validate_pcap_records(header + record)



@pytest.mark.parametrize("endian,magic", [
    ("<", bytes.fromhex("d4c3b2a1")),
    (">", bytes.fromhex("a1b2c3d4")),
    ("<", bytes.fromhex("4d3cb2a1")),
    (">", bytes.fromhex("a1b23c4d")),
])
@pytest.mark.parametrize("captured,original", [(1, 1), (1, 4)])
def test_classic_pcap_accepts_minimal_nonempty_packet(endian, magic, captured, original):
    """A one-byte captured packet is valid, including when truncated on capture."""
    import struct

    header = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 0, 0, captured, original)
    server._validate_pcap_records(header + record + b"x")



@pytest.mark.parametrize("endian,magic", [
    ("<", bytes.fromhex("d4c3b2a1")),
    (">", bytes.fromhex("a1b2c3d4")),
    ("<", bytes.fromhex("4d3cb2a1")),
    (">", bytes.fromhex("a1b23c4d")),
])
@pytest.mark.parametrize("captured,valid", [(4, True), (5, False)])
def test_classic_pcap_snapshot_length_boundary(endian, magic, captured, valid):
    """Captured lengths at snaplen are allowed; larger records are rejected."""
    import struct

    header = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 4, 1)
    record = struct.pack(endian + "IIII", 0, 0, captured, captured)
    payload = header + record + b"x" * captured
    if valid:
        server._validate_pcap_records(payload)
    else:
        with pytest.raises(ValueError, match="Invalid PCAP packet length"):
            server._validate_pcap_records(payload)



@pytest.mark.parametrize("endian,magic", [
    ("<", bytes.fromhex("d4c3b2a1")),
    (">", bytes.fromhex("a1b2c3d4")),
    ("<", bytes.fromhex("4d3cb2a1")),
    (">", bytes.fromhex("a1b23c4d")),
])
@pytest.mark.parametrize("last_packet_truncated", [False, True])
def test_classic_pcap_multiple_records_validate_final_payload(endian, magic, last_packet_truncated):
    """A valid first record must not mask a truncated second packet."""
    import struct

    header = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 1)
    first = struct.pack(endian + "IIII", 1, 0, 4, 4) + b"abcd"
    second = struct.pack(endian + "IIII", 2, 0, 4, 4) + (b"xyz" if last_packet_truncated else b"wxyz")
    payload = header + first + second
    if last_packet_truncated:
        with pytest.raises(ValueError, match="Truncated PCAP packet data"):
            server._validate_pcap_records(payload)
    else:
        server._validate_pcap_records(payload)
