import asyncio

import pytest
from scapy.all import Ether, IP, TCP

from etherlens.engine import CaptureSession


def packet(number):
    return Ether()/IP(src="192.168.1.10", dst="198.51.100.20")/TCP(sport=40000+number, dport=443)


def test_packet_limit_evicts_packet_and_detail_index_together():
    session = CaptureSession()
    session.configure_packet_limit(1000)

    for number in range(1002):
        session.ingest(packet(number))

    assert len(session.packets) == 1000
    assert len(session.by_id) == 1000
    assert session.dropped_packets == 2
    assert session.stats()["packet_limit"] == 1000


def test_shrinking_packet_limit_retains_newest_packets():
    session = CaptureSession()
    for number in range(1100):
        session.ingest(packet(number))
    newest_ids = [item["id"] for item in list(session.packets)[-1000:]]

    session.configure_packet_limit(1000)

    assert [item["id"] for item in session.packets] == newest_ids
    assert set(session.by_id) == set(newest_ids)
    assert session.dropped_packets == 100


def test_packet_limit_rejects_unbounded_values():
    session = CaptureSession()
    with pytest.raises(ValueError, match="between 1000 and 1000000"):
        session.configure_packet_limit(999)
    with pytest.raises(ValueError, match="between 1000 and 1000000"):
        session.configure_packet_limit(1000001)


def test_interface_switch_preserves_or_clears_capture_state():
    async def scenario():
        session = CaptureSession()
        first = session.ingest(packet(1))
        session.interface = "adapter-a"
        session.running = True

        preserved = await session.switch_interface("adapter-b", True, 1000)
        assert preserved["status"] == "switched"
        assert preserved["previous_interface"] == "adapter-a"
        assert preserved["preserved_packets"] == 1
        assert session.get_packet(first["id"]) is not None

        cleared = await session.switch_interface("simulated", False, 1000)
        assert cleared["preserved_packets"] == 0
        assert session.get_packet(first["id"]) is None
        assert session.counter == 0
        await session.stop()

    asyncio.run(scenario())
