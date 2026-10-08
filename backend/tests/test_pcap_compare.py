import io

import pytest
from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap  # type: ignore

from etherlens.pcap_compare import compare_pcap_bytes, compare_summaries, summarize_pcap


def _summary(packets, bytes_, protocols, hosts, domains=(), findings=()):
    return {
        "overview": {
            "total_packets": packets,
            "total_bytes": bytes_,
            "protocols": [{"protocol": key, "packets": value} for key, value in protocols.items()],
            "top_ports": [{"port": 443, "packets": packets}],
        },
        "hosts": [{"ip": host} for host in hosts],
        "connections": [{"a_ip": hosts[0], "a_port": 50000, "b_ip": hosts[-1], "b_port": 443}] if hosts else [],
        "dns": {"top_domains": [{"domain": domain, "queries": 1} for domain in domains]},
        "security": {"findings": list(findings)},
        "tcp_health": {},
    }


def _pcap_bytes(packets):
    buffer = io.BytesIO()
    wrpcap(buffer, packets)
    return buffer.getvalue()


def test_compare_summaries_reports_deltas_and_added_removed_entities():
    before = _summary(10, 1000, {"DNS": 3, "HTTPS": 7}, ["10.0.0.2", "1.1.1.1"], ["old.test"])
    after = _summary(15, 2200, {"DNS": 2, "HTTPS": 10, "SSH": 3}, ["10.0.0.2", "8.8.8.8"], ["new.test"], [{"type": "network.port_scan", "severity": "high"}])
    result = compare_summaries(before, after)
    assert result["metrics"]["packets"]["delta"] == 5
    assert result["metrics"]["bytes"]["percent_change"] == 120.0
    assert result["hosts"]["added"] == ["8.8.8.8"]
    assert result["hosts"]["removed"] == ["1.1.1.1"]
    assert next(row for row in result["protocols"] if row["name"] == "SSH")["delta"] == 3
    assert result["interpretation"].endswith("not proof of compromise.")


def test_compare_pcap_bytes_is_isolated_and_records_hashes_and_duration():
    baseline = _pcap_bytes([Ether()/IP(src="10.0.0.2", dst="1.1.1.1")/TCP(sport=50000, dport=443, flags="S")])
    current = _pcap_bytes([
        Ether()/IP(src="10.0.0.2", dst="1.1.1.1")/TCP(sport=50000, dport=443, flags="S"),
        Ether()/IP(src="10.0.0.2", dst="8.8.8.8")/UDP(sport=53000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.test")),
    ])
    result = compare_pcap_bytes(baseline, current, "before.pcap", "after.pcap")
    assert result["schema"] == "nscout.pcap-comparison.v1"
    assert result["baseline"]["name"] == "before.pcap"
    assert len(result["current"]["sha256"]) == 64
    assert result["comparison"]["metrics"]["packets"]["delta"] == 1
    assert "example.test" in result["comparison"]["domains"]["added"]


def test_summarize_pcap_rejects_empty_invalid_and_out_of_range_limit():
    with pytest.raises(ValueError, match="empty"):
        summarize_pcap(b"", "empty.pcap")
    with pytest.raises(ValueError, match="Invalid or unsupported"):
        summarize_pcap(b"not-a-pcap", "bad.pcap")
    valid = _pcap_bytes([Ether()/IP()/TCP()])
    with pytest.raises(ValueError, match="packet_limit"):
        summarize_pcap(valid, "one.pcap", packet_limit=0)


def test_comparison_discloses_packet_limit_truncation():
    data = _pcap_bytes([Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP() for _ in range(3)])
    result = summarize_pcap(data, "bounded.pcap", packet_limit=2)
    assert result["file"]["packets_analyzed"] == 2
    assert result["file"]["truncated"] is True
