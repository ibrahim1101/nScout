from etherlens.security_intelligence import security_intelligence


def pkt(pid, ts, src="10.0.0.2", dst="1.1.1.1", sport=50000, dport=443, flags="SYN", layers=None, length=60):
    return {"id": pid, "timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport,
            "dst_port": dport, "protocol": "TCP", "flags": flags, "length": length, "layers": layers or []}


def test_detects_failed_connection_without_synack():
    rows = [pkt("s", 1.0), pkt("r", 1.1, src="1.1.1.1", dst="10.0.0.2", sport=443, dport=50000, flags="RST,ACK")]
    out = security_intelligence(rows)
    assert any(f["type"] == "tcp.failed_connection" for f in out["findings"])


def test_does_not_mark_established_handshake_failed():
    rows = [pkt("s", 1.0), pkt("sa", 1.1, src="1.1.1.1", dst="10.0.0.2", sport=443, dport=50000, flags="SYN,ACK"),
            pkt("r", 2.0, src="1.1.1.1", dst="10.0.0.2", sport=443, dport=50000, flags="RST,ACK")]
    out = security_intelligence(rows)
    assert not any(f["type"] == "tcp.failed_connection" for f in out["findings"])


def test_detects_regular_beaconing_lead():
    rows = [pkt(str(i), float(i * 10), sport=50000 + i) for i in range(6)]
    out = security_intelligence(rows)
    assert any(f["type"] == "traffic.beaconing" for f in out["findings"])


def test_detects_arp_identity_change():
    def arp(pid, ts, mac):
        return pkt(pid, ts, flags="", layers=[{"name": "ARP", "fields": {"Sender IP": "10.0.0.1", "Sender MAC": mac}}])
    out = security_intelligence([arp("a", 1, "aa:aa:aa:aa:aa:aa"), arp("b", 2, "bb:bb:bb:bb:bb:bb")])
    finding = next(f for f in out["findings"] if f["type"] == "arp.identity_change")
    assert len(finding["mac_addresses"]) == 2


def test_detects_fast_tcp_port_scan_and_attaches_evidence():
    rows = [pkt(str(i), i, dport=1000 + i, sport=40000 + i) for i in range(12)]
    out = security_intelligence(rows)
    finding = next(f for f in out["findings"] if f["type"] == "network.port_scan")
    assert finding["severity"] == "high"
    assert finding["confidence"] == "high"
    assert finding["state"] == "new"
    assert finding["unique_ports"] == 12
    assert finding["evidence"]


def test_does_not_flag_slow_sparse_port_activity_as_scan():
    rows = [pkt(str(i), i * 10, dport=1000 + i, sport=40000 + i) for i in range(12)]
    out = security_intelligence(rows)
    assert not any(f["type"] == "network.port_scan" for f in out["findings"])


def test_detects_unusually_long_dns_query():
    name = ("a" * 56) + ".example.com"
    rows = [pkt("dns", 1, flags="", layers=[{"name": "DNS", "fields": {"Query Name": name}}])]
    out = security_intelligence(rows)
    assert any(f["type"] == "dns.long_query" for f in out["findings"])


def test_detects_large_directional_transfer():
    rows = [pkt(str(i), i, flags="ACK", length=11 * 1024 * 1024) for i in range(10)]
    out = security_intelligence(rows)
    finding = next(f for f in out["findings"] if f["type"] == "traffic.large_transfer")
    assert finding["bytes"] >= 100 * 1024 * 1024


def test_findings_have_triage_metadata():
    rows = [pkt(str(i), float(i * 10), sport=50000 + i) for i in range(6)]
    out = security_intelligence(rows)
    assert out["findings"]
    assert all(f["state"] == "new" for f in out["findings"])
    assert all(f["confidence"] in {"low", "medium", "high"} for f in out["findings"])
    assert "confidences" in out


def test_security_output_states_heuristic_boundary():
    out = security_intelligence([])
    assert "not proof" in out["note"].lower()
    assert out["findings"] == []
