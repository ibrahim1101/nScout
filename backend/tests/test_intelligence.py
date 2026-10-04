from etherlens.intelligence import annotate_tcp_health, connection_intelligence, protocol_dashboard, investigation_summary


def tcp_packet(pid, number, ts, src, sport, dst, dport, seq, ack, flags="ACK", payload=0, window=8192, length=60):
    return {
        "id": pid, "number": number, "timestamp": ts, "src_ip": src, "dst_ip": dst,
        "src_port": sport, "dst_port": dport, "protocol": "TCP", "flags": flags,
        "payload_size": payload, "length": length,
        "layers": [{"name": "Transmission Control Protocol", "fields": {
            "Source Port": sport, "Destination Port": dport, "Sequence Number": seq,
            "Acknowledgment Number": ack, "Window Size": window,
        }}],
    }


def test_tcp_health_detects_retransmission_reset_and_zero_window():
    packets = [
        tcp_packet("a", 1, 1.0, "10.0.0.1", 50000, "1.1.1.1", 443, 100, 1, payload=20),
        tcp_packet("b", 2, 1.1, "10.0.0.1", 50000, "1.1.1.1", 443, 100, 1, payload=20),
        tcp_packet("c", 3, 1.2, "1.1.1.1", 443, "10.0.0.1", 50000, 200, 120, flags="ACK,RST", window=0),
        tcp_packet("d", 4, 1.3, "1.1.1.1", 443, "10.0.0.1", 50000, 200, 120, window=0),
    ]
    health = annotate_tcp_health(packets)
    assert "tcp.retransmission" in health["b"]["events"]
    assert "tcp.reset" in health["c"]["events"]
    assert "tcp.zero_window" in health["d"]["events"]


def test_connection_intelligence_groups_both_directions():
    packets = [
        tcp_packet("a", 1, 1.0, "10.0.0.1", 50000, "1.1.1.1", 443, 1, 0, "SYN", length=60),
        tcp_packet("b", 2, 1.1, "1.1.1.1", 443, "10.0.0.1", 50000, 10, 2, "SYN,ACK", length=70),
    ]
    rows = connection_intelligence(packets)
    assert len(rows) == 1
    assert rows[0]["packets"] == 2
    assert rows[0]["bytes"] == 130
    assert rows[0]["state"] == "established"


def test_dashboard_and_investigation_summary_are_serializable_shapes():
    packets = [tcp_packet("a", 1, 1.0, "10.0.0.1", 1234, "8.8.8.8", 53, 1, 0)]
    dash = protocol_dashboard(packets)
    assert dash["total_packets"] == 1
    assert dash["total_bytes"] == 60
    assert dash["protocols"][0]["protocol"] == "TCP"
    summary = investigation_summary(packets, [{"id": "t1", "severity": "low"}])
    assert summary["overview"]["total_packets"] == 1
    assert summary["threats"][0]["id"] == "t1"
