from etherlens.explanations import explain_connection


def test_connection_explanation_preserves_encryption_boundary():
    connection = {
        "a_ip": "10.0.0.5", "a_port": 53100,
        "b_ip": "1.1.1.1", "b_port": 443,
        "state": "established", "packets": 14,
        "protocols": ["TCP", "TLS"],
        "retransmissions": 0, "duplicate_acks": 0,
        "out_of_order": 0, "zero_windows": 0, "resets": 0,
    }
    tls = {"events": [{"src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "sni": "example.test"}]}
    result = explain_connection(connection, tls=tls)
    assert result["appears_normal"] is True
    assert result["tls_events"] == 1
    assert "not decrypted" in result["visibility_note"].lower()
    assert "encrypted" in result["visibility_note"].lower()


def test_connection_explanation_surfaces_tcp_health_without_claiming_compromise():
    connection = {
        "a_ip": "192.168.1.20", "a_port": 51000,
        "b_ip": "203.0.113.10", "b_port": 80,
        "state": "reset", "packets": 9,
        "protocols": ["TCP", "HTTP"],
        "retransmissions": 2, "duplicate_acks": 1,
        "out_of_order": 0, "zero_windows": 0, "resets": 1,
    }
    result = explain_connection(connection)
    assert result["appears_normal"] is False
    assert {x["type"] for x in result["tcp_issues"]} == {"retransmissions", "duplicate_acks", "resets"}
    assert "not proof of compromise" in result["assessment"].lower()
    assert result["next_steps"]


def test_connection_explanation_correlates_dns_by_endpoint():
    connection = {
        "a_ip": "10.0.0.8", "a_port": 52000,
        "b_ip": "8.8.8.8", "b_port": 53,
        "state": "established", "packets": 2,
        "protocols": ["UDP", "DNS"],
    }
    dns = {"events": [
        {"src_ip": "10.0.0.8", "dst_ip": "8.8.8.8", "query": "example.test"},
        {"src_ip": "10.0.0.99", "dst_ip": "8.8.4.4", "query": "unrelated.test"},
    ]}
    result = explain_connection(connection, dns=dns)
    assert result["dns_events"] == 1
    assert any("DNS" in step for step in result["next_steps"])
