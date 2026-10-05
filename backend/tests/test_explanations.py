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


def test_connection_explanation_handles_metadata_only_tls_schema():
    connection = {
        "a_ip": "10.0.0.15", "a_port": 54000,
        "b_ip": "203.0.113.44", "b_port": 443,
        "state": "established", "packets": 20,
        "protocols": ["TCP", "TLS"],
    }
    tls = {"connections": [
        {"src_ip": "203.0.113.44", "dst_ip": "10.0.0.15", "version": "TLS 1.3"},
        {"src_ip": "198.51.100.8", "dst_ip": "10.0.0.99", "version": "TLS 1.2"},
    ]}
    result = explain_connection(connection, tls=tls)
    assert result["tls_events"] == 1
    assert any("TLS" in observation for observation in result["observations"])
    assert any("do not infer encrypted application contents" in step for step in result["next_steps"])


def test_connection_explanation_marks_incomplete_connection_for_review():
    connection = {
        "a_ip": "10.0.0.25", "a_port": 55000,
        "b_ip": "198.51.100.25", "b_port": 22,
        "state": "incomplete", "packets": 3,
        "protocols": ["TCP"],
        "retransmissions": 0, "duplicate_acks": 0,
        "out_of_order": 0, "zero_windows": 0, "resets": 0,
    }
    result = explain_connection(connection)
    assert result["appears_normal"] is False
    assert result["tcp_issues"] == []
    assert "worth analyst review" in result["assessment"].lower()
    assert "not proof of compromise" in result["assessment"].lower()


def test_connection_explanation_defaults_missing_optional_fields_safely():
    result = explain_connection({"a_ip": "10.0.0.1", "b_ip": "10.0.0.2"})
    assert result["appears_normal"] is True
    assert "unknown" in result["summary"].lower()
    assert result["dns_events"] == 0
    assert result["tls_events"] == 0
    assert result["next_steps"]
