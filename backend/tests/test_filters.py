from etherlens.filters import filter_packets


def packets():
    return [
        {"id": "1", "src_ip": "10.0.0.5", "dst_ip": "1.1.1.1", "src_port": 51000, "dst_port": 443, "protocol": "TLS", "length": 1200, "layers": []},
        {"id": "2", "src_ip": "10.0.0.8", "dst_ip": "8.8.8.8", "src_port": 53000, "dst_port": 53, "protocol": "DNS", "length": 80, "layers": []},
        {"id": "3", "src_ip": "1.1.1.1", "dst_ip": "10.0.0.5", "src_port": 443, "dst_port": 51000, "protocol": "TLS", "length": 900, "layers": []},
    ]


def ids(expression):
    return [p["id"] for p in filter_packets(packets(), expression)]


def test_ip_token_matches_both_directions():
    assert ids("ip:10.0.0.5") == ["1", "3"]


def test_readable_ip_equality_used_by_connection_story():
    assert ids("ip == 10.0.0.5") == ["1", "3"]


def test_readable_endpoint_equality_forms():
    assert ids("src == 10.0.0.5") == ["1"]
    assert ids("dst == 10.0.0.5") == ["3"]
    assert ids("port == 443") == ["1", "3"]


def test_endpoint_filter_composes_with_existing_tokens():
    assert ids("ip == 10.0.0.5 port:443 bytes>1000") == ["1"]
