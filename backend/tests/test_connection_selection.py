import pytest

from etherlens.connection_selection import select_connection


def conn(a_ip="10.0.0.2", a_port=51000, b_ip="1.1.1.1", b_port=443, packets=10, bytes_=1000):
    return {"a_ip": a_ip, "a_port": a_port, "b_ip": b_ip, "b_port": b_port, "packets": packets, "bytes": bytes_}


def test_exact_forward_tuple():
    wanted = conn(a_port=51000, b_port=443)
    other = conn(a_port=443, b_port=51000, packets=999, bytes_=999999)
    assert select_connection([other, wanted], "10.0.0.2", "1.1.1.1", 51000, 443) is wanted


def test_exact_reverse_tuple():
    stored = conn(a_ip="1.1.1.1", a_port=443, b_ip="10.0.0.2", b_port=51000)
    assert select_connection([stored], "10.0.0.2", "1.1.1.1", 51000, 443) is stored


def test_exact_tuple_does_not_fall_back_to_endpoint_pair():
    existing = conn(a_port=52000, b_port=443)
    assert select_connection([existing], "10.0.0.2", "1.1.1.1", 51000, 443) is None


def test_crossed_ports_do_not_collide():
    crossed = conn(a_port=443, b_port=51000)
    assert select_connection([crossed], "10.0.0.2", "1.1.1.1", 51000, 443) is None


def test_partial_port_request_is_rejected():
    with pytest.raises(ValueError, match="supplied together"):
        select_connection([conn()], "10.0.0.2", "1.1.1.1", a_port=51000)


def test_endpoint_only_chooses_highest_traffic_deterministically():
    small = conn(a_port=51000, packets=20, bytes_=2000)
    large = conn(a_port=52000, packets=30, bytes_=9000)
    assert select_connection([small, large], "10.0.0.2", "1.1.1.1") is large


def test_missing_endpoint_pair_returns_none():
    assert select_connection([conn()], "10.0.0.9", "8.8.8.8") is None
