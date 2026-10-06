from etherlens.host_intelligence import host_intelligence


def packet(pid, ts, src, dst, sport, dport, protocol="HTTPS", length=100, layers=None):
    return {"id": pid, "timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport,
            "dst_port": dport, "protocol": protocol, "length": length, "layers": layers or []}


def test_profiles_correlate_identity_activity_and_findings():
    ethernet = {"name": "Ethernet II", "fields": {"Source": "aa:aa:aa:aa:aa:aa", "Destination": "bb:bb:bb:bb:bb:bb"}}
    dns_query = {"name": "Domain Name System", "fields": {"Query": "api.example.test", "Response": False}}
    dns_answer = {"name": "Domain Name System", "fields": {"Query": "api.example.test", "Response": True, "Answers": [{"value": "203.0.113.9"}]}}
    packets = [
        packet("q", 1, "10.0.0.5", "8.8.8.8", 53000, 53, "DNS", 80, [ethernet, dns_query]),
        packet("a", 2, "8.8.8.8", "10.0.0.5", 53, 53000, "DNS", 120, [ethernet, dns_answer]),
        packet("t", 3, "10.0.0.5", "203.0.113.9", 50000, 443, "HTTPS", 1000, [ethernet]),
    ]
    findings = [{"type": "network.port_scan", "severity": "high", "confidence": "high",
                 "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9"}]
    hosts = {row["ip"]: row for row in host_intelligence(packets, findings)}
    local = hosts["10.0.0.5"]
    remote = hosts["203.0.113.9"]
    assert local["mac"] == "aa:aa:aa:aa:aa:aa"
    assert local["is_local"] is True
    assert local["domains"][0]["domain"] == "api.example.test"
    assert local["risk"] == {"score": 25, "level": "medium"}
    assert local["finding_count"] == 1
    assert remote["hostname"] == "api.example.test"
    assert remote["services"] == [{"port": 443, "protocol": "HTTPS"}]
    assert remote["bytes_received"] == 1000
    assert remote["connections"][0]["peer_ip"] == "10.0.0.5"


def test_risk_is_bounded_and_profiles_sort_by_risk():
    packets = [packet("1", 1, "10.0.0.1", "10.0.0.2", 1, 2)]
    findings = [{"severity": "critical", "confidence": "high", "src_ip": "10.0.0.2"} for _ in range(4)]
    hosts = host_intelligence(packets, findings)
    assert hosts[0]["ip"] == "10.0.0.2"
    assert hosts[0]["risk"] == {"score": 100, "level": "critical"}
