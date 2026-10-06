from etherlens.investigation_timeline import investigation_timeline


def packet(pid, number, ts, src="10.0.0.5", dst="203.0.113.9", proto="TCP", flags="", layers=None):
    return {"id": pid, "number": number, "timestamp": ts, "src_ip": src, "dst_ip": dst,
            "src_port": 50000, "dst_port": 443, "protocol": proto, "flags": flags,
            "length": 100, "layers": layers or []}


def test_timeline_builds_dns_connection_tls_http_and_finding_story():
    dns = {"name": "Domain Name System", "fields": {"Query": "api.example.test", "Response": True,
                                                              "Answers": [{"value": "203.0.113.9"}]}}
    tls = {"name": "Transport Layer Security", "fields": {"SNI": "api.example.test", "Version": "TLS 1.3",
                                                                    "Handshake": "Client Hello"}}
    http = {"name": "Hypertext Transfer Protocol", "fields": {"Method": "GET", "Host": "api.example.test", "Path": "/v1"}}
    packets = [
        packet("dns", 1, 1, src="8.8.8.8", dst="10.0.0.5", proto="DNS", layers=[dns]),
        packet("syn", 2, 2, flags="SYN"),
        packet("tls", 3, 3, proto="TLS", layers=[tls]),
        packet("http", 4, 4, proto="HTTP", layers=[http]),
    ]
    findings = [{"type": "traffic.beaconing", "title": "Regular outbound connection pattern",
                 "severity": "medium", "confidence": "medium", "packet_id": "syn", "timestamp": 2,
                 "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "state": "new"}]
    result = investigation_timeline(packets, findings)
    types = [event["event_type"] for event in result["events"]]
    assert types == ["dns.response", "connection.start", "security.finding", "tls.handshake", "http.request"]
    assert result["events"][1]["domain"] == "api.example.test"
    assert result["counts"] == {"dns": 1, "connection": 1, "security": 1, "tls": 1, "http": 1}


def test_timeline_filters_host_domain_protocol_severity_and_time():
    packets = [packet("syn", 1, 10, flags="SYN"), packet("rst", 2, 20, flags="RST")]
    findings = [{"type": "network.port_scan", "severity": "high", "packet_id": "syn", "timestamp": 10,
                 "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9"}]
    high = investigation_timeline(packets, findings, host="10.0.0.5", protocol="security", min_severity="high")
    assert high["total"] == 1
    assert high["events"][0]["event_type"] == "security.finding"
    window = investigation_timeline(packets, findings, start=15, end=25)
    assert [event["event_type"] for event in window["events"]] == ["connection.reset"]
