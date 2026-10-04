from etherlens.protocol_intelligence import packet_ascii, packet_timeline, tls_intelligence


def packet(pid, ts, proto="TCP", flags="", length=60, layers=None):
    return {
        "id": pid, "timestamp": ts, "protocol": proto, "flags": flags,
        "length": length, "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1",
        "src_port": 50000, "dst_port": 443, "layers": layers or [],
    }


def test_timeline_tracks_connection_events():
    rows = packet_timeline([
        packet("1", 10.0, flags="SYN"),
        packet("2", 10.2, proto="DNS"),
        packet("3", 11.1, flags="RST,ACK"),
    ], bucket_seconds=1)
    assert len(rows) == 2
    assert rows[0]["events"]["connection_start"] == 1
    assert rows[0]["events"]["dns"] == 1
    assert rows[1]["events"]["tcp_reset"] == 1


def test_tls_summary_uses_only_visible_metadata():
    layers = [{"name": "Transport Layer Security", "fields": {
        "SNI": "example.com", "Version": "TLS 1.3", "ALPN": "h2"
    }}]
    result = tls_intelligence([packet("tls1", 1.0, proto="TLS", layers=layers)])
    assert result["events"][0]["sni"] == "example.com"
    assert result["events"][0]["decoded"] is True
    assert result["versions"][0]["version"] == "TLS 1.3"
    assert "not decrypted" in result["note"]


def test_legacy_tls_warning():
    layers = [{"name": "Transport Layer Security", "fields": {"Version": "TLS 1.0"}}]
    result = tls_intelligence([packet("old", 1.0, proto="TLS", layers=layers)])
    assert result["warnings"][0]["type"] == "legacy_tls"


def test_packet_ascii_is_printable_and_safe():
    assert packet_ascii({"hex": "48656c6c6f000a"}) == "Hello.."
    assert packet_ascii({"hex": "not-hex"}) == ""
