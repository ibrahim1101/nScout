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
        "SNI": "example.com", "Version": "TLS 1.3", "ALPN": "h2",
        "Cipher Suite": "TLS_AES_128_GCM_SHA256", "Handshake": "Client Hello",
        "Certificate Subject": "CN=example.com", "Certificate Issuer": "Example CA",
        "Certificate Expiry": "2099-01-01T00:00:00Z",
    }}]
    result = tls_intelligence([packet("tls1", 1.0, proto="TLS", layers=layers)])
    event = result["events"][0]
    assert event["sni"] == "example.com"
    assert event["decoded"] is True
    assert event["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert event["handshake"] == "Client Hello"
    assert event["certificate_subject"] == "CN=example.com"
    assert result["versions"][0]["version"] == "TLS 1.3"
    assert result["alpns"][0]["alpn"] == "h2"
    assert result["cipher_suites"][0]["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert result["handshakes"][0]["handshake"] == "Client Hello"
    assert result["decoded_events"] == 1
    assert result["metadata_only_events"] == 0
    assert "not decrypted" in result["note"]


def test_https_port_context_is_not_claimed_as_decoded_tls():
    result = tls_intelligence([packet("https", 1.0, proto="HTTPS")])
    assert result["events"][0]["decoded"] is False
    assert result["decoded_events"] == 0
    assert result["metadata_only_events"] == 1


def test_legacy_tls_and_expired_certificate_warnings():
    layers = [{"name": "Transport Layer Security", "fields": {
        "Version": "TLS 1.0", "Certificate Expiry": "2000-01-01T00:00:00Z"
    }}]
    result = tls_intelligence([packet("old", 1.0, proto="TLS", layers=layers)])
    warning_types = {warning["type"] for warning in result["warnings"]}
    assert "legacy_tls" in warning_types
    assert "expired_certificate" in warning_types


def test_packet_ascii_is_printable_and_safe():
    assert packet_ascii({"hex": "48656c6c6f000a"}) == "Hello.."
    assert packet_ascii({"hex": "not-hex"}) == ""
