from datetime import datetime, timezone

from scapy.all import Ether, IP, Raw, TCP

from etherlens.engine import dissect_packet
from etherlens.protocol_intelligence import decode_tls_payload, packet_ascii, packet_timeline, tls_intelligence


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


def _extension(kind, value):
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


def _client_hello(host="api.example.test"):
    encoded_host = host.encode("ascii")
    sni_names = b"\x00" + len(encoded_host).to_bytes(2, "big") + encoded_host
    sni = len(sni_names).to_bytes(2, "big") + sni_names
    alpn_names = b"\x02h2\x08http/1.1"
    extensions = b"".join((
        _extension(0, sni),
        _extension(16, len(alpn_names).to_bytes(2, "big") + alpn_names),
        _extension(43, b"\x04\x03\x04\x03\x03"),
        _extension(10, b"\x00\x04\x00\x1d\x0a\x0a"),
        _extension(11, b"\x01\x00"),
    ))
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x04\x13\x01\x0a\x0a" +
            b"\x01\x00" + len(extensions).to_bytes(2, "big") + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def test_client_hello_decoder_extracts_visible_metadata_and_stable_fingerprint():
    fields = decode_tls_payload(_client_hello())
    assert fields["Handshake"] == "Client Hello"
    assert fields["SNI"] == "api.example.test"
    assert fields["ALPN"] == ["h2", "http/1.1"]
    assert fields["Offered Versions"] == ["TLS 1.3", "TLS 1.2"]
    assert fields["Cipher Suites"] == ["0x1301", "0x0a0a"]
    assert len(fields["JA3"]) == 32
    assert fields["JA3"] == decode_tls_payload(_client_hello())["JA3"]


def test_decoder_rejects_non_tls_and_truncated_records():
    assert decode_tls_payload(b"GET / HTTP/1.1\r\n") == {}
    assert decode_tls_payload(_client_hello()[:20]) == {}


def test_packet_dissection_promotes_visible_client_hello_to_tls():
    raw = Ether()/IP(src="10.0.0.2", dst="203.0.113.5")/TCP(sport=51000, dport=443)/Raw(_client_hello())
    decoded = dissect_packet(raw, 1, 100.0)
    tls = next(layer for layer in decoded["layers"] if layer["name"] == "Transport Layer Security")
    assert decoded["protocol"] == "TLS"
    assert "api.example.test" in decoded["info"]
    assert tls["fields"]["SNI"] == "api.example.test"


def test_certificate_status_warnings_are_deterministic():
    layers = [{"name": "Transport Layer Security", "fields": {
        "Version": "TLS 1.2", "Certificate Subject": "CN=internal.test",
        "Certificate Issuer": "CN=internal.test", "Certificate Not Before": "2026-11-01T00:00:00Z",
        "Certificate Expiry": "2026-10-20T00:00:00Z",
    }}]
    result = tls_intelligence([packet("cert", 1.0, proto="TLS", layers=layers)],
                              now=datetime(2026, 10, 8, tzinfo=timezone.utc))
    assert result["warning_counts"] == {
        "certificate_expiring_soon": 1,
        "certificate_not_yet_valid": 1,
        "self_signed_certificate": 1,
    }


def test_tls_summary_counts_visible_fingerprints():
    layers = [{"name": "Transport Layer Security", "fields": {
        "Version": "TLS 1.3", "Handshake": "Client Hello", "JA3": "a" * 32,
        "Offered Versions": ["TLS 1.3", "TLS 1.2"], "Cipher Suites": ["0x1301"],
    }}]
    result = tls_intelligence([packet("hello", 1.0, proto="TLS", layers=layers)])
    assert result["fingerprints"] == [{"fingerprint": f"ja3:{'a' * 32}", "packets": 1}]
    assert result["events"][0]["offered_versions"] == ["TLS 1.3", "TLS 1.2"]
