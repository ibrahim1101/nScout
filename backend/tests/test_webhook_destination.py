"""Regression coverage for outbound webhook destination validation."""
from unittest.mock import patch

from etherlens.webhooks import _public_webhook_target


def test_webhook_rejects_local_and_unsafe_urls():
    for url in (
        "http://hooks.slack.com/services/example",
        "https://localhost/hook",
        "https://127.0.0.1/hook",
        "https://10.0.0.2/hook",
        "https://[::1]/hook",
        "https://user:pass@hooks.slack.com/hook",
        "https://hooks.slack.com:8443/hook",
        "file:///etc/passwd",
        "https://internal.local/hook",
    ):
        assert not _public_webhook_target(url)


def test_webhook_rejects_private_dns_answers():
    fake = [(2, 1, 6, "", ("10.1.2.3", 443))]
    with patch("etherlens.webhooks.socket.getaddrinfo", return_value=fake):
        assert not _public_webhook_target("https://hooks.example.com/alert")


def test_webhook_accepts_public_https_dns_answers():
    fake = [(2, 1, 6, "", ("8.8.8.8", 443))]
    with patch("etherlens.webhooks.socket.getaddrinfo", return_value=fake):
        assert _public_webhook_target("https://hooks.example.com/alert")


def test_delivery_failure_does_not_expose_webhook_secret():
    import asyncio
    import requests
    from etherlens.webhooks import send

    secret_url = "https://hooks.example.com/services/sensitive-token"
    fake = [(2, 1, 6, "", ("8.8.8.8", 443))]
    with patch("etherlens.webhooks.socket.getaddrinfo", return_value=fake), \\
         patch("etherlens.webhooks.requests.post", side_effect=requests.ConnectionError(secret_url)):
        result = asyncio.run(send(secret_url, {"severity": "high", "title": "Test"}))
    assert result["ok"] is False
    assert "sensitive-token" not in result["error"]
    assert secret_url not in result["error"]
