"""Alert webhook delivery (Slack & Discord compatible)."""
from __future__ import annotations

import asyncio
import json
import ipaddress
import socket
from urllib.parse import urlsplit
from typing import Dict, List

import requests


SEVERITY_EMOJI = {
    "critical": "🚨",
    "high": "⚠️",
    "medium": "⚡",
    "low": "ℹ️",
}


def _slack_payload(threat: Dict) -> Dict:
    sev = threat.get("severity", "info")
    emoji = SEVERITY_EMOJI.get(sev, "🔔")
    text = (
        f"{emoji} *nScout Alert — {sev.upper()}*\n"
        f"*{threat.get('title', 'Anomaly detected')}*\n"
        f"> {threat.get('description', '')}\n"
        f"`{threat.get('src', '?')}` → `{threat.get('dst', '?')}` · type: `{threat.get('type', '?')}`"
    )
    return {"text": text}


def _discord_payload(threat: Dict) -> Dict:
    sev = threat.get("severity", "info")
    emoji = SEVERITY_EMOJI.get(sev, "🔔")
    color = {"critical": 0xE11D48, "high": 0xF97316, "medium": 0xF59E0B, "low": 0x0EA5E9}.get(sev, 0x3B82F6)
    return {
        "embeds": [{
            "title": f"{emoji} nScout — {sev.upper()}: {threat.get('title', 'Anomaly')}",
            "description": threat.get("description", ""),
            "color": color,
            "fields": [
                {"name": "Source", "value": f"`{threat.get('src', '?')}`", "inline": True},
                {"name": "Destination", "value": f"`{threat.get('dst', '?')}`", "inline": True},
                {"name": "Type", "value": threat.get("type", "?"), "inline": True},
            ],
        }]
    }


def _public_webhook_target(url: str) -> bool:
    """Reject non-HTTPS, credential-bearing, local and private webhook targets."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            return False
        if parsed.port not in (None, 443):
            return False
        hostname = parsed.hostname.rstrip(".").lower()
        if hostname in {"localhost"} or hostname.endswith((".localhost", ".local", ".internal")):
            return False
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)
    except (ValueError, OSError, TypeError):
        return False


async def send(url: str, threat: Dict) -> Dict:
    if not _public_webhook_target(url):
        return {"ok": False, "error": "webhook destination must be a public HTTPS endpoint"}
    is_discord = "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url
    payload = _discord_payload(threat) if is_discord else _slack_payload(threat)
    try:
        resp = await asyncio.to_thread(
            requests.post, url, json=payload, timeout=5.0, allow_redirects=False,
        )
        return {"ok": resp.status_code < 400, "status": resp.status_code}
    except Exception as e:
        # Requests exceptions can embed webhook URLs containing secret tokens.
        return {"ok": False, "error": "Webhook delivery failed; check destination and network connectivity"}


async def fan_out(urls: List[str], threat: Dict) -> None:
    """Fire-and-forget to all configured webhook URLs."""
    if not urls:
        return
    try:
        await asyncio.gather(*(send(u, threat) for u in urls if u), return_exceptions=True)
    except Exception:
        pass
