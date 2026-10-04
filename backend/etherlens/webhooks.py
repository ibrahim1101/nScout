"""Alert webhook delivery (Slack & Discord compatible)."""
from __future__ import annotations

import asyncio
import json
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


async def send(url: str, threat: Dict) -> Dict:
    if not url:
        return {"ok": False, "error": "empty url"}
    is_discord = "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url
    payload = _discord_payload(threat) if is_discord else _slack_payload(threat)
    try:
        resp = await asyncio.to_thread(
            requests.post, url, json=payload, timeout=5.0,
        )
        return {"ok": resp.status_code < 400, "status": resp.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def fan_out(urls: List[str], threat: Dict) -> None:
    """Fire-and-forget to all configured webhook URLs."""
    if not urls:
        return
    try:
        await asyncio.gather(*(send(u, threat) for u in urls if u), return_exceptions=True)
    except Exception:
        pass
