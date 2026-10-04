"""Geo-IP + ASN enrichment via free ip-api.com batch endpoint.

- No API key required (45 req/min for free tier).
- Aggressively caches results so each IP is looked up at most once per session.
- Returns an "unknown" record on timeout / rate-limit so the UI stays responsive.
"""
from __future__ import annotations

import asyncio
import ipaddress
from typing import Dict, Iterable, List

import requests


_cache: Dict[str, dict] = {}
_lock = asyncio.Lock()


COUNTRY_FLAG = lambda cc: "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in (cc or "").upper() if "A" <= c <= "Z") or "🌐"  # noqa: E731


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved
    except ValueError:
        return True


def _blank(ip: str, note: str = "") -> dict:
    return {
        "ip": ip, "country": "", "country_code": "",
        "city": "", "region": "", "org": "", "as": "", "asname": "",
        "flag": "🏠" if _is_private(ip) else "🌐",
        "private": _is_private(ip), "note": note,
    }


async def enrich(ips: Iterable[str]) -> Dict[str, dict]:
    """Return {ip: enriched_dict} for the given set of IPs."""
    ips = list({ip for ip in ips if ip})
    if not ips:
        return {}

    async with _lock:
        todo = [ip for ip in ips if ip not in _cache and not _is_private(ip)]
        for ip in ips:
            if _is_private(ip):
                _cache.setdefault(ip, _blank(ip, "private"))

        # Batch requests (ip-api supports up to 100 per call)
        for chunk_start in range(0, len(todo), 90):
            chunk = todo[chunk_start:chunk_start + 90]
            try:
                payload = [{"query": ip, "fields": "status,country,countryCode,regionName,city,org,as,asname,query"} for ip in chunk]
                resp = await asyncio.to_thread(
                    requests.post, "http://ip-api.com/batch", json=payload, timeout=4.5,
                )
                data = resp.json() if resp.ok else []
                for row in data if isinstance(data, list) else []:
                    ip = row.get("query")
                    if not ip:
                        continue
                    if row.get("status") == "success":
                        _cache[ip] = {
                            "ip": ip,
                            "country": row.get("country", ""),
                            "country_code": row.get("countryCode", ""),
                            "city": row.get("city", ""),
                            "region": row.get("regionName", ""),
                            "org": row.get("org", ""),
                            "as": row.get("as", ""),
                            "asname": row.get("asname", ""),
                            "flag": COUNTRY_FLAG(row.get("countryCode", "")),
                            "private": False,
                            "note": "",
                        }
                    else:
                        _cache[ip] = _blank(ip, row.get("message", "lookup failed"))
            except Exception as e:  # pragma: no cover
                for ip in chunk:
                    _cache.setdefault(ip, _blank(ip, f"error: {e.__class__.__name__}"))

    return {ip: _cache.get(ip, _blank(ip)) for ip in ips}


async def enrich_one(ip: str) -> dict:
    out = await enrich([ip])
    return out.get(ip, _blank(ip))
