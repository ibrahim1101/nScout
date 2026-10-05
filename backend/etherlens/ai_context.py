"""Bounded, defensive context builders for nScout AI explanations."""
from __future__ import annotations

import json
from typing import Iterable

from etherlens.explanations import explain_connection


def _belongs(packet: dict, connection: dict) -> bool:
    a_ip, b_ip = str(connection.get("a_ip")), str(connection.get("b_ip"))
    src, dst = str(packet.get("src_ip")), str(packet.get("dst_ip"))
    if not ((src == a_ip and dst == b_ip) or (src == b_ip and dst == a_ip)):
        return False
    a_port, b_port = connection.get("a_port"), connection.get("b_port")
    if a_port is None or b_port is None:
        return True
    sp, dp = packet.get("src_port"), packet.get("dst_port")
    try:
        ap, bp, sp, dp = int(a_port), int(b_port), int(sp), int(dp)
    except (TypeError, ValueError):
        return False
    return (src == a_ip and sp == ap and dp == bp) or (src == b_ip and sp == bp and dp == ap)


def connection_context(
    connection: dict,
    packets: Iterable[dict],
    dns: dict,
    http: dict,
    tls: dict,
    tcp_health: dict,
    security_findings: Iterable[dict] = (),
    packet_limit: int = 40,
) -> dict:
    """Build evidence-only context for one reconstructed connection.

    Payload is intentionally bounded and never represents encrypted application
    contents as visible evidence.
    """
    related = [p for p in packets if _belongs(p, connection)]
    related_ids = {str(p.get("id")) for p in related if p.get("id") is not None}
    endpoints = {str(connection.get("a_ip")), str(connection.get("b_ip"))}

    def endpoint_event(event: dict) -> bool:
        return str(event.get("src_ip")) in endpoints or str(event.get("dst_ip")) in endpoints

    def finding_matches(finding: dict) -> bool:
        values = {str(finding.get(k)) for k in ("src", "dst", "src_ip", "dst_ip") if finding.get(k) is not None}
        return bool(values & endpoints)

    health = {pid: value for pid, value in (tcp_health or {}).items() if str(pid) in related_ids}
    dns_events = [e for e in (dns or {}).get("events", []) if endpoint_event(e)][:30]
    http_events = [e for e in (http or {}).get("events", []) if endpoint_event(e)][:30]
    tls_events = [e for e in (tls or {}).get("events", (tls or {}).get("connections", [])) if endpoint_event(e)][:30]
    findings = [f for f in security_findings if finding_matches(f)][:20]

    return {
        "connection": connection,
        "deterministic_explanation": explain_connection(connection, {"events": dns_events}, {"events": tls_events}),
        "packets": related[:max(1, min(int(packet_limit), 100))],
        "tcp_health": health,
        "dns": {"events": dns_events},
        "http": {"events": http_events, "visibility": "Only unencrypted HTTP metadata/content observed by capture may be represented."},
        "tls": {"events": tls_events, "visibility": "TLS metadata only; encrypted application payload is not decrypted or inferred."},
        "security_findings": findings,
        "visibility_note": "Use only observed capture evidence. Never infer or claim encrypted application payload contents.",
    }


def connection_prompt(context: dict, max_chars: int = 12000) -> str:
    instruction = (
        "You are nScout, a senior defensive network investigator. Explain this reconstructed connection: "
        "what happened, relevant DNS/TCP/HTTP/TLS context, whether the observed metadata appears normal, "
        "security findings that deserve review, and concrete next investigation steps. Distinguish evidence "
        "from uncertainty. Never claim to decrypt, see, or infer encrypted application payload contents.\n\nContext: "
    )
    budget = max(1000, int(max_chars) - len(instruction))
    return instruction + json.dumps(context, default=str)[:budget]
