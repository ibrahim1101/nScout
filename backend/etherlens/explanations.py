"""Deterministic, defensive explanation helpers for reconstructed connections."""
from __future__ import annotations


def explain_connection(connection: dict, dns: dict | None = None, tls: dict | None = None) -> dict:
    """Build a useful connection explanation without inventing unobserved payload data.

    This is intentionally deterministic so Connection Story remains useful when the
    optional AI integration is unavailable. AI may later elaborate on this context,
    but it must preserve the same evidence boundary.
    """
    dns = dns or {}
    tls = tls or {}
    a_ip, b_ip = connection.get("a_ip"), connection.get("b_ip")
    endpoints = {str(x) for x in (a_ip, b_ip) if x}
    related_dns = [
        event for event in dns.get("events", [])
        if str(event.get("src_ip")) in endpoints or str(event.get("dst_ip")) in endpoints
    ]
    related_tls = [
        event for event in tls.get("events", tls.get("connections", []))
        if str(event.get("src_ip")) in endpoints or str(event.get("dst_ip")) in endpoints
    ]
    issues = []
    labels = (
        ("retransmissions", "retransmission"),
        ("duplicate_acks", "duplicate ACK"),
        ("out_of_order", "out-of-order segment"),
        ("zero_windows", "zero-window condition"),
        ("resets", "reset"),
    )
    for key, label in labels:
        count = int(connection.get(key) or 0)
        if count:
            issues.append({"type": key, "count": count, "label": label})

    state = str(connection.get("state") or "unknown")
    protocols = connection.get("protocols") or []
    normal = not issues and state.lower() not in {"failed", "reset", "incomplete"}
    observations = [
        f"Observed {int(connection.get('packets') or 0)} packets across the reconstructed conversation.",
        f"Connection state is {state}.",
    ]
    if protocols:
        observations.append("Observed protocol progression: " + " -> ".join(map(str, protocols)) + ".")
    if related_dns:
        observations.append(f"{len(related_dns)} DNS event(s) correlate with one or both endpoints.")
    if related_tls:
        observations.append(f"{len(related_tls)} TLS/HTTPS metadata event(s) correlate with one or both endpoints.")
    if issues:
        observations.append("TCP health signals require review: " + ", ".join(f"{x['count']} {x['label']}(s)" for x in issues) + ".")

    next_steps = []
    if issues:
        next_steps.append("Inspect the affected packets and TCP Health annotations to distinguish loss, congestion, endpoint resets, or capture artifacts.")
    if related_dns:
        next_steps.append("Review correlated DNS answers, response codes, and TTLs for expected name resolution behavior.")
    if related_tls:
        next_steps.append("Review observable TLS metadata such as SNI, version, ALPN, cipher and certificate warnings; do not infer encrypted application contents.")
    if not next_steps:
        next_steps.append("Compare the endpoints, ports, traffic volume and timing with the expected application behavior if further validation is needed.")

    return {
        "summary": f"Reconstructed connection {a_ip}:{connection.get('a_port')} ↔ {b_ip}:{connection.get('b_port')} ({state}).",
        "assessment": "No TCP-health warning is currently evident from the reconstructed metadata." if normal else "The reconstructed metadata contains conditions worth analyst review; they are not proof of compromise.",
        "appears_normal": normal,
        "observations": observations,
        "tcp_issues": issues,
        "dns_events": len(related_dns),
        "tls_events": len(related_tls),
        "next_steps": next_steps,
        "visibility_note": "Explanation is based only on observed packet and protocol metadata. Encrypted application payload is not decrypted or inferred.",
    }
