"""Bounded, privacy-conscious search across live and saved investigation data."""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Sequence

MAX_QUERY_LENGTH = 200
MAX_RESULTS = 100
MAX_SOURCE_ITEMS = 5000


def _text(*values: Any) -> str:
    parts: List[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            parts.extend(str(item) for item in value if item is not None)
        elif isinstance(value, Mapping):
            # Search only one level of small display metadata. Callers select
            # which mappings are supplied, so packet layers/payload never enter.
            parts.extend(str(item) for item in value.values() if not isinstance(item, (dict, list)))
        else:
            parts.append(str(value))
    return " ".join(parts).strip()


def _score(query: str, title: str, searchable: str) -> int:
    q = query.casefold()
    title_folded = title.casefold()
    haystack = searchable.casefold()
    if q not in haystack:
        return 0
    if title_folded == q:
        return 400
    if title_folded.startswith(q):
        return 300
    if q in title_folded:
        return 200
    return 100


def _result(kind: str, item_id: Any, title: str, subtitle: str, timestamp: Any,
            target: Dict[str, Any], query: str, searchable: str) -> Dict[str, Any] | None:
    score = _score(query, title, searchable)
    if not score:
        return None
    return {
        "id": f"{kind}:{item_id}",
        "type": kind,
        "title": title,
        "subtitle": subtitle,
        "timestamp": timestamp,
        "target": target,
        "score": score,
    }


def search_investigation_data(
    query: str,
    *,
    packets: Sequence[Mapping[str, Any]] = (),
    hosts: Sequence[Mapping[str, Any]] = (),
    connections: Sequence[Mapping[str, Any]] = (),
    dns_events: Sequence[Mapping[str, Any]] = (),
    findings: Sequence[Mapping[str, Any]] = (),
    timeline: Sequence[Mapping[str, Any]] = (),
    investigations: Sequence[Mapping[str, Any]] = (),
    limit: int = 50,
) -> Dict[str, Any]:
    """Search bounded metadata and return navigable, category-labelled results.

    Raw packet layers, payload, ASCII and hex fields are intentionally excluded.
    Saved investigation snapshots are likewise not indexed; only evidence labels,
    references and analyst notes are searchable.
    """
    query = str(query or "").strip()
    if len(query) < 2:
        raise ValueError("Search query must contain at least 2 characters")
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"Search query must not exceed {MAX_QUERY_LENGTH} characters")
    limit = max(1, min(int(limit), MAX_RESULTS))
    results: List[Dict[str, Any]] = []

    def add(candidate: Dict[str, Any] | None) -> None:
        if candidate is not None:
            results.append(candidate)

    for packet in packets[:MAX_SOURCE_ITEMS]:
        packet_id = packet.get("id") or packet.get("number") or "unknown"
        title = f"Packet #{packet.get('number', packet_id)} · {packet.get('protocol') or 'Unknown'}"
        subtitle = _text(packet.get("src_ip"), "→", packet.get("dst_ip"), packet.get("info"))
        searchable = _text(title, subtitle, packet.get("src_port"), packet.get("dst_port"), packet.get("flags"))
        add(_result("packet", packet_id, title, subtitle, packet.get("timestamp"),
                    {"packet_id": str(packet_id)}, query, searchable))

    for host in hosts[:MAX_SOURCE_ITEMS]:
        ip = str(host.get("ip") or "unknown")
        alias = host.get("alias") or host.get("hostname") or ""
        title = f"{alias} ({ip})" if alias else ip
        services = [f"{service.get('port')}/{service.get('protocol', '')}" for service in (host.get("services") or []) if isinstance(service, Mapping)]
        domains = [domain.get("domain") for domain in (host.get("domains") or []) if isinstance(domain, Mapping)]
        subtitle = _text(host.get("hostname"), host.get("mac"), host.get("vendor"), services)
        searchable = _text(title, subtitle, domains, host.get("protocols"), host.get("watchlisted"), host.get("risk"))
        add(_result("host", ip, title, subtitle, host.get("last_seen"),
                    {"host_ip": ip}, query, searchable))

    for index, connection in enumerate(connections[:MAX_SOURCE_ITEMS]):
        a = f"{connection.get('a_ip', '')}:{connection.get('a_port', 0)}"
        b = f"{connection.get('b_ip', '')}:{connection.get('b_port', 0)}"
        title = f"{a} ↔ {b}"
        subtitle = _text(connection.get("protocols"), connection.get("state"), f"{connection.get('packets', 0)} packets")
        add(_result("connection", index, title, subtitle, connection.get("last_seen"),
                    {"connection": dict(connection)}, query, _text(title, subtitle)))

    for index, event in enumerate(dns_events[:MAX_SOURCE_ITEMS]):
        title = str(event.get("query") or "DNS event")
        answers = [answer.get("value", answer) if isinstance(answer, Mapping) else answer for answer in (event.get("answers") or [])]
        subtitle = _text(event.get("src_ip"), "→", event.get("dst_ip"), answers, event.get("response_code"))
        add(_result("dns", event.get("packet_id") or index, title, subtitle, event.get("timestamp"),
                    {"packet_id": event.get("packet_id"), "domain": event.get("query")}, query, _text(title, subtitle)))

    for index, finding in enumerate(findings[:MAX_SOURCE_ITEMS]):
        finding_id = finding.get("id") or finding.get("finding_id") or index
        title = str(finding.get("title") or finding.get("type") or "Security finding")
        subtitle = _text(finding.get("description"), finding.get("detail"), finding.get("severity"), finding.get("src_ip"), finding.get("dst_ip"))
        add(_result("finding", finding_id, title, subtitle, finding.get("timestamp"),
                    {"finding_id": str(finding_id), "packet_id": finding.get("packet_id")}, query, _text(title, subtitle)))

    for index, event in enumerate(timeline[:MAX_SOURCE_ITEMS]):
        event_id = event.get("id") or index
        title = str(event.get("title") or event.get("type") or event.get("event") or "Timeline event")
        subtitle = _text(event.get("description"), event.get("detail"), event.get("summary"), event.get("host"), event.get("domain"), event.get("protocol"))
        add(_result("timeline", event_id, title, subtitle, event.get("timestamp"),
                    {"packet_id": event.get("packet_id"), "host_ip": event.get("host")}, query, _text(title, subtitle)))

    for investigation in investigations[:500]:
        investigation_id = str(investigation.get("id") or "")
        case_title = str(investigation.get("name") or "Untitled investigation")
        case_subtitle = str(investigation.get("description") or "Saved investigation")
        add(_result("investigation", investigation_id, case_title, case_subtitle, investigation.get("updated_at"),
                    {"investigation_id": investigation_id}, query, _text(case_title, case_subtitle)))
        for note in (investigation.get("notes") or [])[:1000]:
            note_id = note.get("id") or len(results)
            note_text = str(note.get("text") or "")
            add(_result("note", note_id, f"Note in {case_title}", note_text, note.get("created_at"),
                        {"investigation_id": investigation_id, "note_id": str(note_id)}, query,
                        _text(case_title, note_text, note.get("author"))))
        for evidence in (investigation.get("evidence") or [])[:1000]:
            evidence_id = evidence.get("id") or len(results)
            evidence_title = str(evidence.get("title") or evidence.get("ref_id") or "Evidence")
            evidence_subtitle = _text(evidence.get("type"), evidence.get("ref_id"), evidence.get("note"), f"in {case_title}")
            add(_result("evidence", evidence_id, evidence_title, evidence_subtitle, evidence.get("created_at"),
                        {"investigation_id": investigation_id, "evidence_id": str(evidence_id),
                         "evidence_type": evidence.get("type"), "ref_id": evidence.get("ref_id")},
                        query, _text(evidence_title, evidence_subtitle, case_title)))

    results.sort(key=lambda item: (item["score"], str(item.get("timestamp") or "")), reverse=True)
    total = len(results)
    visible = results[:limit]
    counts = Counter(item["type"] for item in visible)
    return {"query": query, "count": len(visible), "total_matches": total,
            "truncated": total > len(visible), "categories": dict(sorted(counts.items())),
            "results": visible}
