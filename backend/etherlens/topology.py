"""Bounded investigation topology built from host and connection intelligence."""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Any, Dict, Iterable, List

MAX_EDGE_CONNECTIONS = 25


def _integer(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _pair(left: str, right: str) -> tuple[str, str]:
    return tuple(sorted((str(left or ""), str(right or ""))))


def build_topology(hosts: Iterable[Dict[str, Any]], connections: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Create searchable host nodes and IP-pair edges with bounded flow details."""
    nodes = []
    known = set()
    for source in hosts:
        host = deepcopy(source)
        host_id = str(host.get("ip") or "")
        if not host_id or host_id in known:
            continue
        known.add(host_id)
        ports = {_integer(item.get("port")) for item in host.get("services") or [] if isinstance(item, dict)}
        for peer in host.get("connections") or []:
            if isinstance(peer, dict):
                ports.update(_integer(value) for value in peer.get("ports") or [])
        ports.discard(0)
        nodes.append({
            "id": host_id, "type": "local" if host.get("is_local") else "external",
            "packets": _integer(host.get("total_packets")), "bytes": _integer(host.get("total_bytes")),
            "ports": sorted(ports)[:50], "protocols": list(host.get("protocols") or [])[:50],
            "hostname": str(host.get("hostname") or ""), "mac": str(host.get("mac") or ""),
            "alias": str(host.get("alias") or ""), "watchlisted": bool(host.get("watchlisted")),
            "activity_state": str(host.get("activity_state") or ""),
            "first_seen": host.get("first_seen"), "last_seen": host.get("last_seen"),
            "risk": deepcopy(host.get("risk") or {"score": 0, "level": "none"}),
            "finding_count": _integer(host.get("finding_count")),
            "domains": [str(item.get("domain") or "") for item in (host.get("domains") or [])
                        if isinstance(item, dict) and item.get("domain")][:25],
        })

    grouped: Dict[tuple[str, str], Dict[str, Any]] = {}
    for source in connections:
        left, right = _pair(source.get("a_ip"), source.get("b_ip"))
        if not left or not right:
            continue
        edge = grouped.setdefault((left, right), {
            "source": left, "target": right, "packets": 0, "bytes": 0,
            "protocols": set(), "first_seen": None, "last_seen": None,
            "tcp_health": defaultdict(int), "connections": [],
        })
        edge["packets"] += _integer(source.get("packets")); edge["bytes"] += _integer(source.get("bytes"))
        edge["protocols"].update(str(value) for value in source.get("protocols") or [] if str(value))
        first, last = source.get("first_seen"), source.get("last_seen")
        if first is not None: edge["first_seen"] = first if edge["first_seen"] is None else min(edge["first_seen"], first)
        if last is not None: edge["last_seen"] = last if edge["last_seen"] is None else max(edge["last_seen"], last)
        for field in ("retransmissions", "duplicate_acks", "out_of_order", "zero_windows", "resets"):
            edge["tcp_health"][field] += _integer(source.get(field))
        detail = {key: deepcopy(source.get(key)) for key in (
            "a_ip", "a_port", "b_ip", "b_port", "packets", "bytes", "protocols", "state",
            "duration_ms", "retransmissions", "duplicate_acks", "out_of_order", "zero_windows", "resets",
        )}
        edge["connections"].append(detail)

    edges: List[Dict[str, Any]] = []
    for edge in grouped.values():
        edge["protocols"] = sorted(edge["protocols"])
        edge["tcp_health"] = dict(edge["tcp_health"])
        ordered = sorted(edge["connections"], key=lambda item: (_integer(item.get("bytes")), _integer(item.get("packets"))), reverse=True)
        edge["connection_count"] = len(ordered)
        edge["connections_truncated"] = len(ordered) > MAX_EDGE_CONNECTIONS
        edge["connections"] = ordered[:MAX_EDGE_CONNECTIONS]
        if edge["connection_count"] == 1:
            only = edge["connections"][0]
            edge.update({"source_port": only.get("a_port") if only.get("a_ip") == edge["source"] else only.get("b_port"),
                         "target_port": only.get("b_port") if only.get("b_ip") == edge["target"] else only.get("a_port")})
        edges.append(edge)
    nodes.sort(key=lambda item: (bool(item["watchlisted"]), _integer((item.get("risk") or {}).get("score")), item["bytes"]), reverse=True)
    edges.sort(key=lambda item: (item["bytes"], item["packets"]), reverse=True)
    return {"nodes": nodes, "edges": edges,
            "summary": {"hosts": len(nodes), "connections": sum(edge["connection_count"] for edge in edges),
                        "host_pairs": len(edges), "watchlisted_hosts": sum(bool(node["watchlisted"]) for node in nodes),
                        "flagged_hosts": sum(_integer((node.get("risk") or {}).get("score")) > 0 for node in nodes)}}
