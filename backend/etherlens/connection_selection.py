"""Deterministic helpers for resolving reconstructed connections."""
from __future__ import annotations

from typing import Iterable, Optional


def _port(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _traffic_rank(connection: dict) -> tuple[int, int, float, str, int, str, int]:
    """Stable ranking for endpoint-only lookups: busiest conversation first."""
    return (
        int(connection.get("bytes") or connection.get("total_bytes") or 0),
        int(connection.get("packets") or 0),
        float(connection.get("duration") or 0),
        str(connection.get("a_ip") or ""),
        _port(connection.get("a_port")),
        str(connection.get("b_ip") or ""),
        _port(connection.get("b_port")),
    )


def select_connection(
    connections: Iterable[dict],
    a_ip: str,
    b_ip: str,
    a_port: Optional[int] = None,
    b_port: Optional[int] = None,
) -> Optional[dict]:
    """Resolve an endpoint pair or an exact forward/reverse transport 4-tuple.

    When ports are supplied both are required. Exact requests never degrade to
    endpoint-only matching. Endpoint-only requests choose the highest-traffic
    reconstructed conversation deterministically.
    """
    if (a_port is None) != (b_port is None):
        raise ValueError("a_port and b_port must be supplied together")

    a_ip, b_ip = str(a_ip), str(b_ip)
    candidates = [
        c for c in connections
        if {str(c.get("a_ip")), str(c.get("b_ip"))} == {a_ip, b_ip}
    ]
    if not candidates:
        return None

    if a_port is not None:
        ap, bp = int(a_port), int(b_port)
        exact = []
        for c in candidates:
            ca, cb = str(c.get("a_ip")), str(c.get("b_ip"))
            cap, cbp = _port(c.get("a_port")), _port(c.get("b_port"))
            forward = ca == a_ip and cb == b_ip and cap == ap and cbp == bp
            reverse = ca == b_ip and cb == a_ip and cap == bp and cbp == ap
            if forward or reverse:
                exact.append(c)
        if not exact:
            return None
        return max(exact, key=_traffic_rank)

    return max(candidates, key=_traffic_rank)
