"""Safe analyst-friendly packet query language used by nScout.

Examples::

    protocol == dns AND domain contains example.com
    (port == 443 OR port == 8443) AND NOT tcp.reset
    ip:10.0.0.5 bytes>1000
    severity >= high

Whitespace between legacy predicates remains an implicit ``AND``. Expressions
are parsed without ``eval`` and malformed input raises :class:`FilterSyntaxError`.
"""
from __future__ import annotations

import shlex
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Sequence, Tuple


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
COMPARISON_OPERATORS = {"==", "=", "!=", ">", ">=", "<", "<=", "contains"}
BOOLEAN_OPERATORS = {"AND", "OR", "NOT"}


class FilterSyntaxError(ValueError):
    """Raised when an advanced filter cannot be parsed safely."""


def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()):
            return layer.get("fields", {}) or {}
    return {}


def _contains(value: Any, needle: str) -> bool:
    return needle.lower() in str(value or "").lower()


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(actual: Any, operator: str, expected: str, severity: bool = False) -> bool:
    if severity:
        a = SEVERITY_RANK.get(str(actual or "info").lower(), -1)
        b = SEVERITY_RANK.get(expected.lower(), -1)
        if b < 0:
            return False
    else:
        a, b = _number(actual), _number(expected)
    if operator in (">", ">=", "<", "<=") and a is not None and b is not None:
        return {">": a > b, ">=": a >= b, "<": a < b, "<=": a <= b}[operator]
    left, right = str(actual or "").lower(), expected.lower()
    if operator == "contains":
        return right in left
    equal = left == right
    return not equal if operator == "!=" else equal


def _finding_severity(packet: Dict[str, Any], findings: Dict[str, List[Dict[str, Any]]]) -> str:
    rows = findings.get(str(packet.get("id")), [])
    return max((str(row.get("severity") or "info").lower() for row in rows),
               key=lambda value: SEVERITY_RANK.get(value, -1), default="info")


def _field_values(packet: Dict[str, Any], field: str, health: Dict[str, Any],
                  findings: Dict[str, List[Dict[str, Any]]]) -> Tuple[List[Any], bool]:
    field = field.lower()
    dns = _layer(packet, "Domain Name System")
    http = _layer(packet, "Hypertext Transfer Protocol")
    tls = _layer(packet, "Transport Layer Security")
    mapping = {
        "protocol": [packet.get("protocol")], "src": [packet.get("src_ip")],
        "src_ip": [packet.get("src_ip")], "dst": [packet.get("dst_ip")],
        "dst_ip": [packet.get("dst_ip")], "ip": [packet.get("src_ip"), packet.get("dst_ip")],
        "port": [packet.get("src_port"), packet.get("dst_port")], "srcport": [packet.get("src_port")],
        "src_port": [packet.get("src_port")], "dstport": [packet.get("dst_port")],
        "dst_port": [packet.get("dst_port")], "bytes": [packet.get("length")],
        "length": [packet.get("length")], "info": [packet.get("info")], "flags": [packet.get("flags")],
        "domain": [dns.get("Query"), http.get("Host"), tls.get("SNI") or tls.get("Server Name")],
        "dns.query": [dns.get("Query")], "dns.rcode": [dns.get("Response Code")],
        "http.host": [http.get("Host")], "http.method": [http.get("Method")],
        "http.status": [http.get("Status") or http.get("Status Code")],
        "tls.sni": [tls.get("SNI") or tls.get("Server Name")],
        "severity": [_finding_severity(packet, findings)],
    }
    if field.startswith("tcp."):
        events = {str(value).lower() for value in health.get(str(packet.get("id")), {}).get("events", [])}
        return [field in events], False
    return mapping.get(field, []), field == "severity"


def _legacy_predicate(packet: Dict[str, Any], token: str, health: Dict[str, Any],
                      findings: Dict[str, List[Dict[str, Any]]]) -> bool:
    low = token.lower()
    if low.startswith("!") and len(low) > 1:
        return not _legacy_predicate(packet, token[1:], health, findings)
    for field in ("protocol", "src", "dst", "ip", "port", "info", "dns.query", "dns.rcode",
                  "http.host", "http.method", "http.status", "tls.sni", "severity"):
        prefix = field + ":"
        if low.startswith(prefix):
            values, severity = _field_values(packet, field, health, findings)
            expected = token[len(prefix):]
            operator = "==" if field in {"ip", "port", "dns.rcode", "http.method", "severity"} else "contains"
            return any(_compare(value, operator, expected, severity) for value in values)
    for field in ("bytes", "length", "srcport", "dstport"):
        for operator in (">=", "<=", "!=", "==", ">", "<", "="):
            prefix = field + operator
            if low.startswith(prefix):
                values, _ = _field_values(packet, field, health, findings)
                return any(_compare(value, operator, token[len(prefix):]) for value in values)
    if low.startswith("tcp."):
        values, _ = _field_values(packet, low, health, findings)
        return bool(values and values[0])
    return any(_contains(packet.get(key), token) for key in ("protocol", "src_ip", "dst_ip", "info", "flags"))


def _tokenize(expression: str) -> List[str]:
    lexer = shlex.shlex(expression or "", posix=True, punctuation_chars="()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        raw = list(lexer)
    except ValueError as exc:
        raise FilterSyntaxError(str(exc)) from exc
    combined: List[str] = []
    index = 0
    while index < len(raw):
        token = raw[index]
        if index + 2 < len(raw) and raw[index + 1].lower() in COMPARISON_OPERATORS:
            if token in ("(", ")") or raw[index + 2] in ("(", ")"):
                raise FilterSyntaxError("A comparison requires a field and value")
            combined.append("\x1f".join((token, raw[index + 1].lower(), raw[index + 2])))
            index += 3
        else:
            combined.append(token)
            index += 1
    return combined


class _Parser:
    def __init__(self, tokens: Sequence[str]):
        self.tokens = list(tokens)
        self.index = 0

    def peek(self) -> str:
        return self.tokens[self.index] if self.index < len(self.tokens) else ""

    def take(self) -> str:
        token = self.peek()
        if token:
            self.index += 1
        return token

    def parse(self):
        if not self.tokens:
            return ("true",)
        node = self.parse_or()
        if self.peek():
            raise FilterSyntaxError(f"Unexpected token: {self.peek()}")
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek().upper() == "OR":
            self.take(); node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek() and self.peek() != ")" and self.peek().upper() != "OR":
            if self.peek().upper() == "AND":
                self.take()
                if not self.peek() or self.peek() == ")":
                    raise FilterSyntaxError("AND requires a following expression")
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if self.peek().upper() == "NOT":
            self.take()
            if not self.peek():
                raise FilterSyntaxError("NOT requires a following expression")
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self):
        token = self.take()
        if not token:
            raise FilterSyntaxError("Expected an expression")
        if token == "(":
            node = self.parse_or()
            if self.take() != ")":
                raise FilterSyntaxError("Missing closing parenthesis")
            return node
        if token == ")" or token.upper() in BOOLEAN_OPERATORS or token.lower() in COMPARISON_OPERATORS:
            raise FilterSyntaxError(f"Unexpected token: {token}")
        if "\x1f" in token:
            field, operator, expected = token.split("\x1f", 2)
            return ("comparison", field, operator, expected)
        return ("predicate", token)


def parse_filter(expression: str):
    """Parse and return an immutable filter AST."""
    return _Parser(_tokenize(expression)).parse()


def _evaluate(node, packet: Dict[str, Any], health: Dict[str, Any],
              findings: Dict[str, List[Dict[str, Any]]]) -> bool:
    kind = node[0]
    if kind == "true": return True
    if kind == "and": return _evaluate(node[1], packet, health, findings) and _evaluate(node[2], packet, health, findings)
    if kind == "or": return _evaluate(node[1], packet, health, findings) or _evaluate(node[2], packet, health, findings)
    if kind == "not": return not _evaluate(node[1], packet, health, findings)
    if kind == "predicate": return _legacy_predicate(packet, node[1], health, findings)
    _, field, operator, expected = node
    values, severity = _field_values(packet, field, health, findings)
    if not values:
        return False
    if field.lower().startswith("tcp."):
        desired = expected.lower() not in {"false", "0", "no"}
        matched = bool(values[0]) == desired
        return not matched if operator == "!=" else matched
    return any(_compare(value, operator, expected, severity) for value in values)


def validate_filter(expression: str) -> Dict[str, Any]:
    ast = parse_filter(expression)
    return {"valid": True, "tokens": len(_tokenize(expression)), "ast": ast[0]}


def filter_packets(packets: Iterable[Dict[str, Any]], expression: str,
                   health: Dict[str, Any] | None = None, findings: Iterable[Dict[str, Any]] | None = None,
                   limit: int = 500) -> List[Dict[str, Any]]:
    """Filter packets with boolean logic, comparisons, parentheses and legacy predicates."""
    ast = parse_filter(expression)
    health = health or {}
    findings_by_packet: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in findings or []:
        findings_by_packet[str(finding.get("packet_id"))].append(finding)
    out = []
    for packet in packets:
        if _evaluate(ast, packet, health, findings_by_packet):
            out.append(packet)
            if len(out) >= max(1, min(int(limit), 5000)):
                break
    return out
