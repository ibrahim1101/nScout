"""TCP stream reassembly and PCAP export utilities."""
from __future__ import annotations

import io
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import Ether, TCP, IP, IPv6, wrpcap  # type: ignore


def _is_text(buf: bytes) -> bool:
    if not buf:
        return False
    # Printable ratio
    printable = sum(1 for b in buf if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(buf) >= 0.75


def _render_payload(buf: bytes) -> Tuple[str, str]:
    """Return (text_or_hex, mode) where mode is 'text' or 'hex'."""
    if _is_text(buf):
        try:
            return buf.decode("utf-8", errors="replace"), "text"
        except Exception:
            pass
    # Hex dump 16 bytes/line
    lines = []
    for i in range(0, len(buf), 16):
        row = buf[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row).ljust(16 * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in row)
        lines.append(f"{i:04x}  {hex_part}  {ascii_part}")
    return "\n".join(lines), "hex"


def reassemble_stream(packets: List[Dict[str, Any]], flow_key: Tuple[str, str, int, int]) -> Dict[str, Any]:
    """Reassemble a TCP stream by seq order.

    flow_key = (hostA, hostB, portA, portB). Direction A→B or B→A is detected per packet.
    """
    a_host, b_host, a_port, b_port = flow_key
    # Collect packets belonging to the flow (either direction)
    buckets = {"a_to_b": [], "b_to_a": []}
    for p in packets:
        if p.get("protocol") not in ("TCP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "TLS"):
            continue
        if not (p.get("src_ip") and p.get("dst_ip") and p.get("src_port") and p.get("dst_port")):
            continue
        s, d = p["src_ip"], p["dst_ip"]
        sp, dp = p["src_port"], p["dst_port"]
        if s == a_host and d == b_host and sp == a_port and dp == b_port:
            buckets["a_to_b"].append(p)
        elif s == b_host and d == a_host and sp == b_port and dp == a_port:
            buckets["b_to_a"].append(p)

    def _assemble(ps: List[Dict[str, Any]]) -> bytes:
        # Try to extract raw TCP payload from stored hex, order by seq if available.
        chunks = []
        for p in ps:
            try:
                raw = bytes.fromhex(p.get("hex", "") or "")
                pkt = Ether(raw) if raw else None
                if pkt is None or TCP not in pkt:
                    continue
                tcp = pkt[TCP]
                payload = bytes(tcp.payload) if tcp.payload else b""
                if payload:
                    chunks.append((int(tcp.seq or 0), payload, int(p.get("number", 0))))
            except Exception:
                continue
        chunks.sort(key=lambda c: (c[0], c[2]))
        # De-duplicate overlapping seq
        seen = set()
        out = bytearray()
        for seq, payload, _ in chunks:
            if seq in seen:
                continue
            seen.add(seq)
            out.extend(payload)
        return bytes(out)

    a_bytes = _assemble(buckets["a_to_b"])
    b_bytes = _assemble(buckets["b_to_a"])
    a_text, a_mode = _render_payload(a_bytes)
    b_text, b_mode = _render_payload(b_bytes)

    return {
        "flow": {
            "a": {"ip": a_host, "port": a_port},
            "b": {"ip": b_host, "port": b_port},
        },
        "a_to_b": {"bytes": len(a_bytes), "mode": a_mode, "data": a_text, "packets": len(buckets["a_to_b"])},
        "b_to_a": {"bytes": len(b_bytes), "mode": b_mode, "data": b_text, "packets": len(buckets["b_to_a"])},
    }


def export_pcap(packets: List[Dict[str, Any]]) -> bytes:
    """Rebuild scapy packets from stored hex and write to a pcap byte stream."""
    pkts = []
    for p in packets:
        try:
            raw = bytes.fromhex(p.get("hex", "") or "")
            if raw:
                pkts.append(Ether(raw))
        except Exception:
            continue
    if not pkts:
        return b""
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp = f.name
    try:
        wrpcap(tmp, pkts)
        with open(tmp, "rb") as f:
            return f.read()
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def list_flows(packets: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    """Group TCP packets into bidirectional flows."""
    agg: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
    for p in packets:
        if p.get("protocol") not in ("TCP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", "TLS"):
            continue
        s, d = p.get("src_ip"), p.get("dst_ip")
        sp, dp = p.get("src_port"), p.get("dst_port")
        if not (s and d and sp and dp):
            continue
        a, b, ap, bp = (s, d, sp, dp) if (s, sp) <= (d, dp) else (d, s, dp, sp)
        key = (a, b, ap, bp)
        row = agg.get(key)
        if row is None:
            row = {"a_ip": a, "a_port": ap, "b_ip": b, "b_port": bp, "packets": 0, "bytes": 0, "protocols": set(), "last": 0}
            agg[key] = row
        row["packets"] += 1
        row["bytes"] += p.get("length") or 0
        row["protocols"].add(p.get("protocol"))
        row["last"] = max(row["last"], p.get("timestamp") or 0)
    rows = sorted(agg.values(), key=lambda r: r["bytes"], reverse=True)[:limit]
    for r in rows:
        r["protocols"] = sorted(list(r["protocols"]))
    return rows
