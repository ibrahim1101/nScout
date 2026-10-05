"""Portable investigation report exporters for nScout."""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List


def json_report(summary: Dict[str, Any]) -> bytes:
    doc = {"generated_at": datetime.now(timezone.utc).isoformat(), "product": "nScout", "investigation": summary}
    return json.dumps(doc, indent=2, default=str).encode("utf-8")


def html_report(summary: Dict[str, Any]) -> bytes:
    overview = summary.get("overview", {})
    threats = summary.get("threats", [])
    security = summary.get("security", {})
    findings = security.get("findings", [])
    conns = summary.get("connections", [])
    protocols = overview.get("protocols", [])
    def esc(v): return html.escape(str(v if v is not None else ""))
    protocol_rows = "".join(f"<tr><td>{esc(x.get('protocol'))}</td><td>{esc(x.get('packets'))}</td><td>{esc(x.get('percent'))}%</td></tr>" for x in protocols)
    all_findings = findings or threats
    threat_rows = "".join(f"<tr><td>{esc(x.get('severity'))}</td><td>{esc(x.get('type'))}</td><td>{esc(x.get('title') or x.get('detail'))}</td><td>{esc(x.get('src') or x.get('src_ip'))}</td><td>{esc(x.get('dst') or x.get('dst_ip'))}</td></tr>" for x in all_findings[:100]) or "<tr><td colspan='5'>No detected security findings</td></tr>"
    conn_rows = "".join(f"<tr><td>{esc(x.get('a_ip'))}:{esc(x.get('a_port'))}</td><td>{esc(x.get('b_ip'))}:{esc(x.get('b_port'))}</td><td>{esc(x.get('packets'))}</td><td>{esc(x.get('bytes'))}</td><td>{esc(x.get('state'))}</td></tr>" for x in conns[:100])
    body=f"""<!doctype html><html><head><meta charset='utf-8'><title>nScout Investigation Report</title><style>body{{font-family:system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#17202a}}h1,h2{{margin-bottom:8px}}.meta{{color:#667}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{border:1px solid #ccd;padding:12px 18px;border-radius:8px}}table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}th,td{{border-bottom:1px solid #ddd;text-align:left;padding:8px}}th{{background:#f5f6f7}}</style></head><body><h1>nScout Investigation Report</h1><p class='meta'>Generated {esc(datetime.now(timezone.utc).isoformat())}</p><div class='cards'><div class='card'><b>Packets</b><br>{esc(overview.get('total_packets',0))}</div><div class='card'><b>Bytes</b><br>{esc(overview.get('total_bytes',0))}</div><div class='card'><b>Connections</b><br>{len(conns)}</div><div class='card'><b>Security findings</b><br>{len(all_findings)}</div></div><h2>Protocols</h2><table><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr>{protocol_rows}</table><h2>Security Findings</h2><table><tr><th>Severity</th><th>Type</th><th>Finding</th><th>Source</th><th>Destination</th></tr>{threat_rows}</table><h2>Connections</h2><table><tr><th>Endpoint A</th><th>Endpoint B</th><th>Packets</th><th>Bytes</th><th>State</th></tr>{conn_rows}</table><p class='meta'>{esc(security.get('note','Security findings are investigation leads and should be validated with additional evidence.'))}</p></body></html>"""
    return body.encode("utf-8")


def _pdf_escape(value: Any) -> str:
    text = str(value if value is not None else "").encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_lines(summary: Dict[str, Any]) -> List[str]:
    overview = summary.get("overview", {})
    security = summary.get("security", {})
    findings = security.get("findings", []) or summary.get("threats", [])
    lines = [
        "nScout Investigation Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"Packets: {overview.get('total_packets', 0)}    Bytes: {overview.get('total_bytes', 0)}",
        f"Connections: {len(summary.get('connections', []))}    Devices: {len(summary.get('devices', []))}",
        f"Security findings: {len(findings)}",
        "", "Protocol summary",
    ]
    for row in overview.get("protocols", [])[:25]:
        lines.append(f"  {row.get('protocol', 'Unknown')}: {row.get('packets', 0)} packets ({row.get('percent', 0)}%)")
    lines.extend(["", "Security findings"])
    if not findings:
        lines.append("  No detected security findings.")
    for row in findings[:75]:
        detail = row.get("title") or row.get("detail") or row.get("description") or "Finding"
        endpoints = " -> ".join(str(x) for x in (row.get("src") or row.get("src_ip"), row.get("dst") or row.get("dst_ip")) if x)
        lines.append(f"  [{str(row.get('severity', 'info')).upper()}] {row.get('type', 'finding')}: {detail}" + (f" ({endpoints})" if endpoints else ""))
    lines.extend(["", "Top connections"])
    for row in summary.get("connections", [])[:50]:
        lines.append(f"  {row.get('a_ip')}:{row.get('a_port')} <-> {row.get('b_ip')}:{row.get('b_port')}  {row.get('packets', 0)} packets / {row.get('bytes', 0)} bytes  {row.get('state', '')}")
    lines.extend(["", security.get("note", "Security findings are investigation leads and should be validated with additional evidence."), "TLS application payload remains encrypted and is not decrypted by nScout."])
    return lines


def pdf_report(summary: Dict[str, Any]) -> bytes:
    """Build a dependency-free, text-first PDF suitable for portable/desktop builds."""
    raw_lines = _pdf_lines(summary)
    wrapped = []
    for line in raw_lines:
        if len(line) <= 105:
            wrapped.append(line)
        else:
            while len(line) > 105:
                cut = line.rfind(" ", 0, 105)
                if cut < 40: cut = 105
                wrapped.append(line[:cut]); line = "    " + line[cut:].lstrip()
            wrapped.append(line)
    pages = [wrapped[i:i + 48] for i in range(0, len(wrapped), 48)] or [[]]
    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_ids = [4 + i * 2 for i in range(len(pages))]
    objects.append(("<< /Type /Pages /Kids [" + " ".join(f"{i} 0 R" for i in page_ids) + f"] /Count {len(page_ids)} >>").encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    for page_index, lines in enumerate(pages):
        content_id = page_ids[page_index] + 1
        page = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        objects.append(page.encode())
        commands = ["BT", "/F1 9 Tf", "42 750 Td", "12 TL"]
        for idx, line in enumerate(lines):
            if idx: commands.append("T*")
            commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1")
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out)); out.extend(f"{i} 0 obj\n".encode()); out.extend(obj); out.extend(b"\nendobj\n")
    xref = len(out); out.extend(f"xref\n0 {len(objects)+1}\n".encode()); out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]: out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(out)
