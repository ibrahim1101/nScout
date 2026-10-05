"""Portable investigation report exporters for nScout."""
from __future__ import annotations
import html
import json
from datetime import datetime, timezone
from typing import Any, Dict


def json_report(summary: Dict[str, Any]) -> bytes:
    doc = {"generated_at": datetime.now(timezone.utc).isoformat(), "product": "nScout", "investigation": summary}
    return json.dumps(doc, indent=2, default=str).encode("utf-8")


def html_report(summary: Dict[str, Any]) -> bytes:
    overview = summary.get("overview", {})
    threats = summary.get("threats", [])
    conns = summary.get("connections", [])
    protocols = overview.get("protocols", [])
    def esc(v): return html.escape(str(v if v is not None else ""))
    protocol_rows = "".join(f"<tr><td>{esc(x.get('protocol'))}</td><td>{esc(x.get('packets'))}</td><td>{esc(x.get('percent'))}%</td></tr>" for x in protocols)
    threat_rows = "".join(f"<tr><td>{esc(x.get('severity'))}</td><td>{esc(x.get('type'))}</td><td>{esc(x.get('title'))}</td><td>{esc(x.get('src'))}</td><td>{esc(x.get('dst'))}</td></tr>" for x in threats[:100]) or "<tr><td colspan='5'>No detected threats</td></tr>"
    conn_rows = "".join(f"<tr><td>{esc(x.get('a_ip'))}:{esc(x.get('a_port'))}</td><td>{esc(x.get('b_ip'))}:{esc(x.get('b_port'))}</td><td>{esc(x.get('packets'))}</td><td>{esc(x.get('bytes'))}</td><td>{esc(x.get('state'))}</td></tr>" for x in conns[:100])
    body=f"""<!doctype html><html><head><meta charset='utf-8'><title>nScout Investigation Report</title><style>body{{font-family:system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#17202a}}h1,h2{{margin-bottom:8px}}.meta{{color:#667}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{border:1px solid #ccd;padding:12px 18px;border-radius:8px}}table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}th,td{{border-bottom:1px solid #ddd;text-align:left;padding:8px}}th{{background:#f5f6f7}}</style></head><body><h1>nScout Investigation Report</h1><p class='meta'>Generated {esc(datetime.now(timezone.utc).isoformat())}</p><div class='cards'><div class='card'><b>Packets</b><br>{esc(overview.get('total_packets',0))}</div><div class='card'><b>Bytes</b><br>{esc(overview.get('total_bytes',0))}</div><div class='card'><b>Connections</b><br>{len(conns)}</div><div class='card'><b>Threats</b><br>{len(threats)}</div></div><h2>Protocols</h2><table><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr>{protocol_rows}</table><h2>Security Findings</h2><table><tr><th>Severity</th><th>Type</th><th>Finding</th><th>Source</th><th>Destination</th></tr>{threat_rows}</table><h2>Connections</h2><table><tr><th>Endpoint A</th><th>Endpoint B</th><th>Packets</th><th>Bytes</th><th>State</th></tr>{conn_rows}</table></body></html>"""
    return body.encode("utf-8")
