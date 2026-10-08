"""Portable, dependency-free Investigation Report 2.0 exporters for nScout."""
from __future__ import annotations

import csv
import html
import io
import json
import re
import zipfile
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

REPORT_COLUMNS = ["section", "timestamp", "severity", "title", "source", "destination", "protocol", "details"]
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")


class _Redactor:
    def __init__(self) -> None:
        self.maps = {"host": {}, "mac": {}, "domain": {}}

    def _label(self, kind: str, value: str) -> str:
        values = self.maps[kind]
        if value not in values:
            values[value] = f"{kind}-{len(values) + 1:03d}" + (".invalid" if kind == "domain" else "")
        return values[value]

    def text(self, value: Any) -> str:
        text = str(value if value is not None else "")
        text = MAC_RE.sub(lambda match: self._label("mac", match.group(0).lower()), text)
        text = IPV4_RE.sub(lambda match: self._label("host", match.group(0)), text)
        return DOMAIN_RE.sub(lambda match: self._label("domain", match.group(0).lower()), text)

    def walk(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.walk(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.walk(item) for item in value]
        return self.text(value) if isinstance(value, str) else value


def _case_document(workspace: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not workspace:
        return None
    # Evidence snapshots may contain raw packets, layers, payload and hex.
    # Reports retain references and analyst context, never snapshot bodies.
    evidence = [{key: item.get(key) for key in ("id", "type", "ref_id", "title", "note", "created_at")}
                for item in (workspace.get("evidence") or [])]
    return {
        "id": workspace.get("id"), "name": workspace.get("name"),
        "description": workspace.get("description"), "created_at": workspace.get("created_at"),
        "updated_at": workspace.get("updated_at"), "evidence": evidence,
        "notes": list(workspace.get("notes") or []),
        "finding_states": dict(workspace.get("finding_states") or {}),
    }


def report_document(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
                    redact: bool = False) -> Dict[str, Any]:
    document = {
        "schema": "nscout.investigation-report.v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "product": "nScout", "redacted": bool(redact),
        "case": _case_document(workspace), "investigation": deepcopy(summary),
        "limitations": [
            "Findings are investigation leads and require analyst validation.",
            "Encrypted application payload is not decrypted by nScout.",
            "Evidence snapshot bodies and packet payloads are not embedded in this report.",
        ],
    }
    if redact:
        redactor = _Redactor()
        document["case"] = redactor.walk(document["case"])
        document["investigation"] = redactor.walk(document["investigation"])
        document["redaction"] = {
            "method": "deterministic report-local aliases",
            "host_count": len(redactor.maps["host"]), "mac_count": len(redactor.maps["mac"]),
            "domain_count": len(redactor.maps["domain"]),
        }
    return document


def json_report(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
                redact: bool = False) -> bytes:
    return json.dumps(report_document(summary, workspace, redact), indent=2, default=str).encode("utf-8")


def _findings(report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    return list((report.get("security") or {}).get("findings") or report.get("threats") or [])


def _report_rows(document: Mapping[str, Any]) -> List[Dict[str, Any]]:
    report = document.get("investigation") or {}
    overview = report.get("overview") or {}
    rows: List[Dict[str, Any]] = []

    def add(section: str, **values: Any) -> None:
        row = {column: "" for column in REPORT_COLUMNS}
        row["section"] = section
        row.update({key: value for key, value in values.items() if key in row})
        rows.append(row)

    for key in ("total_packets", "total_bytes"):
        add("overview", title=key.replace("_", " ").title(), details=overview.get(key, 0))
    for item in overview.get("protocols") or []:
        add("protocol", title=item.get("protocol"), protocol=item.get("protocol"),
            details=f"{item.get('packets', 0)} packets ({item.get('percent', 0)}%)")
    for item in report.get("connections") or []:
        add("connection", timestamp=item.get("last_seen"), title="Reconstructed connection",
            source=f"{item.get('a_ip', '')}:{item.get('a_port', '')}",
            destination=f"{item.get('b_ip', '')}:{item.get('b_port', '')}",
            protocol=", ".join(str(value) for value in (item.get("protocols") or [])),
            details=f"{item.get('packets', 0)} packets; {item.get('bytes', 0)} bytes; state {item.get('state', 'observed')}")
    for item in report.get("hosts") or report.get("devices") or []:
        risk = item.get("risk") or {}
        add("host", timestamp=item.get("last_seen"), severity=risk.get("level"),
            title=item.get("alias") or item.get("hostname") or item.get("ip"), source=item.get("ip"),
            protocol=", ".join(str(value) for value in (item.get("protocols") or [])),
            details=f"MAC {item.get('mac') or 'unknown'}; risk {risk.get('score', 0)}; {item.get('total_bytes', 0)} bytes")
    for item in _findings(report):
        add("finding", timestamp=item.get("timestamp"), severity=item.get("severity"),
            title=item.get("title") or item.get("type") or "Security finding",
            source=item.get("src") or item.get("src_ip"), destination=item.get("dst") or item.get("dst_ip"),
            protocol=item.get("protocol"), details=item.get("description") or item.get("detail") or item.get("evidence"))
    timeline = report.get("investigation_timeline") or report.get("timeline") or {}
    timeline_items = timeline.get("events") if isinstance(timeline, Mapping) else timeline
    for item in timeline_items or []:
        add("timeline", timestamp=item.get("timestamp"), severity=item.get("severity"),
            title=item.get("title") or item.get("event_type"), source=item.get("src_ip"),
            destination=item.get("dst_ip"), protocol=item.get("protocol") or item.get("category"),
            details=item.get("detail") or item.get("domain"))
    case = document.get("case") or {}
    if case:
        add("case", timestamp=case.get("updated_at"), title=case.get("name"), details=case.get("description"))
        states = case.get("finding_states") or {}
        for item in case.get("evidence") or []:
            state = states.get(str(item.get("ref_id")), {})
            add("evidence", timestamp=item.get("created_at"), severity=state.get("state"),
                title=item.get("title") or item.get("ref_id"), protocol=item.get("type"),
                details="; ".join(value for value in (str(item.get("ref_id") or ""), str(item.get("note") or "")) if value))
        for item in case.get("notes") or []:
            add("note", timestamp=item.get("created_at"),
                title=f"Analyst note · {item.get('author') or 'analyst'}", details=item.get("text"))
    return rows


def _safe_cell(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value if value is not None else "")
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def csv_report(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
               redact: bool = False) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=REPORT_COLUMNS)
    writer.writeheader()
    for row in _report_rows(report_document(summary, workspace, redact)):
        writer.writerow({key: _safe_cell(value) for key, value in row.items()})
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


def _xml_value(parent: ET.Element, name: str, value: Any) -> None:
    node = ET.SubElement(parent, name)
    if isinstance(value, Mapping):
        for key, item in value.items():
            key = str(key)
            if re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*$", key):
                _xml_value(node, key, item)
            else:
                entry = ET.SubElement(node, "entry", {"key": key})
                if isinstance(item, (Mapping, list)):
                    _xml_value(entry, "value", item)
                elif item is not None:
                    entry.text = str(item)
    elif isinstance(value, list):
        for item in value:
            _xml_value(node, "item", item)
    elif value is not None:
        node.text = str(value)


def xml_report(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
               redact: bool = False) -> bytes:
    root = ET.Element("nscout-investigation-report", {"schema": "2"})
    for key, value in report_document(summary, workspace, redact).items():
        _xml_value(root, key, value)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def xlsx_report(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
                redact: bool = False) -> bytes:
    """Create a portable OOXML workbook without desktop-only dependencies."""
    rows = [REPORT_COLUMNS] + [[_safe_cell(row.get(column, "")) for column in REPORT_COLUMNS]
                               for row in _report_rows(report_document(summary, workspace, redact))]
    sheet_rows = []
    for row_number, row in enumerate(rows, 1):
        cells = []
        for column_number, value in enumerate(row, 1):
            letters, number = "", column_number
            while number:
                number, remainder = divmod(number - 1, 26)
                letters = chr(65 + remainder) + letters
            cells.append(f'<c r="{letters}{row_number}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>')
        sheet_rows.append(f'<row r="{row_number}">{"".join(cells)}</row>')
    worksheet = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>' + "".join(sheet_rows) + '</sheetData></worksheet>'
    generated = datetime.now(timezone.utc).isoformat()
    parts = {
        "[Content_Types].xml": '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>',
        "xl/workbook.xml": '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Investigation Report" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels": '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml": worksheet,
        "docProps/core.xml": f'<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>nScout Investigation Report</dc:title><dc:creator>nScout</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{generated}</dcterms:created></cp:coreProperties>',
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, content in parts.items():
            archive.writestr(path, content.encode("utf-8"))
    return output.getvalue()


def _html_table(headers: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    esc = lambda value: html.escape(str(value if value is not None else ""))
    return "<table><thead><tr>" + "".join(f"<th>{esc(value)}</th>" for value in headers) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{esc(value)}</td>" for value in row) + "</tr>" for row in rows) + "</tbody></table>"


def html_report(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
                redact: bool = False) -> bytes:
    document = report_document(summary, workspace, redact)
    report, case = document["investigation"], document.get("case") or {}
    overview, findings = report.get("overview") or {}, _findings(report)
    sections = []
    if case:
        sections.append(f"<section><h2>{html.escape(str(case.get('name') or 'Saved investigation'))}</h2><p>{html.escape(str(case.get('description') or ''))}</p><div class='cards'><div class='card'><b>Evidence</b><br>{len(case.get('evidence') or [])}</div><div class='card'><b>Notes</b><br>{len(case.get('notes') or [])}</div><div class='card'><b>Tracked findings</b><br>{len(case.get('finding_states') or {})}</div></div></section>")
    sections.append("<h2>Protocols</h2>" + _html_table(["Protocol", "Packets", "Share"], ((row.get("protocol"), row.get("packets"), f"{row.get('percent', 0)}%") for row in overview.get("protocols") or [])))
    sections.append("<h2>Security findings</h2>" + _html_table(["Severity", "Finding", "Source", "Destination", "Details"], ((row.get("severity"), row.get("title") or row.get("type"), row.get("src") or row.get("src_ip"), row.get("dst") or row.get("dst_ip"), row.get("description") or row.get("detail")) for row in findings)))
    sections.append("<h2>Hosts</h2>" + _html_table(["Host", "Identity", "Risk", "Traffic"], ((row.get("ip"), row.get("alias") or row.get("hostname") or row.get("mac"), (row.get("risk") or {}).get("level"), row.get("total_bytes")) for row in (report.get("hosts") or report.get("devices") or [])[:100])))
    timeline = report.get("investigation_timeline") or {}
    sections.append("<h2>Timeline</h2>" + _html_table(["Time", "Severity", "Event", "Source", "Destination"], ((row.get("timestamp"), row.get("severity"), row.get("title") or row.get("event_type"), row.get("src_ip"), row.get("dst_ip")) for row in (timeline.get("events") or [])[:200])))
    if case:
        sections.append("<h2>Evidence locker</h2>" + _html_table(["Type", "Reference", "Title", "Analyst context"], ((row.get("type"), row.get("ref_id"), row.get("title"), row.get("note")) for row in case.get("evidence") or [])))
        sections.append("<h2>Analyst notes</h2>" + _html_table(["Time", "Author", "Note"], ((row.get("created_at"), row.get("author"), row.get("text")) for row in case.get("notes") or [])))
    redaction = "<span class='badge'>REDACTED</span>" if document["redacted"] else ""
    body = f'''<!doctype html><html><head><meta charset="utf-8"><title>nScout Investigation Report</title><style>body{{font-family:system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 20px;color:#17202a}}h1,h2{{margin-bottom:8px}}h2{{margin-top:28px}}.meta{{color:#667}}.badge{{background:#6d28d9;color:white;border-radius:999px;padding:4px 8px;font-size:11px}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{border:1px solid #ccd;padding:12px 18px;border-radius:8px}}table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}th,td{{border-bottom:1px solid #ddd;text-align:left;padding:8px;vertical-align:top}}th{{background:#f5f6f7}}</style></head><body><h1>nScout Investigation Report {redaction}</h1><p class="meta">Generated {html.escape(document["generated_at"])}</p><div class="cards"><div class="card"><b>Packets</b><br>{overview.get("total_packets", 0)}</div><div class="card"><b>Bytes</b><br>{overview.get("total_bytes", 0)}</div><div class="card"><b>Connections</b><br>{len(report.get("connections") or [])}</div><div class="card"><b>Security findings</b><br>{len(findings)}</div></div>{''.join(sections)}<h2>Limitations</h2><ul>{''.join(f'<li>{html.escape(item)}</li>' for item in document["limitations"])}</ul></body></html>'''
    return body.encode("utf-8")


def _pdf_escape(value: Any) -> str:
    text = str(value if value is not None else "").encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_lines(document: Dict[str, Any]) -> List[str]:
    report = document["investigation"]
    overview, findings, case = report.get("overview") or {}, _findings(report), document.get("case") or {}
    lines = ["nScout Investigation Report" + (" [REDACTED]" if document["redacted"] else ""),
             f"Generated: {document['generated_at']}", "",
             f"Packets: {overview.get('total_packets', 0)}    Bytes: {overview.get('total_bytes', 0)}",
             f"Connections: {len(report.get('connections') or [])}    Hosts: {len(report.get('hosts') or report.get('devices') or [])}",
             f"Security findings: {len(findings)}"]
    if case:
        lines.extend(["", f"Case: {case.get('name')}", f"Description: {case.get('description') or ''}",
                      f"Evidence: {len(case.get('evidence') or [])}    Notes: {len(case.get('notes') or [])}"])
    lines.extend(["", "Protocol summary"])
    for row in (overview.get("protocols") or [])[:25]:
        lines.append(f"  {row.get('protocol', 'Unknown')}: {row.get('packets', 0)} packets ({row.get('percent', 0)}%)")
    lines.extend(["", "Security findings"])
    if not findings:
        lines.append("  No detected security findings.")
    for row in findings[:75]:
        lines.append(f"  [{str(row.get('severity', 'info')).upper()}] {row.get('title') or row.get('type') or 'Finding'}: {row.get('description') or row.get('detail') or ''}")
    lines.extend(["", "Hosts"])
    for row in (report.get("hosts") or report.get("devices") or [])[:50]:
        lines.append(f"  {row.get('ip')}  {row.get('alias') or row.get('hostname') or row.get('mac') or ''}  risk {(row.get('risk') or {}).get('level', 'unknown')}")
    if case:
        lines.extend(["", "Evidence locker"])
        for row in (case.get("evidence") or [])[:75]:
            lines.append(f"  [{row.get('type')}] {row.get('title') or row.get('ref_id')} ({row.get('ref_id')}) {row.get('note') or ''}")
        lines.extend(["", "Analyst notes"])
        for row in (case.get("notes") or [])[:75]:
            lines.append(f"  {row.get('created_at')} {row.get('author')}: {row.get('text')}")
    security_note = (report.get("security") or {}).get("note")
    lines.extend(["", *([security_note] if security_note else []), *document["limitations"]])
    return lines


def pdf_report(summary: Dict[str, Any], workspace: Optional[Mapping[str, Any]] = None,
               redact: bool = False) -> bytes:
    wrapped = []
    for line in _pdf_lines(report_document(summary, workspace, redact)):
        while len(line) > 105:
            cut = line.rfind(" ", 0, 105)
            cut = cut if cut >= 40 else 105
            wrapped.append(line[:cut])
            line = "    " + line[cut:].lstrip()
        wrapped.append(line)
    pages = [wrapped[index:index + 48] for index in range(0, len(wrapped), 48)] or [[]]
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>"]
    page_ids = [4 + index * 2 for index in range(len(pages))]
    objects.append(("<< /Type /Pages /Kids [" + " ".join(f"{value} 0 R" for value in page_ids) + f"] /Count {len(page_ids)} >>").encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    for page_index, lines in enumerate(pages):
        content_id = page_ids[page_index] + 1
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>".encode())
        commands = ["BT", "/F1 9 Tf", "42 750 Td", "12 TL"]
        for index, line in enumerate(lines):
            if index:
                commands.append("T*")
            commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1")
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, value in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode())
        output.extend(value)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects)+1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)
