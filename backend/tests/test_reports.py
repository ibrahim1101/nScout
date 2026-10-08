import csv
import io
import json
import zipfile
from xml.etree import ElementTree as ET

from etherlens.reports import csv_report,html_report,json_report,pdf_report,report_document,xlsx_report,xml_report


def sample_summary():
    return {
        "overview": {
            "total_packets": 12,
            "total_bytes": 4096,
            "protocols": [{"protocol": "TLS", "packets": 8, "percent": 66.67}],
        },
        "connections": [{
            "a_ip": "10.0.0.2", "a_port": 50123, "b_ip": "1.1.1.1", "b_port": 443,
            "packets": 8, "bytes": 3000, "state": "established",
        }],
        "devices": [{"ip": "10.0.0.2"}],
        "hosts": [{"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "desk.example.test", "risk": {"score": 25, "level": "medium"}}],
        "investigation_timeline": {"events": [{"timestamp": 1, "severity": "medium", "title": "Contacted api.example.test", "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "protocol": "TLS"}]},
        "security": {
            "findings": [{
                "severity": "medium", "type": "periodic_traffic", "detail": "Periodic outbound traffic",
                "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1",
            }],
            "note": "Findings are investigation leads, not proof of compromise.",
        },
        "threats": [],
    }


def sample_workspace():
    return {
        "id": "case-1", "name": "Outbound triage", "description": "Review api.example.test",
        "created_at": "2026-10-08T00:00:00Z", "updated_at": "2026-10-08T01:00:00Z",
        "evidence": [{"id": "ev-1", "type": "packet", "ref_id": "p1", "title": "TLS packet",
                      "note": "Source 10.0.0.2", "created_at": "2026-10-08T00:30:00Z",
                      "snapshot": {"payload": "must-never-appear", "hex": "deadbeef"}}],
        "notes": [{"id": "n1", "author": "analyst", "text": "Escalate desk.example.test", "created_at": "2026-10-08T00:40:00Z"}],
        "finding_states": {"1-starts-with-digit": {"state": "investigating"}},
    }


def test_json_report_contains_investigation_document():
    doc = json.loads(json_report(sample_summary()))
    assert doc["product"] == "nScout"
    assert doc["investigation"]["overview"]["total_packets"] == 12
    assert doc["generated_at"]


def test_html_report_includes_security_intelligence_findings():
    report = html_report(sample_summary()).decode("utf-8")
    assert "nScout Investigation Report" in report
    assert "periodic_traffic" in report
    assert "Periodic outbound traffic" in report


def test_pdf_report_is_valid_portable_pdf_with_investigation_text():
    report = pdf_report(sample_summary())
    assert report.startswith(b"%PDF-1.4")
    assert report.rstrip().endswith(b"%%EOF")
    assert b"nScout Investigation Report" in report
    assert b"periodic_traffic" in report
    assert b"not proof of compromise" in report


def test_report_document_includes_case_context_but_excludes_evidence_snapshots():
    document = report_document(sample_summary(), sample_workspace())
    assert document["schema"] == "nscout.investigation-report.v2"
    assert document["case"]["evidence"][0]["ref_id"] == "p1"
    assert "snapshot" not in document["case"]["evidence"][0]
    assert "must-never-appear" not in json.dumps(document)


def test_redaction_is_consistent_across_structured_and_free_text_fields():
    document = report_document(sample_summary(), sample_workspace(), redact=True)
    serialized = json.dumps(document)
    assert document["redacted"] is True
    assert "10.0.0.2" not in serialized
    assert "1.1.1.1" not in serialized
    assert "aa:bb:cc:dd:ee:ff" not in serialized
    assert "example.test" not in serialized
    assert serialized.count("host-001") >= 2
    assert document["redaction"]["host_count"] == 2


def test_csv_xml_and_xlsx_exports_are_parseable_and_include_case_sections():
    summary, workspace = sample_summary(), sample_workspace()
    csv_rows = list(csv.DictReader(io.StringIO(csv_report(summary, workspace).decode("utf-8-sig"))))
    assert {row["section"] for row in csv_rows} >= {"finding", "host", "timeline", "evidence", "note"}
    xml_root = ET.fromstring(xml_report(summary, workspace))
    assert xml_root.tag == "nscout-investigation-report"
    workbook = xlsx_report(summary, workspace)
    assert workbook.startswith(b"PK")
    with zipfile.ZipFile(io.BytesIO(workbook)) as archive:
        assert "xl/workbook.xml" in archive.namelist()
        assert b"Investigation Report" in archive.read("xl/workbook.xml")
        assert b"evidence" in archive.read("xl/worksheets/sheet1.xml")


def test_tabular_exports_neutralize_formula_prefixes():
    workspace = sample_workspace()
    workspace["notes"][0]["text"] = "=HYPERLINK(\"https://invalid\")"
    csv_text = csv_report(sample_summary(), workspace).decode("utf-8-sig")
    assert "'=HYPERLINK" in csv_text
    with zipfile.ZipFile(io.BytesIO(xlsx_report(sample_summary(), workspace))) as archive:
        assert b"'=HYPERLINK" in archive.read("xl/worksheets/sheet1.xml")
