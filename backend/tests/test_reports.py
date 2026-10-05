import json

from etherlens.reports import html_report, json_report, pdf_report


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
        "security": {
            "findings": [{
                "severity": "medium", "type": "periodic_traffic", "detail": "Periodic outbound traffic",
                "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1",
            }],
            "note": "Findings are investigation leads, not proof of compromise.",
        },
        "threats": [],
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
