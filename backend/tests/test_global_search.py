import pytest

from etherlens.global_search import MAX_RESULTS, search_investigation_data


def test_searches_live_metadata_and_returns_navigation_targets():
    result = search_investigation_data(
        "malware.test",
        packets=[{
            "id": "p1", "number": 1, "timestamp": 10, "protocol": "DNS",
            "src_ip": "10.0.0.8", "dst_ip": "8.8.8.8", "info": "Query malware.test",
            "payload": "malware.test must not be required", "hex": "00ff",
        }],
        dns_events=[{
            "packet_id": "p1", "timestamp": 10, "src_ip": "10.0.0.8",
            "dst_ip": "8.8.8.8", "query": "malware.test", "answers": [],
        }],
    )
    assert result["count"] == 2
    assert result["categories"] == {"dns": 1, "packet": 1}
    assert {item["target"]["packet_id"] for item in result["results"]} == {"p1"}


def test_searches_hosts_connections_findings_and_timeline():
    result = search_investigation_data(
        "10.0.0.5",
        hosts=[{"ip": "10.0.0.5", "alias": "Finance laptop", "services": [], "domains": []}],
        connections=[{"a_ip": "10.0.0.5", "a_port": 55000, "b_ip": "203.0.113.4", "b_port": 443, "protocols": ["TLS"]}],
        findings=[{"id": "f1", "title": "Beaconing", "description": "Periodic traffic from 10.0.0.5"}],
        timeline=[{"id": "t1", "title": "Host contacted remote service", "host": "10.0.0.5"}],
    )
    assert {item["type"] for item in result["results"]} == {"host", "connection", "finding", "timeline"}
    assert next(item for item in result["results"] if item["type"] == "host")["target"] == {"host_ip": "10.0.0.5"}


def test_searches_saved_case_notes_and_evidence_without_snapshot_contents():
    investigation = {
        "id": "case-1", "name": "Suspicious DNS", "description": "Triage workstation",
        "updated_at": "2026-10-08T00:00:00Z",
        "notes": [{"id": "note-1", "text": "Escalate cobalt beacon", "author": "analyst"}],
        "evidence": [{
            "id": "ev-1", "type": "dns", "ref_id": "packet-9", "title": "Beacon domain",
            "note": "Confirmed during triage", "snapshot": {"payload": "snapshot-secret-token"},
        }],
    }
    result = search_investigation_data("cobalt", investigations=[investigation])
    assert result["results"][0]["type"] == "note"
    assert result["results"][0]["target"]["investigation_id"] == "case-1"
    assert search_investigation_data("beacon domain", investigations=[investigation])["results"][0]["type"] == "evidence"
    assert search_investigation_data("snapshot-secret-token", investigations=[investigation])["count"] == 0


def test_payload_and_hex_are_not_indexed():
    packet = {"id": "p1", "number": 1, "protocol": "TCP", "payload": "private-marker", "hex": "deadbeef"}
    assert search_investigation_data("private-marker", packets=[packet])["count"] == 0
    assert search_investigation_data("deadbeef", packets=[packet])["count"] == 0


@pytest.mark.parametrize("query", ["", " ", "x"])
def test_rejects_too_short_queries(query):
    with pytest.raises(ValueError, match="at least 2"):
        search_investigation_data(query)


def test_caps_result_count_and_reports_truncation():
    packets = [{"id": str(index), "number": index, "protocol": "TCP", "info": "needle"} for index in range(200)]
    result = search_investigation_data("needle", packets=packets, limit=1000)
    assert result["count"] == MAX_RESULTS
    assert result["total_matches"] == 200
    assert result["truncated"] is True
