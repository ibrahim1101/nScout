import json

import pytest

from etherlens.baselines import BaselineNotFound, BaselineStore, build_profile, compare_profile


def _profile(**overrides):
    profile = {
        "packet_count": 100,
        "byte_count": 10_000,
        "duration_seconds": 10,
        "packet_rate": 10,
        "byte_rate": 1_000,
        "protocols": {"HTTPS": 80, "DNS": 20},
        "ports": {"443": 80, "53": 20},
        "hosts": ["10.0.0.2", "1.1.1.1"],
        "domains": ["baseline.test"],
        "domain_counts": {"baseline.test": 2},
        "connections": ["10.0.0.2|50000|1.1.1.1|443"],
        "finding_types": {},
        "tcp_health": {},
    }
    profile.update(overrides)
    return profile


def test_store_round_trip_is_atomic_and_list_is_summary_only(tmp_path):
    store = BaselineStore(tmp_path / "baselines")
    created = store.create("Office morning", _profile())
    assert len(created["id"]) == 32
    assert store.get(created["id"])["profile"]["packet_count"] == 100
    assert store.list() == [{
        "id": created["id"], "name": "Office morning", "created_at": created["created_at"],
        "packet_count": 100, "duration_seconds": 10, "host_count": 2, "domain_count": 1,
    }]
    assert not list((tmp_path / "baselines").glob("*.tmp"))


def test_store_skips_corrupt_records_and_rejects_unsafe_ids(tmp_path):
    directory = tmp_path / "baselines"
    directory.mkdir()
    (directory / "broken.json").write_text("not json", encoding="utf-8")
    store = BaselineStore(directory)
    assert store.list() == []
    with pytest.raises(ValueError, match="identifier"):
        store.get("../outside")


def test_store_delete_and_missing_record(tmp_path):
    store = BaselineStore(tmp_path / "baselines")
    baseline_id = store.create("Temporary", _profile())["id"]
    store.delete(baseline_id)
    with pytest.raises(BaselineNotFound):
        store.get(baseline_id)


def test_comparison_explains_entities_protocol_rate_and_health_changes():
    current = _profile(
        packet_count=200, duration_seconds=10, packet_rate=40, byte_rate=4_000,
        protocols={"HTTPS": 80, "DNS": 20, "SSH": 100},
        ports={"443": 80, "53": 20, "22": 100},
        hosts=["10.0.0.2", "1.1.1.1", "203.0.113.5"],
        domains=["baseline.test", "new.test"], tcp_health={"tcp.reset": 3},
    )
    result = compare_profile(_profile(), current)
    kinds = {reason["type"] for reason in result["reasons"]}
    assert {"new_host", "new_domain", "new_service_port", "protocol_share_shift",
            "packet_rate_deviation", "byte_rate_deviation", "increased_tcp_health"} <= kinds
    assert 0 < result["score"] <= 100
    assert all(reason["threshold"] and "observed" in reason and "baseline" in reason for reason in result["reasons"])
    assert result["interpretation"].endswith("learned normal model.")


def test_comparison_is_deterministic_and_quiet_for_matching_profile():
    first = compare_profile(_profile(), _profile())
    second = compare_profile(_profile(), _profile())
    assert first == second
    assert first["score"] == 0
    assert first["level"] == "none"
    assert first["reasons"] == []


def test_build_profile_excludes_raw_packet_content():
    packets = [{
        "id": "packet-1", "number": 1, "timestamp": 10.0, "length": 60,
        "src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "src_port": 50000,
        "dst_port": 443, "protocol": "HTTPS", "layers": [],
        "raw_hex": "secret", "payload": "secret",
    }]
    profile = build_profile(packets, [])
    serialized = json.dumps(profile)
    assert profile["packet_count"] == 1
    assert profile["packet_rate"] is None
    assert "secret" not in serialized
    assert "raw_hex" not in serialized
