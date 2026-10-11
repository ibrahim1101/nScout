import asyncio
import json

import pytest

from etherlens.host_profiles import HostProfileStore, activity_state


def profile(ip="10.0.0.5", first=100, last=120, packets=4, size=500):
    return {"ip": ip, "first_seen": first, "last_seen": last,
            "total_packets": packets, "total_bytes": size, "risk": {"score": 0}}


def test_activity_state_uses_passive_recency_labels():
    assert activity_state(970, now=1000) == "active"
    assert activity_state(500, now=1000) == "recently_seen"
    assert activity_state(1, now=1000) == "inactive"
    assert activity_state(None, now=1000) == "inactive"


def test_alias_watchlist_and_sightings_persist_atomically(tmp_path):
    path = tmp_path / "host-profiles.json"
    store = HostProfileStore(path)
    first = store.enrich([profile()], now=130)[0]
    assert first["activity_state"] == "active"
    assert len(first["activity"]) == 1

    store.update("10.0.0.5", alias="  Lab gateway  ", watchlisted=True)
    unchanged = HostProfileStore(path).enrich([profile()], now=200)[0]
    assert unchanged["alias"] == "Lab gateway"
    assert unchanged["watchlisted"] is True
    assert len(unchanged["activity"]) == 1

    changed = store.enrich([profile(last=210, packets=8)], now=220)[0]
    assert len(changed["activity"]) == 2
    assert changed["activity"][-1]["packets"] == 8
    assert not path.with_suffix(".tmp").exists()

    retained = store.enrich([], now=2000)[0]
    assert retained["ip"] == "10.0.0.5"
    assert retained["alias"] == "Lab gateway"
    assert retained["activity_state"] == "inactive"


def test_profile_validation_and_bounded_history(tmp_path):
    store = HostProfileStore(tmp_path / "hosts.json")
    with pytest.raises(ValueError):
        store.update("not-an-ip", alias="bad")
    with pytest.raises(ValueError):
        store.update("192.0.2.1", alias="x" * 121)
    for timestamp in range(1, 110):
        store.enrich([profile("192.0.2.1", last=timestamp)], now=timestamp)
    assert len(store.enrich([profile("192.0.2.1", last=109)], now=109)[0]["activity"]) == 100
    assert json.loads((tmp_path / "hosts.json").read_text())["version"] == 1


def test_host_profile_api_enriches_and_updates(tmp_path, monkeypatch):
    import server

    store = HostProfileStore(tmp_path / "hosts.json")
    monkeypatch.setattr(server, "_host_profile_store", store)
    monkeypatch.setattr(server.intelligence, "host_intelligence", lambda packets, findings: [profile()])
    monkeypatch.setattr(server.intelligence, "security_intelligence", lambda packets, threats: {"findings": []})

    result = asyncio.run(server.hosts_info())
    assert result["hosts"][0]["ip"] == "10.0.0.5"
    updated = asyncio.run(server.update_host_profile(
        "10.0.0.5", server.HostProfileRequest(alias="Gateway", watchlisted=True)
    ))
    assert updated["profile"]["alias"] == "Gateway"
    assert asyncio.run(server.hosts_info())["hosts"][0]["watchlisted"] is True
