import asyncio
import json

import pytest

from etherlens.preference_profiles import MAX_PROFILES, PreferenceProfileStore, normalize_preferences


def preferences(**overrides):
    value = {"preservePackets": True, "autoRestore": True, "redactReports": False,
             "packetLimit": 50000, "detectionPreset": "balanced", "alertSeverity": "high"}
    value.update(overrides)
    return value


def test_profiles_persist_atomically_without_unknown_or_secret_fields(tmp_path):
    path = tmp_path / "profiles.json"
    created = PreferenceProfileStore(path).create(
        "  Incident response  ", preferences(webhook="secret", token="secret")
    )
    assert created["name"] == "Incident response"
    assert created["preferences"] == preferences()
    assert PreferenceProfileStore(path).list()[0] == created
    assert json.loads(path.read_text())["version"] == 1
    assert not path.with_suffix(".json.tmp").exists()


def test_profile_validation_bounds_and_delete(tmp_path):
    store = PreferenceProfileStore(tmp_path / "profiles.json")
    with pytest.raises(ValueError):
        store.create("", preferences())
    with pytest.raises(ValueError):
        store.create("Bad packet limit", preferences(packetLimit=10))
    with pytest.raises(ValueError):
        normalize_preferences(preferences(detectionPreset="maximum"))
    created = store.create("Travel", preferences(packetLimit=1000, alertSeverity="critical"))
    store.delete(created["id"])
    assert store.list() == []
    with pytest.raises(KeyError):
        store.delete(created["id"])


def test_profile_count_is_bounded(tmp_path):
    store = PreferenceProfileStore(tmp_path / "profiles.json")
    for index in range(MAX_PROFILES):
        store.create(f"Profile {index}", preferences())
    with pytest.raises(ValueError):
        store.create("Too many", preferences())


def test_profile_api_create_list_and_delete(tmp_path, monkeypatch):
    import server
    store = PreferenceProfileStore(tmp_path / "profiles.json")
    monkeypatch.setattr(server, "_preference_profile_store", store)
    request = server.CreatePreferenceProfileRequest(
        name="Forensics", preferences=server.LocalPreferences(**preferences(redactReports=True))
    )
    created = asyncio.run(server.create_preference_profile(request))["profile"]
    listed = asyncio.run(server.list_preference_profiles())["profiles"]
    assert listed[0]["id"] == created["id"]
    assert listed[0]["preferences"]["redactReports"] is True
    assert asyncio.run(server.delete_preference_profile(created["id"])) == {"status": "deleted"}
