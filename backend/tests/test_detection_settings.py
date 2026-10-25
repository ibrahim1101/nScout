import asyncio
import json

import pytest

from etherlens.detection_settings import DetectionSettingsStore


def test_defaults_to_balanced_without_a_settings_file(tmp_path):
    assert DetectionSettingsStore(tmp_path / "detection.json").load() == {
        "version": 1,
        "preset": "balanced",
    }


def test_preset_round_trip_is_atomic_and_allow_listed(tmp_path):
    path = tmp_path / "detection.json"
    store = DetectionSettingsStore(path)

    assert store.save("sensitive")["preset"] == "sensitive"
    assert store.load()["preset"] == "sensitive"
    assert not path.with_suffix(".json.tmp").exists()

    with pytest.raises(ValueError, match="Unknown detection preset"):
        store.save("maximum")


def test_rejects_corrupt_or_future_detection_settings(tmp_path):
    path = tmp_path / "detection.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="unreadable"):
        DetectionSettingsStore(path).load()

    path.write_text(json.dumps({"version": 2, "preset": "balanced"}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        DetectionSettingsStore(path).load()


def test_settings_api_updates_the_active_preset(tmp_path, monkeypatch):
    import server

    store = DetectionSettingsStore(tmp_path / "detection.json")
    monkeypatch.setattr(server, "_detection_settings_store", store)
    monkeypatch.setattr(server, "_detection_preset", "balanced")

    saved = asyncio.run(
        server.save_detection_settings(server.DetectionSettingsRequest(preset="sensitive"))
    )

    assert saved == {"status": "saved", "preset": "sensitive"}
    assert asyncio.run(server.get_detection_settings()) == {"preset": "sensitive"}
    assert store.load()["preset"] == "sensitive"
