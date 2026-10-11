import json

import launcher


def test_desktop_arguments_support_silent_supervision(monkeypatch, tmp_path):
    monkeypatch.setenv("NSCOUT_PORT", "8123")
    readiness = tmp_path / "ready.json"
    args = launcher._arguments(["--no-browser", "--readiness-file", str(readiness)])
    assert args.port == 8123
    assert args.no_browser is True
    assert args.readiness_file == readiness


def test_readiness_file_is_valid_json_and_replaced_atomically(tmp_path):
    readiness = tmp_path / "state" / "ready.json"
    launcher._write_readiness(readiness, "http://127.0.0.1:8001")
    assert json.loads(readiness.read_text(encoding="utf-8")) == {
        "status": "ready",
        "url": "http://127.0.0.1:8001",
    }
    assert not readiness.with_suffix(".json.tmp").exists()


def test_truthy_desktop_mode_values():
    assert launcher._truthy("TRUE") is True
    assert launcher._truthy("0") is False
    assert launcher._truthy(None) is False
