"""EtherLens AI backend tests for v2 features:

- /api/flows (TCP flow aggregation)
- /api/flow/stream (TCP stream reassembly)
- /api/pcap/export (rebuild + download pcap)
- /api/geo/{ip} + /api/topology?enrich=true
- /api/settings/webhooks (GET/POST, persistence) + /test
"""
from __future__ import annotations

import io
import os
import time

import pytest
import requests


BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip()
                break
BASE_URL = BASE_URL.rstrip("/")
API = f"{BASE_URL}/api"


# ---------- Session setup: ensure some simulated traffic exists ----------
@pytest.fixture(scope="module", autouse=True)
def _ensure_traffic():
    # Stop + clear previous state so this module runs independently
    try:
        requests.post(f"{API}/capture/stop", timeout=10)
        requests.post(f"{API}/capture/clear", timeout=10)
    except Exception:
        pass
    r = requests.post(f"{API}/capture/start", json={"interface": "simulated"}, timeout=10)
    assert r.status_code == 200
    # Let simulator accumulate TCP packets
    deadline = time.time() + 20
    while time.time() < deadline:
        s = requests.get(f"{API}/capture/status", timeout=10).json()
        if s.get("total_packets", 0) > 50:
            break
        time.sleep(1)
    yield
    try:
        requests.post(f"{API}/capture/stop", timeout=10)
    except Exception:
        pass


# ---------- /api/flows ----------
def test_flows_list():
    r = requests.get(f"{API}/flows?limit=20", timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "flows" in data and isinstance(data["flows"], list)
    # Simulator produces TCP traffic, we expect at least 1 flow
    if not data["flows"]:
        # Give it a bit more time
        time.sleep(5)
        data = requests.get(f"{API}/flows?limit=20", timeout=15).json()
    assert len(data["flows"]) > 0, "no flows produced by simulator"
    f0 = data["flows"][0]
    for k in ("a_ip", "a_port", "b_ip", "b_port", "packets", "bytes", "protocols", "last"):
        assert k in f0, f"missing {k} in flow row {f0}"
    assert isinstance(f0["protocols"], list)
    assert f0["packets"] >= 1
    assert f0["bytes"] >= 0


# ---------- /api/flow/stream ----------
def test_flow_stream_reassembly():
    flows = requests.get(f"{API}/flows?limit=5", timeout=10).json()["flows"]
    assert flows, "need at least one flow"
    f = flows[0]
    r = requests.get(
        f"{API}/flow/stream",
        params={"a_ip": f["a_ip"], "a_port": f["a_port"], "b_ip": f["b_ip"], "b_port": f["b_port"]},
        timeout=15,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert "flow" in d
    assert d["flow"]["a"]["ip"] == f["a_ip"]
    assert d["flow"]["b"]["ip"] == f["b_ip"]
    for side in ("a_to_b", "b_to_a"):
        assert side in d
        for k in ("bytes", "mode", "data", "packets"):
            assert k in d[side], f"{side} missing {k}"
        assert d[side]["mode"] in ("text", "hex")
        assert isinstance(d[side]["data"], str)
        assert isinstance(d[side]["bytes"], int)


# ---------- /api/pcap/export ----------
def test_pcap_export_download():
    # Make sure some packets exist
    s = requests.get(f"{API}/capture/status", timeout=10).json()
    assert s["total_packets"] > 0

    r = requests.get(f"{API}/pcap/export", timeout=30)
    assert r.status_code == 200, r.text
    assert "pcap" in r.headers.get("content-type", "").lower()
    body = r.content
    # pcap magic: 0xa1b2c3d4 or little-endian 0xd4c3b2a1 or nanosec variants
    assert len(body) > 24, f"pcap too small: {len(body)}"
    magic = body[:4]
    assert magic in (
        b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1",
    ), f"not a pcap magic: {magic!r}"

    # Round-trip: parse with scapy, confirm packet count > 0
    from scapy.all import rdpcap  # type: ignore
    pkts = rdpcap(io.BytesIO(body))
    assert len(pkts) > 0


def test_pcap_export_empty_404():
    # Stop & clear → should 404
    requests.post(f"{API}/capture/stop", timeout=10)
    requests.post(f"{API}/capture/clear", timeout=10)
    r = requests.get(f"{API}/pcap/export", timeout=10)
    assert r.status_code == 404
    # Restart capture for subsequent tests
    requests.post(f"{API}/capture/start", json={"interface": "simulated"}, timeout=10)
    time.sleep(5)


# ---------- /api/geo/{ip} ----------
def test_geo_private_ip():
    r = requests.get(f"{API}/geo/10.0.0.1", timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d["ip"] == "10.0.0.1"
    assert d["private"] is True
    # Private IPs should not have country info
    assert d["country"] == ""


def test_geo_public_ip():
    r = requests.get(f"{API}/geo/8.8.8.8", timeout=15)
    assert r.status_code == 200
    d = r.json()
    assert d["ip"] == "8.8.8.8"
    assert d["private"] is False
    # Lookup may fail if ip-api.com unreachable; accept either filled or note set
    assert ("country_code" in d) and ("flag" in d)


def test_topology_enrich_true():
    r = requests.get(f"{API}/topology", params={"enrich": "true"}, timeout=20)
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data and "edges" in data
    assert len(data["nodes"]) > 0
    # When enrich=true, every node should have a 'geo' key (may be None for local/missing)
    has_geo_field = any("geo" in n for n in data["nodes"])
    assert has_geo_field, "no 'geo' field present on any node when enrich=true"


# ---------- /api/settings/webhooks ----------
def test_webhook_settings_default():
    r = requests.get(f"{API}/settings/webhooks", timeout=10)
    assert r.status_code == 200
    d = r.json()
    for k in ("slack_url", "discord_url", "min_severity"):
        assert k in d


def test_webhook_settings_save_and_persist():
    payload = {
        "slack_url": "https://hooks.slack.com/services/TEST/TEST/TEST",
        "discord_url": "",
        "min_severity": "medium",
    }
    r = requests.post(f"{API}/settings/webhooks", json=payload, timeout=10)
    assert r.status_code == 200, r.text
    saved = r.json()
    assert saved["status"] == "saved"
    assert saved["settings"]["slack_url"] == payload["slack_url"]
    assert saved["settings"]["min_severity"] == "medium"

    # GET should return the saved values
    r2 = requests.get(f"{API}/settings/webhooks", timeout=10)
    assert r2.status_code == 200
    cur = r2.json()
    assert cur["slack_url"] == payload["slack_url"]
    assert cur["min_severity"] == "medium"

    # Reset to defaults for other tests
    requests.post(f"{API}/settings/webhooks", json={
        "slack_url": "", "discord_url": "", "min_severity": "high",
    }, timeout=10)


def test_webhook_test_bad_url_graceful():
    # Use an unroutable/invalid url — endpoint should respond 200 with ok=false
    r = requests.post(
        f"{API}/settings/webhooks/test",
        json={"url": "http://127.0.0.1:1/nope"},
        timeout=15,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("ok") is False
    # Either an error key or a non-2xx status code should be present
    assert ("error" in d) or ("status" in d)


def test_webhook_test_empty_url():
    r = requests.post(f"{API}/settings/webhooks/test", json={"url": ""}, timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d.get("ok") is False
    assert "error" in d
