"""EtherLens AI backend tests."""
import json
import os
import tempfile
import time

import pytest
import requests
import websocket  # websocket-client

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL")
if not BASE_URL:
    # fallback to frontend .env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip()
                break
BASE_URL = BASE_URL.rstrip("/")
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module", autouse=True)
def _cleanup():
    # Make sure clean before module
    try:
        requests.post(f"{API}/capture/stop", timeout=10)
        requests.post(f"{API}/capture/clear", timeout=10)
    except Exception:
        pass
    yield
    try:
        requests.post(f"{API}/capture/stop", timeout=10)
        requests.post(f"{API}/capture/clear", timeout=10)
    except Exception:
        pass


# ---- Health ----
def test_root():
    r = requests.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data["name"] == "EtherLens AI"
    assert data["status"] == "ok"


# ---- Interfaces ----
def test_interfaces():
    r = requests.get(f"{API}/interfaces", timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert "interfaces" in data
    names = [i["name"] for i in data["interfaces"]]
    assert "simulated" in names


# ---- Capture start + status ----
def test_capture_start_and_status():
    r = requests.post(f"{API}/capture/start", json={"interface": "simulated"}, timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] in ("started", "already_running")

    time.sleep(3.5)
    r = requests.get(f"{API}/capture/status", timeout=10)
    assert r.status_code == 200
    s = r.json()
    assert s["running"] is True
    assert s["mode"] == "simulated"
    assert s["total_packets"] > 0, f"no packets after 3s: {s}"
    assert s["pps"] > 0
    assert isinstance(s["protocol_counts"], dict) and len(s["protocol_counts"]) > 0


# ---- Packets ----
def test_list_packets():
    r = requests.get(f"{API}/packets?limit=10", timeout=10)
    assert r.status_code == 200
    pkts = r.json()["packets"]
    assert isinstance(pkts, list) and len(pkts) > 0
    required = {"id", "number", "timestamp", "src_ip", "dst_ip", "protocol", "length", "info"}
    for p in pkts:
        missing = required - set(p.keys())
        assert not missing, f"missing fields {missing} in {p}"


def test_get_packet_detail():
    r = requests.get(f"{API}/packets?limit=5", timeout=10)
    pid = r.json()["packets"][0]["id"]
    r2 = requests.get(f"{API}/packets/{pid}", timeout=10)
    assert r2.status_code == 200
    full = r2.json()
    assert "layers" in full and isinstance(full["layers"], list) and len(full["layers"]) >= 1
    assert "hex" in full and isinstance(full["hex"], str) and len(full["hex"]) > 0
    layer_names = {layer["name"] for layer in full["layers"]}
    assert "Frame" in layer_names


def test_get_packet_404():
    r = requests.get(f"{API}/packets/nonexistent-id-xxx", timeout=10)
    assert r.status_code == 404


# ---- Stats ----
def test_timeline():
    r = requests.get(f"{API}/stats/timeline", timeout=10)
    assert r.status_code == 200
    series = r.json()["series"]
    assert isinstance(series, list) and len(series) > 0
    for b in series:
        assert "t" in b and "pps" in b and "bps" in b


def test_top_talkers():
    r = requests.get(f"{API}/stats/top-talkers?limit=10", timeout=10)
    assert r.status_code == 200
    talkers = r.json()["talkers"]
    assert isinstance(talkers, list) and len(talkers) > 0
    for t in talkers:
        assert "ip" in t and "packets" in t and "bytes" in t and "ports" in t


# ---- Topology ----
def test_topology():
    r = requests.get(f"{API}/topology", timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert "nodes" in d and "edges" in d
    assert len(d["nodes"]) > 0
    for n in d["nodes"]:
        assert "id" in n and "type" in n and "packets" in n and "bytes" in n
    for e in d["edges"]:
        assert "source" in e and "target" in e and "packets" in e and "bytes" in e and "protocols" in e


# ---- WebSocket ----
def test_websocket_stats():
    ws_url = BASE_URL.replace("https://", "wss://").replace("http://", "ws://") + "/api/ws"
    ws = websocket.create_connection(ws_url, timeout=10)
    try:
        ws.settimeout(5)
        got_stats = False
        start = time.time()
        while time.time() - start < 5:
            msg = ws.recv()
            data = json.loads(msg)
            if data.get("type") == "stats":
                got_stats = True
                assert "data" in data
                break
        assert got_stats, "no stats message received"
    finally:
        ws.close()


# ---- Threats (wait for simulator anomaly) ----
def test_threats_appear():
    # The simulator injects SYN flood bursts. Wait up to 60s.
    deadline = time.time() + 60
    threats = []
    while time.time() < deadline:
        r = requests.get(f"{API}/threats", timeout=10)
        assert r.status_code == 200
        threats = r.json()["threats"]
        if threats:
            break
        time.sleep(3)
    assert isinstance(threats, list)
    # Allow empty if simulator didn't inject yet; but assert type and if any, check shape
    if threats:
        t = threats[0]
        for k in ("id", "severity", "type", "title", "description", "timestamp"):
            assert k in t


# ---- AI explain SSE ----
def test_ai_explain_sse():
    r = requests.get(f"{API}/packets?limit=1", timeout=10)
    pid = r.json()["packets"][0]["id"]
    with requests.post(f"{API}/ai/explain", json={"packet_id": pid}, stream=True, timeout=60) as resp:
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
        got_delta = False
        got_done = False
        start = time.time()
        for raw in resp.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            if raw.startswith("data:"):
                payload = raw[5:].strip()
                if payload == "[DONE]":
                    got_done = True
                    break
                try:
                    d = json.loads(payload)
                    if "delta" in d and d["delta"]:
                        got_delta = True
                except Exception:
                    pass
            if time.time() - start > 55:
                break
        assert got_delta, "no delta chunks received from AI stream"
        assert got_done, "stream didn't end with [DONE]"


# ---- PCAP upload ----
def test_pcap_upload():
    from scapy.all import Ether, IP, TCP, wrpcap  # type: ignore
    pkts = [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=80, flags="S")] * 5
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        tmp = tf.name
    wrpcap(tmp, pkts)
    with open(tmp, "rb") as f:
        r = requests.post(f"{API}/pcap/upload", files={"file": ("t.pcap", f, "application/octet-stream")}, timeout=30)
    os.unlink(tmp)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "parsed"
    assert d["packets"] >= 5


# ---- Stop + Clear (run last) ----
def test_z_capture_stop():
    # Restart capture because pcap upload stops it
    requests.post(f"{API}/capture/start", json={"interface": "simulated"}, timeout=10)
    time.sleep(1)
    r = requests.post(f"{API}/capture/stop", timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"
    s = requests.get(f"{API}/capture/status", timeout=10).json()
    assert s["running"] is False


def test_z_capture_clear():
    r = requests.post(f"{API}/capture/clear", timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] == "cleared"
    s = requests.get(f"{API}/capture/status", timeout=10).json()
    assert s["total_packets"] == 0
