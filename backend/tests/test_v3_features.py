"""EtherLens AI v3 backend tests:

- PyInstaller launcher smoke (import + port picker + bundle dir)
- Capture sessions CRUD: POST /sessions/save, GET /sessions,
  POST /sessions/{id}/load, DELETE /sessions/{id}
- Overlap-aware TCP reassembly via /api/flow/stream (duplicate / overlapping /
  gap-filler segments must not inflate reconstructed payload).
"""
from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

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


# ============================================================
# 1) PyInstaller launcher smoke tests
# ============================================================
class TestLauncher:
    """Verify the desktop launcher module is importable and its helpers work."""

    def test_launcher_import(self):
        sys.path.insert(0, "/app/backend")
        try:
            import launcher  # noqa: F401
        finally:
            sys.path.pop(0)
        assert hasattr(launcher, "main")
        assert hasattr(launcher, "_pick_port")
        assert hasattr(launcher, "_bundle_dir")
        assert hasattr(launcher, "_ensure_env")

    def test_pick_port_returns_int(self):
        sys.path.insert(0, "/app/backend")
        try:
            import launcher
        finally:
            sys.path.pop(0)
        p = launcher._pick_port(0)  # 0 = OS-assigned, always succeeds
        assert isinstance(p, int)
        assert 1 <= p <= 65535

    def test_bundle_dir_is_path(self):
        sys.path.insert(0, "/app/backend")
        try:
            import launcher
        finally:
            sys.path.pop(0)
        d = launcher._bundle_dir()
        assert isinstance(d, Path)
        # In dev mode this is /app/backend
        assert d.exists()


# ============================================================
# 2) Session Save / List / Load / Delete
# ============================================================
class TestSessionsCRUD:
    """CRUD lifecycle of captured sessions in MongoDB."""

    @pytest.fixture(autouse=True, scope="class")
    def _prime_capture(self):
        # Ensure a capture with some packets exists before class runs
        try:
            requests.post(f"{API}/capture/stop", timeout=10)
            requests.post(f"{API}/capture/clear", timeout=10)
        except Exception:
            pass
        r = requests.post(f"{API}/capture/start", json={"interface": "simulated"}, timeout=10)
        assert r.status_code == 200
        deadline = time.time() + 20
        while time.time() < deadline:
            if requests.get(f"{API}/capture/status", timeout=10).json().get("total_packets", 0) > 30:
                break
            time.sleep(1)
        yield
        try:
            requests.post(f"{API}/capture/stop", timeout=10)
        except Exception:
            pass

    def test_save_empty_returns_400(self):
        # Clear then try to save — must fail with 400 "No packets to save"
        requests.post(f"{API}/capture/stop", timeout=10)
        requests.post(f"{API}/capture/clear", timeout=10)
        r = requests.post(f"{API}/sessions/save", json={"name": "TEST_empty"}, timeout=10)
        assert r.status_code == 400
        assert "no packets" in r.text.lower()
        # Restart simulator for subsequent tests
        requests.post(f"{API}/capture/start", json={"interface": "simulated"}, timeout=10)
        deadline = time.time() + 20
        while time.time() < deadline:
            if requests.get(f"{API}/capture/status", timeout=10).json().get("total_packets", 0) > 30:
                break
            time.sleep(1)

    def test_full_crud_lifecycle(self):
        # SAVE
        name = f"TEST_sess_{int(time.time())}"
        r = requests.post(f"{API}/sessions/save", json={"name": name}, timeout=15)
        assert r.status_code == 200, r.text
        saved = r.json()
        assert saved["status"] == "saved"
        assert saved["name"] == name
        assert saved["packet_count"] >= 1
        sid = saved["id"]
        assert isinstance(sid, str) and len(sid) >= 8

        # LIST — contains the new session, no mongo _id leak
        r = requests.get(f"{API}/sessions", timeout=10)
        assert r.status_code == 200
        rows = r.json()["sessions"]
        assert any(row["id"] == sid for row in rows), f"saved id {sid} not in list"
        row = next(row for row in rows if row["id"] == sid)
        assert "_id" not in row, "Mongo _id leaked in list response"
        assert row["name"] == name
        assert row["packet_count"] == saved["packet_count"]

        # LOAD — replays packets into the live session
        orig_count = saved["packet_count"]
        # Clear live state first so we can observe reload populates it.
        requests.post(f"{API}/capture/stop", timeout=10)
        requests.post(f"{API}/capture/clear", timeout=10)
        assert requests.get(f"{API}/capture/status", timeout=10).json()["total_packets"] == 0

        r = requests.post(f"{API}/sessions/{sid}/load", timeout=30)
        assert r.status_code == 200, r.text
        loaded = r.json()
        assert loaded["status"] == "loaded"
        assert loaded["id"] == sid
        assert loaded["name"] == name
        # Replay re-ingests through dissector; some packets may fail to re-parse.
        # Expect at least ~50% retained.
        assert loaded["packet_count"] >= max(1, orig_count // 2), (
            f"replay only kept {loaded['packet_count']} / {orig_count}"
        )
        # Live stats reflect loaded packets
        status = requests.get(f"{API}/capture/status", timeout=10).json()
        assert status["total_packets"] >= 1

        # DELETE
        r = requests.delete(f"{API}/sessions/{sid}", timeout=10)
        assert r.status_code == 200
        assert r.json()["status"] == "deleted"

        # LIST again — should be gone
        rows = requests.get(f"{API}/sessions", timeout=10).json()["sessions"]
        assert not any(row["id"] == sid for row in rows)

        # DELETE a 2nd time → 404
        r = requests.delete(f"{API}/sessions/{sid}", timeout=10)
        assert r.status_code == 404

        # LOAD a non-existent id → 404
        r = requests.post(f"{API}/sessions/does-not-exist-xyz/load", timeout=10)
        assert r.status_code == 404


# ============================================================
# 3) Overlap-aware reassembly via /flow/stream
# ============================================================
class TestOverlapReassembly:
    """Craft a pcap with retransmits + overlapping TCP segments; verify
    /flow/stream returns the de-duplicated byte count equal to the unique
    byte range length — NOT the sum of all segment payloads.
    """

    @staticmethod
    def _make_pcap_bytes() -> tuple[bytes, int]:
        """Build a tiny pcap of 5 TCP segments A→B, with overlaps + a retransmit.

        Byte-range plan (relative to initial seq=1000):
          seg1: [0, 10)      "AAAAAAAAAA"            (10 bytes)
          seg2: [10, 25)     "BBBBBBBBBBBBBBB"       (15 bytes)
          seg3: [20, 30)     "ccccCCCCCC"            overlaps 20..25 w/ seg2
          seg4: [0, 10)      "AAAAAAAAAA"            pure retransmit of seg1
          seg5: [30, 40)     "DDDDDDDDDD"            (10 bytes)
        Unique range = [0, 40) = 40 bytes.
        """
        import tempfile

        from scapy.all import Ether, IP, TCP, wrpcap  # type: ignore

        base_seq = 1000
        src_ip, dst_ip = "10.9.9.1", "10.9.9.2"
        sport, dport = 50000, 8080

        payloads = [
            (0, b"A" * 10),
            (10, b"B" * 15),
            (20, b"c" * 5 + b"C" * 5),  # overlaps 20..25 with seg2
            (0, b"A" * 10),              # retransmit of seg1
            (30, b"D" * 10),
        ]
        pkts = []
        t0 = time.time()
        for i, (offset, data) in enumerate(payloads):
            p = (
                Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                / IP(src=src_ip, dst=dst_ip)
                / TCP(sport=sport, dport=dport, seq=base_seq + offset, ack=1, flags="PA")
                / data
            )
            p.time = t0 + i * 0.01
            pkts.append(p)

        buf = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        buf.close()
        wrpcap(buf.name, pkts)
        with open(buf.name, "rb") as fh:
            data = fh.read()
        os.unlink(buf.name)
        return data, 40  # unique bytes expected

    def test_reassembly_dedupes_overlap_and_retransmit(self):
        pcap_bytes, expected_unique = self._make_pcap_bytes()

        # Stop + clear + upload the crafted pcap (this parses and populates session.packets)
        requests.post(f"{API}/capture/stop", timeout=10)
        requests.post(f"{API}/capture/clear", timeout=10)
        files = {"file": ("overlap.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")}
        r = requests.post(f"{API}/pcap/upload", files=files, timeout=15)
        assert r.status_code == 200, r.text
        up = r.json()
        assert up["status"] == "parsed"
        assert up["packets"] == 5, f"expected 5 pkts ingested, got {up['packets']}"

        # Now follow the stream
        r = requests.get(
            f"{API}/flow/stream",
            params={"a_ip": "10.9.9.1", "a_port": 50000, "b_ip": "10.9.9.2", "b_port": 8080},
            timeout=15,
        )
        assert r.status_code == 200, r.text
        d = r.json()
        a2b = d["a_to_b"]

        # Core assertion: overlap-aware reassembly collapses the duplicate/overlap
        # Sum of raw payload bytes would be 10+15+10+10+10 = 55; unique = 40.
        assert a2b["bytes"] == expected_unique, (
            f"overlap-aware reassembly broken: bytes={a2b['bytes']} expected={expected_unique}"
        )
        assert a2b["packets"] == 5  # all 5 segments were in the A→B direction

        # Reconstructed payload should contain each unique region in seq order:
        # A*10, B*15, (overlap region shows "cccccCCCCC" partially — only non-covered bytes kept),
        # then D*10. Since seg3's first 5 bytes (20..25) overlap seg2, only 25..30 ("CCCCC") remains.
        reconstructed = a2b["data"]
        # If mode is "text", data is the raw decoded payload; if "hex", it's a hex-dump.
        if a2b["mode"] == "text":
            assert reconstructed.startswith("A" * 10)
            assert "B" * 15 in reconstructed
            # seg3 kept only tail CCCCC (bytes 25..30), seg2 covers 20..25
            assert "CCCCC" in reconstructed
            assert reconstructed.endswith("D" * 10)
            assert len(reconstructed) == expected_unique
        else:
            # hex-dump mode: just assert content length roughly scales to 40 bytes.
            assert "41 41 41 41 41 41 41 41 41 41" in reconstructed  # 10× 'A'
            assert "44 44 44 44 44 44 44 44 44 44" in reconstructed  # 10× 'D'

    def test_reassembly_empty_for_unknown_flow(self):
        r = requests.get(
            f"{API}/flow/stream",
            params={"a_ip": "1.2.3.4", "a_port": 1, "b_ip": "5.6.7.8", "b_port": 2},
            timeout=10,
        )
        assert r.status_code == 200
        d = r.json()
        assert d["a_to_b"]["bytes"] == 0
        assert d["b_to_a"]["bytes"] == 0
