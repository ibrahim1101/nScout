import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from pydantic import ValidationError
from etherlens.ai_provider import AISettings, AIUnavailable, complete, load_settings, models, save_settings

@pytest.fixture
def local_server():
    state = {"status": 200, "answer": {"choices": [{"message": {"content": "Observed TCP handshake."}}]}, "requests": []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            state["requests"].append(self.path)
            self.send_response(state["status"]); self.end_headers()
            self.wfile.write(json.dumps({"data": [{"id": "test-model"}]}).encode())
        def do_POST(self):
            state["requests"].append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(state["status"]); self.end_headers()
            self.wfile.write(json.dumps(state["answer"]).encode())
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    yield AISettings(enabled=True, base_url=f"http://127.0.0.1:{server.server_port}/v1", model="test-model"), state
    server.shutdown(); server.server_close(); worker.join()

@pytest.mark.parametrize("provider", ["ollama", "lmstudio", "openai_compatible"])
def test_local_provider_end_to_end(local_server, provider, monkeypatch):
    settings, state = local_server; settings.provider = provider
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    assert models(settings) == ["test-model"]
    assert complete(settings, "x" * 20000) == "Observed TCP handshake."
    sent = state["requests"][-1]
    assert sent["model"] == "test-model"
    assert len(sent["messages"][1]["content"]) == 12000
    assert sent["stream"] is False
    assert "untrusted" in sent["messages"][0]["content"]

def test_disabled_and_missing_model_never_send(local_server):
    settings, state = local_server; settings.enabled = False
    with pytest.raises(AIUnavailable, match="disabled"): complete(settings, "capture")
    settings.enabled = True; settings.model = ""
    with pytest.raises(AIUnavailable, match="Choose"): complete(settings, "capture")
    assert state["requests"] == []

@pytest.mark.parametrize("url", ["https://example.com/v1", "http://192.168.1.2/v1", "file:///tmp/ai", "http://user:secret@127.0.0.1/v1", "http://127.0.0.1/v1?secret=x", "http://localhost.evil/v1"])
def test_reject_invalid_urls(url):
    with pytest.raises(ValidationError): AISettings(base_url=url)

def test_loopback_normalization():
    assert AISettings(base_url="http://localhost:11434/v1/").base_url == "http://127.0.0.1:11434/v1"
    assert AISettings(base_url="http://[::1]:1234/v1").base_url == "http://[::1]:1234/v1"

def test_redirect_not_followed(local_server):
    settings, state = local_server; state["status"] = 302
    with pytest.raises(AIUnavailable, match="HTTP 302"): complete(settings, "capture")
    assert len(state["requests"]) == 1

def test_invalid_answer(local_server):
    settings, state = local_server; state["answer"] = {"choices": []}
    with pytest.raises(AIUnavailable, match="no usable"): complete(settings, "capture")

def test_persistence(tmp_path):
    path = tmp_path / "ai.json"
    assert load_settings(path).enabled is False
    saved = AISettings(enabled=True, model="my-model", provider="lmstudio", base_url="http://127.0.0.1:1234/v1")
    save_settings(path, saved); assert load_settings(path) == saved
    path.write_text("invalid"); assert load_settings(path).enabled is False

def test_unavailable(local_server):
    settings, _ = local_server; settings.base_url = "http://127.0.0.1:1/v1"
    with pytest.raises(AIUnavailable, match="Cannot connect"): complete(settings, "capture")

def test_endpoint_disabled_and_fallback(local_server, monkeypatch):
    import server
    from fastapi import HTTPException
    settings, state = local_server
    monkeypatch.setattr(server, "_ai_settings", AISettings())
    with pytest.raises(HTTPException) as error: asyncio.run(server.ai_explain(server.ExplainRequest(packet_id="p1")))
    assert error.value.status_code == 403
    settings.model = ""; monkeypatch.setattr(server, "_ai_settings", settings)
    monkeypatch.setattr(server.session, "get_packet", lambda pid: {"id":pid, "protocol":"TCP", "info":"Observed SYN"})
    async def read():
        response = await server.ai_explain(server.ExplainRequest(packet_id="p1"))
        return "".join([chunk async for chunk in response.body_iterator])
    result = asyncio.run(read())
    assert "Deterministic context" in result and '"fallback": true' in result and "[DONE]" in result
    assert state["requests"] == []

def test_timeout_is_actionable(local_server, monkeypatch):
    import requests
    settings, _ = local_server
    def timeout(*args, **kwargs): raise requests.Timeout()
    monkeypatch.setattr(requests.Session, "request", timeout)
    with pytest.raises(AIUnavailable, match="timed out"): complete(settings, "capture")

def test_response_size_bound(local_server):
    settings, state = local_server
    state["answer"] = {"choices": [{"message": {"content": "x" * (2 * 1024 * 1024)}}]}
    with pytest.raises(AIUnavailable, match="size limit"): complete(settings, "capture")

def test_worker_lock_survives_async_cancellation(local_server):
    from etherlens import ai_provider
    settings, state = local_server
    assert ai_provider._inference_lock.acquire(blocking=False)
    try:
        with pytest.raises(AIUnavailable, match="busy"): complete(settings, "capture")
        assert state["requests"] == []
    finally: ai_provider._inference_lock.release()
