"""EtherLens AI backend – FastAPI app."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from etherlens.engine import CaptureSession

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")
logger = logging.getLogger("etherlens")

# ---------- Mongo (kept, mostly unused for live buffers) ----------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

# ---------- Core state ----------
session = CaptureSession()

app = FastAPI(title="EtherLens AI")
api = APIRouter(prefix="/api")


# ---------- Models ----------
class StartRequest(BaseModel):
    interface: str = "simulated"


class ExplainRequest(BaseModel):
    packet_id: Optional[str] = None
    threat_id: Optional[str] = None


# ---------- Health ----------
@api.get("/")
async def root():
    return {"name": "EtherLens AI", "status": "ok"}


@api.get("/interfaces")
async def interfaces():
    """List available network interfaces. Marks which are capturable."""
    out = [{"name": "simulated", "label": "Simulated Traffic (always available)", "capturable": True, "live": False}]
    try:
        import psutil  # type: ignore
        for name, _ in psutil.net_if_addrs().items():
            out.append({"name": name, "label": name, "capturable": True, "live": True})
    except Exception:
        # Fallback – read /sys/class/net
        try:
            for iface in sorted(os.listdir("/sys/class/net")):
                out.append({"name": iface, "label": iface, "capturable": True, "live": True})
        except Exception:
            pass
    return {"interfaces": out}


# ---------- Capture control ----------
@api.post("/capture/start")
async def start_capture(req: StartRequest):
    if session.running:
        return {"status": "already_running", "stats": session.stats()}
    session.clear()
    await session.start(req.interface)
    return {"status": "started", "stats": session.stats()}


@api.post("/capture/stop")
async def stop_capture():
    await session.stop()
    return {"status": "stopped", "stats": session.stats()}


@api.post("/capture/clear")
async def clear_capture():
    session.clear()
    return {"status": "cleared"}


@api.get("/capture/status")
async def status():
    return session.stats()


# ---------- Packet data ----------
@api.get("/packets")
async def list_packets(limit: int = 500, protocol: Optional[str] = None, q: Optional[str] = None):
    return {"packets": session.list_packets(limit=limit, protocol=protocol, q=q)}


@api.get("/packets/{pid}")
async def get_packet(pid: str):
    p = session.get_packet(pid)
    if not p:
        raise HTTPException(status_code=404, detail="Packet not found")
    return p


@api.get("/threats")
async def list_threats():
    return {"threats": session.list_threats()}


@api.get("/stats/timeline")
async def timeline():
    return {"series": session.timeline_series()}


@api.get("/stats/top-talkers")
async def top_talkers(limit: int = 10):
    return {"talkers": session.top_talkers(limit=limit)}


@api.get("/topology")
async def topology():
    return session.topology()


# ---------- PCAP upload ----------
@api.post("/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")
    await session.stop()
    session.clear()
    try:
        n = session.ingest_pcap_bytes(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid pcap: {e}") from e
    return {"status": "parsed", "packets": n, "stats": session.stats()}


# ---------- AI explain (SSE streaming) ----------
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY", "")


def _build_prompt(pkt: Optional[dict], threat: Optional[dict]) -> str:
    if threat:
        return (
            "Explain this network security anomaly in plain English to a junior SOC analyst. "
            "Give (1) what happened, (2) why it is suspicious, (3) likely attacker goal, "
            "(4) recommended immediate action. Keep it under 160 words.\n\n"
            f"Anomaly: {json.dumps(threat, default=str)}"
        )
    if pkt:
        slim = {k: pkt.get(k) for k in ("number", "time_str", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "info", "flags")}
        slim["layers"] = [{"name": layer["name"], "fields": layer["fields"]} for layer in pkt.get("layers", [])]
        return (
            "You are a senior network engineer. In plain English, explain what this packet is doing, "
            "what each protocol layer means, and whether anything looks unusual. Be concise (<150 words), "
            "use short bullet points.\n\n"
            f"Packet: {json.dumps(slim, default=str)[:3500]}"
        )
    return "Say: no packet selected."


@api.post("/ai/explain")
async def ai_explain(req: ExplainRequest):
    pkt = session.get_packet(req.packet_id) if req.packet_id else None
    threat = None
    if req.threat_id:
        for t in session.threats:
            if t.get("id") == req.threat_id:
                threat = t
                break
    if not pkt and not threat:
        raise HTTPException(status_code=404, detail="packet or threat not found")

    prompt = _build_prompt(pkt, threat)

    async def gen():
        if not EMERGENT_LLM_KEY:
            yield "data: " + json.dumps({"delta": "AI key not configured."}) + "\n\n"
            yield "data: [DONE]\n\n"
            return
        try:
            from emergentintegrations.llm.chat import LlmChat, UserMessage, TextDelta, StreamDone  # type: ignore
            chat = LlmChat(
                api_key=EMERGENT_LLM_KEY,
                session_id=f"explain-{req.packet_id or req.threat_id}",
                system_message="You are EtherLens AI, an expert network and security analyst. Be clear, concise, and accurate.",
            ).with_model("openai", "gpt-5.4")
            async for ev in chat.stream_message(UserMessage(text=prompt)):
                if isinstance(ev, TextDelta):
                    yield "data: " + json.dumps({"delta": ev.content}) + "\n\n"
                elif isinstance(ev, StreamDone):
                    break
        except Exception as e:
            yield "data: " + json.dumps({"delta": f"AI error: {e}"}) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------- WebSocket live stream ----------
@app.websocket("/api/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    q = session.subscribe()
    stats_task = None
    try:
        # send initial stats
        await ws.send_json({"type": "stats", "data": session.stats()})
        stats_task = asyncio.create_task(_stats_pulse(ws))
        while True:
            msg = await q.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning("ws error: %s", e)
    finally:
        session.unsubscribe(q)
        if stats_task is not None:
            stats_task.cancel()


async def _stats_pulse(ws: WebSocket):
    """Push stats every second so dashboards stay fresh."""
    try:
        while True:
            await asyncio.sleep(1.0)
            await ws.send_json({"type": "stats", "data": session.stats()})
    except Exception:
        return


# ---------- Mount & CORS ----------
app.include_router(api)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown():
    await session.stop()
    client.close()
