"""EtherLens AI backend – FastAPI app."""
from __future__ import annotations
import asyncio,json,logging,os
from pathlib import Path
from typing import List,Optional
from dotenv import load_dotenv
from fastapi import APIRouter,FastAPI,File,HTTPException,UploadFile,WebSocket,WebSocketDisconnect
from fastapi.responses import Response,StreamingResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from etherlens import analysis,geo,webhooks,intelligence
from etherlens.filters import filter_packets
from etherlens.reports import json_report,html_report
from etherlens.protocol_intelligence import tls_intelligence,packet_timeline,packet_ascii
from etherlens.engine import CaptureSession
from etherlens.sessions import save_session,list_sessions,load_session,delete_session
ROOT_DIR=Path(__file__).parent; load_dotenv(ROOT_DIR/".env"); logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(name)s - %(message)s"); logger=logging.getLogger("nscout")
mongo_url=os.environ.get("MONGO_URL","mongodb://127.0.0.1:27017"); db_name=os.environ.get("DB_NAME","nscout"); client=AsyncIOMotorClient(mongo_url,serverSelectionTimeoutMS=1500,connectTimeoutMS=1500); db=client[db_name]; settings_col=db.etherlens_settings; mongo_available=False; session=CaptureSession(); app=FastAPI(title="nScout"); api=APIRouter(prefix="/api")
class StartRequest(BaseModel): interface:str="simulated"
class ExplainRequest(BaseModel): packet_id:Optional[str]=None; threat_id:Optional[str]=None
class WebhookSettings(BaseModel): slack_url:str=""; discord_url:str=""; min_severity:str="high"
class WebhookTestRequest(BaseModel): url:str
class SaveSessionRequest(BaseModel): name:str="Untitled"
_webhook_cache={"slack_url":"","discord_url":"","min_severity":"high"}; _SEV_RANK={"low":1,"medium":2,"high":3,"critical":4}
async def _load_settings():
 global mongo_available
 try:
  await client.admin.command("ping"); mongo_available=True; doc=await settings_col.find_one({"_id":"webhooks"})
  if doc:_webhook_cache.update({k:doc.get(k,_webhook_cache[k]) for k in _webhook_cache})
 except Exception as exc: mongo_available=False; logger.warning("MongoDB unavailable; saved sessions/settings persistence disabled: %s",exc)
async def _threat_hook(threat):
 if _SEV_RANK.get(threat.get("severity","low"),1)<_SEV_RANK.get(_webhook_cache.get("min_severity","high"),3):return
 urls=[u for u in (_webhook_cache.get("slack_url"),_webhook_cache.get("discord_url")) if u]
 if urls:asyncio.create_task(webhooks.fan_out(urls,threat))
@api.get("/")
async def root():return {"name":"nScout","status":"ok","mongo":mongo_available}
@api.get("/interfaces")
async def interfaces():
 out=[{"name":"simulated","label":"Simulated Traffic (always available)","capturable":True,"live":False}]
 try:
  import psutil
  for name in psutil.net_if_addrs():out.append({"name":name,"label":name,"capturable":True,"live":True})
 except Exception:pass
 return {"interfaces":out}
@api.post("/capture/start")
async def start_capture(req:StartRequest):
 if session.running:return {"status":"already_running","stats":session.stats()}
 session.clear(); await session.start(req.interface); return {"status":"started","stats":session.stats()}
@api.post("/capture/stop")
async def stop_capture():await session.stop(); return {"status":"stopped","stats":session.stats()}
@api.post("/capture/clear")
async def clear_capture():session.clear(); return {"status":"cleared"}
@api.get("/capture/status")
async def status():return session.stats()
@api.get("/packets")
async def list_packets(limit:int=500,protocol:Optional[str]=None,q:Optional[str]=None):return {"packets":session.list_packets(limit=limit,protocol=protocol,q=q)}
@api.get("/packets/search")
async def smart_packet_search(expression:str="",limit:int=500):
 packets=list(session.packets);health=intelligence.annotate_tcp_health(packets)
 return {"expression":expression,"packets":filter_packets(packets,expression,health=health,limit=max(1,min(limit,5000)))}
@api.get("/packets/{pid}")
async def get_packet(pid:str):
 p=session.get_packet(pid)
 if not p:raise HTTPException(status_code=404,detail="Packet not found")
 p=dict(p); p["tcp_health"]=intelligence.annotate_tcp_health(list(session.packets)).get(pid,{"events":[],"healthy":True}); p["ascii"]=packet_ascii(p); return p
@api.get("/threats")
async def list_threats():return {"threats":session.list_threats()}
@api.get("/stats/timeline")
async def timeline():return {"series":session.timeline_series()}
@api.get("/stats/top-talkers")
async def top_talkers(limit:int=10):return {"talkers":session.top_talkers(limit=limit)}
@api.get("/intelligence/connections")
async def intelligent_connections(limit:int=500):return {"connections":intelligence.connection_intelligence(list(session.packets),limit=limit)}
@api.get("/intelligence/dashboard")
async def intelligent_dashboard():return intelligence.protocol_dashboard(list(session.packets))
@api.get("/intelligence/tcp-health")
async def tcp_health():return {"packets":intelligence.annotate_tcp_health(list(session.packets))}
@api.get("/intelligence/dns")
async def dns_info():return intelligence.dns_intelligence(list(session.packets))
@api.get("/intelligence/http")
async def http_info():return intelligence.http_intelligence(list(session.packets))
@api.get("/intelligence/tls")
async def tls_info():return tls_intelligence(list(session.packets))
@api.get("/intelligence/devices")
async def devices_info():return {"devices":intelligence.device_intelligence(list(session.packets))}
@api.get("/intelligence/timeline")
async def investigation_timeline(bucket_seconds:float=1.0):return {"series":packet_timeline(list(session.packets),bucket_seconds)}
@api.get("/investigation/summary")
async def investigation_summary():return intelligence.investigation_summary(list(session.packets),session.list_threats())
@api.get("/investigation/report.json")
async def investigation_report_json():
 summary=intelligence.investigation_summary(list(session.packets),session.list_threats())
 return Response(content=json_report(summary),media_type="application/json",headers={"Content-Disposition":'attachment; filename="nscout-investigation.json"'})
@api.get("/investigation/report.html")
async def investigation_report_html():
 summary=intelligence.investigation_summary(list(session.packets),session.list_threats())
 return Response(content=html_report(summary),media_type="text/html; charset=utf-8",headers={"Content-Disposition":'attachment; filename="nscout-investigation.html"'})
@api.get("/topology")
async def topology(enrich:bool=False):
 data=session.topology()
 if enrich:
  ext=[n["id"] for n in data["nodes"] if n.get("type")!="local"]; gm=await geo.enrich(ext)
  for n in data["nodes"]:n["geo"]=gm.get(n["id"]) if n["id"] in gm else None
 return data
@api.post("/pcap/upload")
async def upload_pcap(file:UploadFile=File(...)):
 data=await file.read()
 if not data:raise HTTPException(status_code=400,detail="Empty file")
 if len(data)>50*1024*1024:raise HTTPException(status_code=413,detail="File too large (max 50MB)")
 await session.stop();session.clear()
 try:n=session.ingest_pcap_bytes(data)
 except Exception as e:raise HTTPException(status_code=400,detail=f"Invalid pcap: {e}") from e
 return {"status":"parsed","packets":n,"stats":session.stats(),"investigation":intelligence.investigation_summary(list(session.packets),session.list_threats())}
@api.get("/pcap/export")
async def export_pcap():
 pkts=list(session.packets)
 if not pkts:raise HTTPException(status_code=404,detail="No packets to export")
 data=analysis.export_pcap(pkts)
 if not data:raise HTTPException(status_code=500,detail="Failed to build pcap")
 return Response(content=data,media_type="application/vnd.tcpdump.pcap",headers={"Content-Disposition":f'attachment; filename="nscout-{int(pkts[-1]["timestamp"])}.pcap"'})
@api.get("/flows")
async def flows(limit:int=50):return {"flows":analysis.list_flows(list(session.packets),limit=limit)}
@api.get("/flow/stream")
async def flow_stream(a_ip:str,a_port:int,b_ip:str,b_port:int):return analysis.reassemble_stream(list(session.packets),(a_ip,b_ip,a_port,b_port))
@api.get("/geo/{ip}")
async def geo_lookup(ip:str):return await geo.enrich_one(ip)
@api.get("/settings/webhooks")
async def get_webhook_settings():return _webhook_cache
@api.post("/settings/webhooks")
async def save_webhook_settings(body:WebhookSettings):
 doc=body.model_dump();doc["_id"]="webhooks"
 if mongo_available:await settings_col.replace_one({"_id":"webhooks"},doc,upsert=True)
 _webhook_cache.update(body.model_dump());return {"status":"saved" if mongo_available else "saved_in_memory","settings":_webhook_cache}
@api.post("/settings/webhooks/test")
async def test_webhook(body:WebhookTestRequest):return await webhooks.send(body.url,{"severity":"high","type":"Test Alert","title":"nScout test notification","description":"This is a test alert from nScout.","src":"127.0.0.1","dst":"127.0.0.1"})
def _require_mongo():
 if not mongo_available:raise HTTPException(status_code=503,detail="MongoDB is unavailable; saved sessions are disabled")
@api.post("/sessions/save")
async def sessions_save(body:SaveSessionRequest):
 _require_mongo()
 try:meta=await save_session(db,session,body.name)
 except ValueError as e:raise HTTPException(status_code=400,detail=str(e))
 return {"status":"saved",**meta}
@api.get("/sessions")
async def sessions_list():return {"sessions":await list_sessions(db),"mongo_available":True} if mongo_available else {"sessions":[],"mongo_available":False}
@api.post("/sessions/{sid}/load")
async def sessions_load(sid:str):
 _require_mongo()
 try:meta=await load_session(db,session,sid)
 except KeyError:raise HTTPException(status_code=404,detail="session not found")
 return {"status":"loaded",**meta,"stats":session.stats()}
@api.delete("/sessions/{sid}")
async def sessions_delete(sid:str):
 _require_mongo();ok=await delete_session(db,sid)
 if not ok:raise HTTPException(status_code=404,detail="session not found")
 return {"status":"deleted"}
EMERGENT_LLM_KEY=os.environ.get("EMERGENT_LLM_KEY","")
def _build_prompt(pkt,threat):
 if threat:return "Explain this network security anomaly: what happened, why it matters, whether it may be benign, and what to investigate next.\n\n"+json.dumps(threat,default=str)
 if pkt:
  packets=list(session.packets);health=intelligence.annotate_tcp_health(packets).get(str(pkt.get("id")),{"events":[],"healthy":True});connections=intelligence.connection_intelligence(packets);related=[c for c in connections if pkt.get("src_ip") in (c["a_ip"],c["b_ip"]) and pkt.get("dst_ip") in (c["a_ip"],c["b_ip"])][:3];context={"packet":pkt,"tcp_health":health,"related_connections":related,"dns":intelligence.dns_intelligence([pkt]),"http":intelligence.http_intelligence([pkt]),"tls":tls_intelligence([pkt])};return "You are nScout, a senior network investigator. Explain what happened, why the packet exists, whether it looks normal, relevant connection/protocol context, and what to investigate next. Never claim encrypted payload contents are visible.\n\nContext: "+json.dumps(context,default=str)[:12000]
 return "No packet selected."
@api.post("/ai/explain")
async def ai_explain(req:ExplainRequest):
 pkt=session.get_packet(req.packet_id) if req.packet_id else None;threat=next((t for t in session.threats if t.get("id")==req.threat_id),None) if req.threat_id else None
 if not pkt and not threat:raise HTTPException(status_code=404,detail="packet or threat not found")
 prompt=_build_prompt(pkt,threat)
 async def gen():
  if not EMERGENT_LLM_KEY:yield "data: "+json.dumps({"delta":"AI key not configured."})+"\n\n";yield "data: [DONE]\n\n";return
  try:
   from emergentintegrations.llm.chat import LlmChat,UserMessage,TextDelta,StreamDone
   chat=LlmChat(api_key=EMERGENT_LLM_KEY,session_id=f"explain-{req.packet_id or req.threat_id}",system_message="You are nScout, an expert network and security analyst.").with_model("openai","gpt-5.4")
   async for ev in chat.stream_message(UserMessage(text=prompt)):
    if isinstance(ev,TextDelta):yield "data: "+json.dumps({"delta":ev.content})+"\n\n"
    elif isinstance(ev,StreamDone):break
  except ModuleNotFoundError:yield "data: "+json.dumps({"delta":"AI integration is not included in this build. Core analysis remains available."})+"\n\n"
  except Exception as e:yield "data: "+json.dumps({"delta":f"AI error: {e}"})+"\n\n"
  yield "data: [DONE]\n\n"
 return StreamingResponse(gen(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})
@app.websocket("/api/ws")
async def ws_endpoint(ws:WebSocket):
 await ws.accept();q=session.subscribe();stats_task=None
 try:
  await ws.send_json({"type":"stats","data":session.stats()});stats_task=asyncio.create_task(_stats_pulse(ws))
  while True:
   msg=await q.get();await ws.send_json(msg)
   if msg.get("type")=="threat":await _threat_hook(msg["data"])
 except WebSocketDisconnect:pass
 except Exception as e:logger.warning("ws error: %s",e)
 finally:
  session.unsubscribe(q)
  if stats_task is not None:stats_task.cancel()
async def _stats_pulse(ws):
 try:
  while True:await asyncio.sleep(1.0);await ws.send_json({"type":"stats","data":session.stats()})
 except Exception:return
app.include_router(api);app.add_middleware(CORSMiddleware,allow_credentials=True,allow_origins=os.environ.get("CORS_ORIGINS","*").split(","),allow_methods=["*"],allow_headers=["*"])
_UI_DIR=ROOT_DIR/"frontend_build"
if _UI_DIR.exists():
 from fastapi.staticfiles import StaticFiles
 app.mount("/",StaticFiles(directory=str(_UI_DIR),html=True),name="ui")
@app.on_event("startup")
async def startup():await _load_settings()
@app.on_event("shutdown")
async def shutdown():await session.stop();client.close()