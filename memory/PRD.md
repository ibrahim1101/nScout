# EtherLens AI — Product Requirements Document

## Problem statement
A Wireshark-class network monitoring tool with a smoother SaaS GUI, better parsing, AI insights, Geo + ASN enrichment, threat alerts and distributable as a double-click desktop app.

## Core requirements (static)
- Live packet capture (scapy AsyncSniffer) with simulator fallback for sandboxed/non-root hosts
- PCAP upload, export, and session save/replay
- Protocol decode: Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP / DNS / HTTP / HTTPS / TLS + ~25 app-port protocols
- Real-time analytics: packets/sec, bps, protocol distribution, top talkers, timeline
- TCP conversation list + Follow Stream with **overlap-aware** reassembly (byte-range merge)
- Topology map with Geo-IP + ASN enrichment (country flags) via ip-api.com
- Threat engine: SYN flood, port scan, ICMP flood, DNS tunneling, cleartext credentials
- AI explanations (SSE streaming) via Emergent LLM key / OpenAI gpt-5.4
- Slack + Discord alert webhooks with severity threshold, Test button, Mongo persistence
- Save & replay captures from MongoDB
- Light & dark themes, responsive down to 390 px
- Distributable as PyInstaller single-folder app (Windows / macOS / Linux)

## What's been implemented
### v1 (2026-01-04)
- Backend capture engine, dissector, simulator, threat detector
- REST + WS endpoints for packets/threats/stats/topology/ai-explain/pcap-upload
- Frontend: HeaderNav, PacketAnalyzer (list + protocol tree + hex + AI), AnalyticsDashboard, TopologyMap, ThreatFeed
- Tests: 15/15

### v2 (2026-01-04)
- Backend: analysis (reassembly, pcap-export, flow list), geo (ip-api cache), webhooks (Slack + Discord)
- Endpoints: pcap/export, flows, flow/stream, geo/{ip}, topology?enrich=true, settings/webhooks (GET/POST/test)
- Frontend: Flows tab, FlowDrawer, SettingsDrawer, Export button in header, country flags + ASN on topology
- Tests: 11/11 new + 15/15 regression

### v3 (2026-01-04)
- Backend: sessions module (save/list/load/delete) persisting full packet hex in Mongo
- Overlap-aware TCP reassembly (byte-range merge, kills retransmit duplication)
- PyInstaller spec + launcher.py + .env.example + build.sh / build.ps1
- Static-mount `frontend_build/` from FastAPI when bundled
- GitHub Actions workflow (.github/workflows/build.yml) builds Windows + Linux artifacts on tag push
- BUNDLE_README.md shipped with each release
- Frontend: SessionsDrawer, REPLAY status pill, same-origin ws fallback in lib.js
- Tests: 7/7 new + 33/33 total regression (iteration_3.json)
- Verified bundle: 36 MB launcher, 367 MB folder, boots in <2s, serves API+UI on port 8001/8002

## Distribution
Three paths, documented in `/app/PACKAGING.md` and `/app/BUNDLE_README.md`:
1. **PyInstaller** (`./build.sh` on Linux/mac, `.\build.ps1` on Windows) → single folder
2. **Docker Compose** (compose file in PACKAGING.md)
3. **Tauri** desktop app (scaffolded in PACKAGING.md)

GitHub Actions auto-build on `git tag v*` push → produces `EtherLens-windows-x64.zip` and `EtherLens-linux-x64.tar.gz` as release assets.

## Prioritized backlog
### P0
- GridFS-backed session storage so captures > 10k packets fit under BSON 16MB cap
- Overlap merge aware of TCP seq wraparound (2^32 boundary)
### P1
- Signed Windows / macOS code-signing cert for the installer
- Auto-updater channel (Tauri path, if adopted)
- Suricata-style signature rules alongside behavioral threats
### P2
- Multi-user auth + capture permissions
- Webhook retry/backoff on 429
- Chunked session loading (asyncio.to_thread) to never block the event loop

## Security hardening
- Backend binds internally only (127.0.0.1 in bundle, 0.0.0.0 behind ingress in cloud)
- No shell exec on uploads; PCAP parsed in-memory via scapy
- Upload size limit 50 MB; session save limit called out for Mongo 16 MB BSON
- No credentials stored; EMERGENT_LLM_KEY read from env
- CORS gated via env (`CORS_ORIGINS`)
- **Known gap**: `/api/settings/*` and `/api/sessions/*` are unauthenticated — fine for localhost desktop, add shared-secret / token before exposing to a network.
