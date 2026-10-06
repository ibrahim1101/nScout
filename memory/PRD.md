# nScout — Product Requirements Document

## Problem statement
A Wireshark-class network monitor with a modern SaaS UI, AI insights, Geo + ASN enrichment, Follow-stream reassembly, threat alerts, save-and-replay sessions, PCAP import/export, Slack & Discord alerts. Distributable both as a standalone desktop app (PyInstaller) and a lite Docker web service.

## Core requirements (static)
- Live packet capture (scapy AsyncSniffer) with simulator fallback
- PCAP upload, export, and session save/replay
- Protocol decode: Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP / DNS / HTTP / HTTPS / TLS + ~25 app-port protocols
- Real-time analytics: packets/sec, bps, protocol distribution, top talkers, timeline
- TCP conversation list + Follow Stream with overlap-aware byte-range reassembly
- Topology map with Geo-IP + ASN enrichment (ip-api.com, cached)
- Threat engine: SYN flood, port scan, ICMP flood, DNS tunneling, cleartext credentials
- AI explanations via Emergent LLM / OpenAI gpt-5.4 (SSE streaming)
- Slack + Discord alert webhooks with severity threshold, Test button, Mongo persistence
- Mongo-backed save & replay captures
- Light & dark themes, responsive down to 390 px
- Two distribution modes:
  1. PyInstaller single-folder desktop app (Windows / macOS / Linux)
  2. Docker lite web service — single `docker compose up`

## What's been implemented
### v1 (2026-01-04)
- Capture engine, dissector, simulator, threat detector
- REST + WS endpoints for packets/threats/stats/topology/ai-explain/pcap-upload
- Full dashboard UI (packet analyzer, analytics, topology, threat feed)
- Tests: 15/15

### v2 (2026-01-04)
- analysis / geo / webhooks modules
- pcap export, flow list, follow stream, geo enrichment, webhook settings + test
- Frontend: Flows tab, FlowDrawer, SettingsDrawer, country flags & ASN on topology
- Tests: 11/11 new + 15/15 regression

### v3 (2026-01-04)
- Session save/list/load/delete persisted in Mongo
- Overlap-aware TCP reassembly (byte-range merge)
- PyInstaller spec + launcher + build.sh / build.ps1 + GitHub Actions
- Static-mount frontend_build when bundled
- Verified 36 MB launcher boots in <2s
- Tests: 7/7 new + 33/33 regression

### v4 (2026-01-04) — nScout + Docker
- Full rebrand EtherLens AI → **nScout** (UI title, FastAPI title, api/, webhook payloads, PyInstaller APP_NAME, build scripts, GitHub Actions artifact names)
- Browser tab + localStorage theme key updated
- Dockerfile (multi-stage): node:20-alpine builds React, python:3.11-slim serves it + API on 8001
- docker-compose.yml (nScout + Mongo 7 with healthcheck + persistent volume)
- docker-compose.capture.yml overlay for CAP_NET_RAW on Linux hosts
- .dockerignore excludes node_modules / build / tests / memory
- GitHub Actions: new `docker` job pushes `ghcr.io/<owner>/nscout:latest` on tag push
- README.md rewritten with 3-way setup (Docker lite / standalone build / dev)
- BUNDLE_README.md updated

### v0.3 — Security Intelligence
- Detection Engine 2.0: explainable passive findings with severity, confidence, state and structured evidence
- Host Intelligence: identity, traffic, services, domains, peers, associated findings and risk scoring
- Investigation Timeline: correlated DNS, TCP, TLS, HTTP and security events with analyst filters
- Advanced Packet Search: boolean logic, parentheses, comparisons, protocol-aware fields and saved filters
- Security Operations Dashboard: posture, severity distribution, risky hosts and recent detections
- Focused deterministic regression suite expanded to 52 passing tests
- Remaining release gate: documentation review plus Windows build/CI verification

## Distribution matrix
| Mode | File | Command | Output |
|---|---|---|---|
| **Lite web service** | `docker-compose.yml` | `docker compose up -d` | 1 container (API + UI), port 8001, Mongo sidecar |
| **Linux live capture** | `+ docker-compose.capture.yml` | `docker compose -f … -f … up` | Host network + NET_RAW |
| **Standalone desktop** | `nscout.spec` + `build.sh` / `build.ps1` | `./build.sh` | `dist/nScout/` folder, double-click |
| **CI releases** | `.github/workflows/build.yml` | `git tag v* && git push --tags` | Windows zip, Linux tar.gz, GHCR docker image |

## Prioritized backlog
### P0
- GridFS-backed session storage so captures > 10k packets fit under BSON 16 MB cap
- Multi-arch docker image (linux/arm64 for M-series Macs / Raspberry Pi)
### P1
- Code-signing cert for Windows installer
- Auto-updater channel
- Suricata-style signature rules alongside behavioural threats
- Persist analyst triage state and notes for Security Intelligence findings
### P2
- Multi-user auth + capture permissions (settings/sessions currently unauth)
- Webhook retry/backoff on 429
- Chunked session loading to never block event loop

## Security hardening
- Backend binds internally only (127.0.0.1 in bundle, 0.0.0.0 in Docker)
- No shell exec on uploads; PCAP parsed in-memory via scapy
- Upload size limit 50 MB
- `tini` as PID 1 in Docker for correct signal handling
- No credentials stored; EMERGENT_LLM_KEY read from env
- CORS gated via env (`CORS_ORIGINS`)
- **Known gap**: `/api/settings/*` and `/api/sessions/*` are unauthenticated — fine for localhost desktop, add auth before exposing to a network.
