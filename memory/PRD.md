# EtherLens AI — Product Requirements Document

## Problem statement
Build a Wireshark-class network monitoring tool with a smoother SaaS GUI and better parsing: real-time traffic charts & bandwidth analytics, packet list + detail decode + filter + protocol stats + flow graph, AI-powered anomaly detection, device/host discovery with topology map, deep protocol decoding, and plain-English AI insights. Must be compatible on most devices and hardened against modern attacks.

## Core requirements (static)
- Live packet capture (scapy AsyncSniffer) with simulator fallback for sandboxed/non-root hosts
- PCAP upload & offline analysis
- PCAP export of current session
- Protocol decode: Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP / DNS / HTTP / HTTPS / TLS + app-port inference for ~25 protocols
- Real-time analytics: packets/sec, bps, protocol distribution, top talkers, timeline
- TCP conversation list + Follow Stream reassembly (bi-directional, text/hex mode auto)
- Topology map with Geo-IP + ASN enrichment (country flags, org, city) via ip-api.com
- Threat engine: SYN flood, port scan, ICMP flood, DNS tunneling, cleartext credentials
- AI explanation (SSE streaming) powered by Emergent LLM key / OpenAI gpt-5.4
- Alert webhooks: Slack & Discord with severity threshold + Test button + Mongo-persisted settings
- Light & dark themes, responsive down to 390 px

## User persona
Network / SOC engineer who needs quick, visual, explainable traffic analysis without a desktop installer.

## What's been implemented
### v1 (2026-01-04)
- Full backend `etherlens/engine.py` (capture session, simulator, dissector, threat detection)
- Backend endpoints: health, interfaces, capture/*, packets, threats, stats/*, topology, pcap/upload, ai/explain (SSE), WS /api/ws
- Frontend: HeaderNav, PacketAnalyzer (3-pane list+tree+hex+AI), AnalyticsDashboard, TopologyMap, ThreatFeed, dark/light theme
- Tests: 15/15 passing (`/app/test_reports/iteration_1.json`)

### v2 (2026-01-04)
- Backend: `etherlens/analysis.py` (TCP reassembly, pcap export, flow listing), `etherlens/geo.py` (ip-api batch + cache + country flag), `etherlens/webhooks.py` (Slack + Discord payloads, severity gating)
- New endpoints: `GET /api/pcap/export`, `GET /api/flows`, `GET /api/flow/stream`, `GET /api/geo/{ip}`, `GET /api/topology?enrich=true`, `GET/POST /api/settings/webhooks`, `POST /api/settings/webhooks/test`
- Threat → webhook fan-out wired into WS endpoint
- Frontend: new Flows tab, FlowDrawer modal, SettingsDrawer, "Export" + settings button in header, country flags & ASN badges on topology map
- Mongo collection `etherlens_settings` persists webhook config
- Tests: 11/11 new passing + 15/15 regression (`/app/test_reports/iteration_2.json`)
- `/app/PACKAGING.md` guide for Docker / PyInstaller / Tauri distribution

## Prioritized backlog
### P0
- Live capture permission bootstrap docs per OS (now in PACKAGING.md)
- Persist saved capture sessions in Mongo
### P1
- Overlap-aware TCP reassembly (merge retransmits by byte range not just seq)
- Signature-based IDS rules (Suricata-style)
- Advanced BPF-like filter grammar
### P2
- Multi-user auth + capture permissions (settings endpoint currently unauth)
- Webhook retry/backoff on 429
- Backfill ASN/geo in topology via background task to never block UI

## Security hardening
- Backend binds internally only (0.0.0.0:8001 via supervisor)
- No shell execution on uploaded files; PCAP parsed in-memory via scapy
- Upload size limit 50 MB
- No credentials stored; EMERGENT_LLM_KEY read from env
- CORS controlled via env (`CORS_ORIGINS`)
- Webhook settings persisted — recommend adding auth before public deployment
