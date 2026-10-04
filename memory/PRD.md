# EtherLens AI — Product Requirements Document

## Problem statement
Build a Wireshark-class network monitoring tool with a smoother SaaS GUI and better parsing: real-time traffic charts & bandwidth analytics, packet list + detail decode + filter + protocol stats + flow graph, AI-powered anomaly detection, device/host discovery with topology map, deep protocol decoding, and plain-English AI insights. Must be compatible on most devices and hardened against modern attacks.

## Core requirements (static)
- Live packet capture (scapy AsyncSniffer) with simulator fallback for sandboxed/non-root hosts
- PCAP upload & offline analysis
- Protocol decode: Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP / DNS / HTTP / HTTPS / TLS + app-port inference for ~25 protocols
- Real-time analytics: packets/sec, bps, protocol distribution, top talkers, timeline
- Topology map: local vs external hosts, animated edge flows, host inspector
- Threat engine: SYN flood, port scan, ICMP flood, DNS tunneling, cleartext credentials
- AI explanation (SSE streaming) powered by Emergent LLM key / OpenAI gpt-5.4
- Light & dark themes, responsive down to 390 px

## User persona
Network / SOC engineer who needs quick, visual, explainable traffic analysis without a desktop installer.

## What's been implemented (2026-01)
- Backend (`/app/backend/server.py` + `/app/backend/etherlens/engine.py`)
  - `GET /api/`, `/api/interfaces`, `/api/capture/{start,stop,clear,status}`
  - `GET /api/packets`, `/api/packets/{id}` (full decode + hex)
  - `GET /api/stats/timeline`, `/api/stats/top-talkers`, `/api/topology`, `/api/threats`
  - `POST /api/pcap/upload` (scapy rdpcap)
  - `POST /api/ai/explain` SSE streaming (OpenAI gpt-5.4 via emergentintegrations)
  - `WS /api/ws` live push (stats + threats + notice)
  - Simulator produces realistic TCP/UDP/HTTP/DNS/ICMP/ARP + periodic SYN-flood anomalies
- Frontend (`/app/frontend/src/components/etherlens/*`)
  - HeaderNav (interface select, start/stop/clear/upload, filter bar, dark/light toggle, status pills)
  - PacketAnalyzer (virtual table + protocol tree + hex dump + AI explain)
  - AnalyticsDashboard (recharts area + donut + top talkers)
  - TopologyMap (SVG force-ish layout, animated packet motion)
  - ThreatFeed (severity pills + AI explanation drawer, streaming)
- All interactive elements have `data-testid` in kebab-case
- Backend tests: 15/15 passing (iteration_1.json)

## Prioritized backlog
### P0 (next)
- Live capture permission bootstrap on real hosts (document `setcap cap_net_raw,cap_net_admin+eip`)
- Persist capture history snapshots to MongoDB (saved sessions)
### P1
- Save selection as PCAP export
- Flow conversation reassembly (TCP stream follow)
- Geo-IP enrichment on external hosts
- Advanced BPF-like filter grammar (ip.addr, tcp.port and/or/not)
### P2
- Multi-user auth + capture permissions
- Alert webhooks (Slack, Discord) on critical threats
- Signature-based IDS rules (Suricata-style)

## Security hardening (requested)
- Backend binds internally only (0.0.0.0:8001 via supervisor)
- No shell execution on uploaded files; PCAP parsed in-memory via scapy
- Upload size limit 50 MB
- No credentials stored; EMERGENT_LLM_KEY read from env
- CORS controlled via env (`CORS_ORIGINS`)
