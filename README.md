# nScout

nScout is a defensive network monitoring and investigation platform for live traffic and PCAP analysis. It combines packet inspection, connection and protocol intelligence, TCP health analysis, device discovery, security findings, investigation workflows, and optional AI-assisted explanations in a modern web UI.

> **Development status:** nScout is under active development. The Intelligence Update is implemented and being finalized on the `intelligence-ui` branch before review, merge and packaging as a new Windows release. The latest stable release does not necessarily contain the in-development capabilities described below.

## What nScout does

Current Intelligence Update capabilities include:

- Deep Packet Inspector for Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP and observable TLS metadata, with Summary, Layers, Connection, Protocol, TCP Health, Hex/ASCII, Security and Explain views.
- Raw packet hex and printable ASCII plus detailed protocol fields such as TCP sequence/ACK information, flags, options, payload sizing and IP fragmentation/checksum metadata.
- Connection intelligence that groups bidirectional conversations and tracks endpoints, packets, directional bytes, duration, state, resets and TCP-health signals.
- Connection Story reconstruction that correlates observed conversation, protocol, DNS and TLS context while preserving encryption boundaries.
- TCP health analysis for retransmissions, duplicate ACKs, out-of-order traffic, zero-window conditions and resets.
- DNS intelligence with query/response events, answer data, TTL/response-code information and failed lookup visibility.
- HTTP inspection for unencrypted traffic, including methods, hosts, URLs, user agents, response status and content metadata when observable.
- TLS intelligence based only on metadata visible without decrypting HTTPS. When decoded from the capture, nScout can summarize SNI, TLS version, ALPN, cipher suites, handshake types and certificate subject/issuer/expiry metadata, and can flag observable legacy TLS or expired-certificate conditions. Port-only HTTPS observations remain explicitly metadata-only. nScout does **not** decrypt or claim to inspect encrypted application payloads.
- Device discovery and traffic/protocol activity by observed endpoint.
- Protocol dashboard and packet timeline analysis.
- Smart analyst filters/search for captured packets, including endpoint-aware IP filtering used by Connection Story packet drill-down.
- Defensive security analysis for scan/flood and unusual DNS heuristics, cleartext-authentication indicators, ARP identity changes, failed TCP connections, periodic/beacon-like outbound traffic, abnormal traffic spikes and conservative special/reserved-destination findings. These are investigation leads, not proof of compromise.
- Focused Network Map for scalable topology investigation, including Map/List views, live/frozen snapshots, Focus Mode, low-noise/high-volume views, protocol/host/port/search filters, traffic-weighted links, security overlays, host inspection and clickable connection drill-down into Connection Story. Topology investigation targets are routed directly through application state into Intelligence rather than relying on browser-storage or DOM-navigation workarounds.
- Dedicated PCAP Investigation Workspace with automatic summary, protocol/device/connection/security context and interesting-packet navigation into the Deep Packet Inspector.
- Investigation report generation in JSON, standalone HTML and portable PDF.
- Follow-stream TCP reconstruction, topology/Geo enrichment, saved sessions and Slack/Discord webhook support.
- Optional contextual AI explanation of packets/security findings when an AI integration is configured. Explanations are instructed not to infer encrypted payload contents.

## Intelligence Update

The approved investigation scope is:

1. Deep Packet Inspector
2. Connection Intelligence
3. DNS Intelligence
4. HTTP Inspector
5. TLS Inspector
6. TCP Health Analysis
7. Device Discovery
8. Protocol Dashboard
9. Packet Timeline
10. Smarter Filters
11. Security Analysis
12. Contextual Explain Packet / Connection
13. PCAP Investigation Workspace
14. HTML / PDF / JSON Investigation Reporting

The major analysis and investigation workflows above are now implemented on `intelligence-ui`. The topology workflow has also been redesigned around progressive disclosure rather than a dense all-connections graph: analysts can filter or focus the map, select a host or edge, inspect security context, and route that selection directly into Intelligence where a matching reconstructed connection opens in Connection Story. Connection packet drill-down uses endpoint-aware filtering so both sides of the selected conversation are preserved. Finalization work is focused on contextual Explain Connection polish, loading/error/empty-state polish, regression coverage, documentation accuracy and final CI validation. Release packaging remains deliberately deferred until the feature branch is reviewed.

## Application modes

nScout supports three practical analysis modes:

- **Live capture** — capture traffic from a supported local network interface.
- **PCAP investigation** — import an existing packet capture for offline analysis.
- **Simulated traffic** — use generated traffic when live capture is unavailable or for demonstrations/testing.

Live packet capture depends on the operating system and packet-capture driver. On Windows, install Npcap and run nScout with sufficient capture permissions. If live capture is unavailable, PCAP and simulated modes remain usable.

## Windows builds

The repository contains a PyInstaller-based Windows build pipeline that produces the nScout application folder and portable ZIP. Inno Setup support is also present for installer packaging.

**Important:** release packaging is intentionally deferred while the Intelligence Update is being completed and reviewed. Do not assume the current development branch represents a finished installer release.

To build locally from source on Windows:

```powershell
# If PowerShell blocks the script, build.bat can be used instead.
.\build.ps1
```

Build-machine prerequisites currently include:

- Python 3.10+
- Node.js 18+
- Yarn

The PyInstaller output is written under `dist\nScout\`.

## Development

Backend:

```powershell
cd backend
uvicorn server:app --reload --port 8001
```

Frontend in a separate shell:

```powershell
cd frontend
yarn install
yarn start
```

The development frontend is normally available on `http://localhost:3000` and communicates with the FastAPI backend.

## Configuration

Environment variables can be supplied through a `.env` file in the backend/runtime environment.

```ini
MONGO_URL=mongodb://localhost:27017
DB_NAME=nscout
EMERGENT_LLM_KEY=your-key-here
CORS_ORIGINS=*
```

MongoDB is currently used for persisted saved sessions/settings. If MongoDB is unavailable, the packet-analysis application continues to run, while persistence-dependent features such as Saved Sessions are unavailable.

The AI integration is optional. Core capture, protocol parsing and investigation intelligence do not require an AI key. Never commit API keys or other credentials to the repository.

## Architecture

nScout currently uses:

- **FastAPI / Python** for capture control, packet APIs and investigation services.
- **Scapy** for packet parsing/capture and PCAP processing.
- **React** for the frontend analyst interface.
- **MongoDB** for current persisted sessions/settings when available.
- **PyInstaller** for portable Windows application packaging.
- **Inno Setup** for the developing Windows installer pipeline.

## Project maturity and accuracy

nScout is an actively evolving project rather than a claim of feature parity with mature packet-analysis suites. Documentation should describe capabilities that are actually implemented or explicitly mark them as in development. Protocol visibility depends on what is observable in the capture: encrypted application payloads cannot be inferred simply because TLS traffic is present, and heuristic security findings require analyst validation.

## Responsible use

nScout is intended for defensive network monitoring, troubleshooting, education and analysis of traffic you are authorized to inspect. Users are responsible for complying with applicable privacy, network and computer-access rules.

## License

A project license has not yet been selected. Add an appropriate license before distributing the project under licensing terms that have not been decided.