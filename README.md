# nScout

**nScout — Network Intelligence, Made Clear.**

nScout is a defensive network monitoring, packet-analysis and investigation platform built to turn raw network traffic into understandable security context. It can inspect live traffic or imported PCAP captures, reconstruct conversations between hosts, analyze protocol behavior, surface network-health problems and defensive security findings, and provide an investigation workspace for drilling from a device or connection all the way down to individual packets.

The current stable release is [**nScout v0.3.0 — Security Intelligence**](https://github.com/ibrahim1101/nScout/releases/tag/v0.3.0), available as a native Windows installer and portable ZIP. **v0.4.0 — Investigation Platform is in development** on `v0.4-investigation-platform`; its features are not yet included in the stable installer. Follow [the development PR](https://github.com/ibrahim1101/nScout/pull/3) for progress.

## What nScout does

Instead of treating every packet as an isolated row, nScout correlates packets into devices, connections, protocol activity, timelines and security context. This helps answer questions such as:

- Which devices are communicating on the network?
- Which host initiated a connection and where did it go?
- Which DNS lookup led to a particular connection?
- Did a TCP conversation experience retransmissions, resets or other health problems?
- What HTTP information is visible in unencrypted traffic?
- What TLS metadata is observable without decrypting HTTPS?
- Are there scan-like patterns, unusual DNS activity, ARP changes, traffic spikes or other activity worth investigating?
- Which packets provide the evidence behind a finding?

### Deep Packet Inspector

Inspect Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP and observable TLS metadata. Packet views include protocol layers, TCP flags and sequence/ACK information, timestamps, payload sizing, raw HEX, printable ASCII, TCP-health context, security context and packet explanations.

### Connection Intelligence & Connection Story

nScout reconstructs bidirectional network conversations and tracks endpoints, packet/byte counts, duration, connection state, resets and TCP-health signals. **Connection Story** correlates the sequence of observable events so an analyst can follow activity such as:

`DNS lookup -> resolved IP -> TCP handshake -> TLS/HTTP activity -> traffic -> connection close`

### DNS, HTTP & TLS Intelligence

- **DNS:** queries, responses, resolved addresses, response codes, TTL information, failed lookups and domain-to-connection correlation.
- **HTTP:** visible unencrypted requests/responses, methods, hosts, URLs, user agents, status codes and content metadata.
- **TLS:** observable metadata such as SNI, TLS version, ALPN, cipher information and certificate metadata when available.

nScout does **not** decrypt HTTPS or claim visibility into encrypted application payloads.

### TCP Health Analysis

Analyze retransmissions, duplicate ACKs, out-of-order traffic, zero-window conditions, resets, handshake problems and RTT/latency information.

### Device Discovery & Protocol Dashboard

Build an observed inventory of devices and endpoints with IP/MAC information, hostnames where available, traffic statistics and protocol activity. Dashboard views summarize protocols, top talkers, ports, domains and endpoints.

### Defensive Security Analysis

nScout produces investigation leads for activity such as scan/flood patterns, suspicious ports, ARP identity changes, unusual DNS behavior, visible cleartext-authentication indicators, failed TCP connections, beacon-like periodic traffic, abnormal traffic spikes and suspicious/reserved destinations.

These findings are defensive heuristics and investigation leads, **not proof of compromise**. Analyst validation is still required.

Detection Engine 2.0 enriches each finding with severity, confidence, investigation state and structured evidence. Host Intelligence associates those findings with observed hosts and calculates a transparent, bounded risk score for prioritization.

### Network Map & Timeline

Explore observed hosts and connections through an investigation-oriented topology with focus/filter controls, traffic-weighted links, security overlays and direct connection drill-down. The packet timeline highlights traffic bursts, DNS events, connection activity, errors and findings.

The v0.3 Investigation Timeline adds a chronological evidence view that correlates DNS queries/answers, TCP lifecycle events, TLS/HTTP metadata and security findings. It can be filtered by host, domain, connection/port, protocol, severity and time range.

### Advanced Packet Search

The v0.3 search parser supports `AND`, `OR`, `NOT`, parentheses, comparisons and `contains` across packet, endpoint, DNS, HTTP, TLS, TCP-health and security-severity fields. Legacy compact filters such as `ip:10.0.0.15 port:443 bytes>1000` remain supported. Malformed expressions are rejected with a clear validation error; expressions are parsed without dynamic code execution.

### PCAP Investigation Workspace

Import an existing PCAP and let nScout build an investigation summary covering devices, connections, protocols, DNS activity, security findings, anomalies, interesting packets and traffic statistics. PCAP analysis works even when live capture is unavailable.

### Explain Packet / Connection

Deterministic explanations combine packet, connection, TCP-health, DNS, HTTP, TLS and defensive-security context to explain what was observed and suggest useful next investigation steps. Optional AI-assisted explanations can add plain-language context when configured; core analysis does not require an AI key.

### Investigation Reports

Export investigation information as **JSON, standalone HTML or PDF** for sharing or later analysis.

## Installation — Windows

### Recommended: Windows installer

1. Open the **Releases** section of this repository and select **nScout v0.3.0** (or the newest stable release).
2. Download `nScout-Setup-0.3.0-windows-x64.exe`.
3. Run the installer and complete the setup wizard.
4. Launch **nScout** from the Start Menu or desktop shortcut created by the installer.
5. nScout starts its local backend and opens the application in your default browser.
6. For **live packet capture**, install **Npcap** and run nScout with sufficient capture permissions. Without live-capture access, PCAP investigation and simulated traffic remain available.

The packaged Windows build does **not** require Python, Node.js or Yarn to be installed.

### Portable Windows build

1. Download `nScout-windows-x64.zip` from the same release.
2. Extract the ZIP to a folder of your choice.
3. Run `nScout.exe` from the extracted `nScout` folder.
4. Your browser should open the local nScout interface automatically.

Do not run the executable directly from inside the ZIP; extract the complete bundle first because the executable depends on files packaged beside it.

## Live packet capture requirements

### Windows

Install **Npcap** to provide packet-capture support. Running nScout as Administrator may be necessary depending on the system configuration. If capture permissions or a capture driver are unavailable, nScout can still be used for PCAP investigation and simulated traffic.

### Linux / macOS

Native Linux packaging is being developed. The application architecture already supports Linux/macOS execution from compatible builds/source, but the Windows package should not be treated as a Linux/macOS installer.

On Linux, live capture normally requires libpcap and suitable capabilities/permissions. A typical capability configuration for a native binary is:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./nScout
```

## Application modes

nScout supports three practical analysis modes:

- **Live Capture** — monitor traffic from a supported local network interface.
- **PCAP Investigation** — import an existing packet capture for offline analysis.
- **Simulated Traffic** — demonstrate and test investigation features when live capture is unavailable.

## Optional configuration

The standalone application works without a custom configuration for its core analysis workflow. Optional environment settings can be supplied through a `.env` file in the runtime environment:

```ini
MONGO_URL=mongodb://localhost:27017
DB_NAME=nscout
EMERGENT_LLM_KEY=your-key-here
CORS_ORIGINS=*
```

MongoDB is currently used for persisted saved sessions/settings. If MongoDB is unavailable, nScout continues to run while persistence-dependent functionality such as Saved Sessions is unavailable.

On the v0.4 development branch, optional local LLM settings persist independently of MongoDB. See the setup section below.

The AI integration is optional. Packet capture, protocol parsing, deterministic investigation intelligence, PCAP analysis and reporting do not require an AI key. Never commit API keys or credentials to the repository.

## Build from source

### Prerequisites

- Python 3.10+
- Node.js 18+
- Yarn
- A compatible packet-capture driver/library for live capture

### Backend

```powershell
cd backend
python -m pip install -r requirements.txt
uvicorn server:app --reload --port 8001
```

### Frontend

In a separate shell:

```powershell
cd frontend
yarn install
yarn start
```

The development frontend normally runs on port `3000` and communicates with the FastAPI backend.

### Build the Windows application

```powershell
# If PowerShell blocks the script, build.bat can be used instead.
.\build.ps1
```

The PyInstaller application bundle is written under `dist\nScout\`.

## Architecture

nScout uses:

- **FastAPI / Python** — capture control, packet APIs and investigation services.
- **Scapy** — packet parsing/capture and PCAP processing.
- **React** — analyst interface.
- **WebSockets** — live application updates.
- **MongoDB / Motor / PyMongo** — optional persisted sessions/settings.
- **PyInstaller** — standalone application packaging.
- **Inno Setup** — native Windows installer.
- **GitHub Actions** — automated verification and Windows release builds.

## nScout v0.2.0

The Intelligence Update includes the completed investigation scope:

1. Deep Packet Inspector
2. Connection Intelligence
3. DNS Intelligence
4. HTTP Inspector
5. TLS Inspector
6. TCP Health Analysis
7. Device Discovery
8. Protocol Dashboard
9. Packet Timeline
10. Smart Filters
11. Security Analysis
12. Explain Packet / Connection
13. PCAP Investigation Workspace
14. HTML / PDF / JSON Investigation Reporting

The v0.2.0 Windows release is built automatically through GitHub Actions and packaged as both a native installer and a portable ZIP.

## nScout v0.3 Security Intelligence

The v0.3 milestone adds:

1. Detection Engine 2.0 with explainable evidence and confidence metadata
2. Host Intelligence profiles and severity/confidence-based risk scoring
3. Correlated Investigation Timeline
4. Advanced boolean packet search with saved filters and history
5. Security Operations Dashboard with posture, severity and risky-host views
6. Expanded focused regression coverage (52 tests)

See [the v0.3 Security Intelligence guide](docs/v0.3-security-intelligence.md) for rule coverage, filter syntax, API routes, risk scoring and the recommended analyst workflow.

## nScout v0.4.0 — Investigation Platform (in development)

v0.4 extends the security-intelligence foundation into a persistent analyst workflow.
The development branch currently includes:

- Expanded settings foundation for capture, investigation, privacy and detection preferences.
- Investigation workspace lifecycle foundation with regression coverage; full application integration remains in progress.
- Optional local LLM explanations for selected packets, findings and connections, using Ollama, LM Studio or a custom local OpenAI-compatible server.
- AI disabled by default, with backend enforcement, model discovery, connection testing, model selection and timeout/output limits.
- Persistent AI settings without MongoDB and observed-context fallback when local inference is unavailable.

Capture preference wiring, workspace recovery, investigation notes/bookmarks,
evidence locker, finding lifecycle, Live Hosts, PCAP comparison, baselines,
expanded exports/redaction and further map/UI improvements remain under development.
See [the v0.4 roadmap and setup guide](docs/v0.4-investigation-platform.md) for scope and progress.
Full AI Analyst remains planned for v0.5; Sensor Mode and threat-intelligence integrations are later milestones.

### Connect a local model (v0.4 development builds)

1. Start a model server on the same computer as the nScout backend.
2. Open **Settings → AI integration**, enable AI and select **Ollama**, **LM Studio** or a custom local provider.
3. Enter the API base URL: `http://127.0.0.1:11434/v1` for Ollama or `http://127.0.0.1:1234/v1` for LM Studio.
4. **Test connection / discover models**, choose or enter the exact model ID, then **Save**.

Local providers need no cloud AI key. Only loopback endpoints are supported;
local failures never automatically switch to cloud AI. Select a locally running
model in your server. The existing cloud integration remains a separate explicit
provider selection. See the guide for optional authentication and data-directory settings.

### Validation status

The current v0.4 development implementation has **75 passing focused backend regression tests**,
and the changed frontend files pass syntax validation. Full frontend build,
real-model testing and packaged Windows end-to-end validation remain pending.
This is development progress, not a v0.4 release announcement.

## Project maturity & accuracy

nScout is an actively evolving defensive-security project rather than a claim of feature parity with mature commercial packet-analysis suites. Protocol visibility depends on what is observable in the capture. Encrypted application payloads remain encrypted, and heuristic findings require analyst validation.

## Responsible use

nScout is intended for defensive network monitoring, troubleshooting, education and analysis of traffic you are authorized to inspect. Users are responsible for complying with applicable privacy, network and computer-access rules.

## License

nScout is free and open-source software licensed under the **GNU General Public License v3.0 (GPL-3.0)**. You may use, study, modify and redistribute nScout under the terms of GPLv3. Distributed modified versions must preserve the freedoms and obligations required by the GPL, including corresponding-source requirements where applicable.

Copyright © 2026 Shaik Ibrahim.

See [`LICENSE`](LICENSE) for the full license terms.
