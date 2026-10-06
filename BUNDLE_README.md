# nScout — Standalone Build

This folder is a self-contained copy of nScout. Share it with colleagues —
no Python, Node, or developer tools required on their machine.

## Run it

**Windows**
1. Double-click `nScout.exe`.
2. A console window opens and your browser auto-launches at `http://127.0.0.1:8001`.
3. Click **Start** to begin monitoring.

## v0.3 investigation workflow

The Security Intelligence build adds Detection Engine findings, host risk
profiles, a correlated Investigation Timeline, advanced boolean packet search
and an operator-focused security dashboard.

1. Start a capture or upload an authorized PCAP.
2. Open **Analytics** to review security posture and prioritized hosts.
3. Use **Intelligence** to inspect hosts, connections, domains and findings.
4. Use **Timeline** and **Advanced Packet Search** to locate packet evidence.
5. Export JSON, HTML or PDF investigation reports when needed.

Security findings are passive heuristic leads, not proof of compromise. nScout
does not decrypt HTTPS application payloads.

**macOS / Linux**
```bash
./nScout
```
Then open <http://127.0.0.1:8001> in your browser.

## Live packet capture

nScout auto-detects whether it can capture real packets. If permissions are
missing, it transparently falls back to **Simulated** or **PCAP** mode so you
can still demo every feature.

| OS | What to install | One-time command |
|---|---|---|
| **Windows** | [Npcap](https://npcap.com) (free) | Install the MSI, then run nScout as Administrator. |
| **macOS** | ChmodBPF (ships with Wireshark) *or* run with `sudo`. | `sudo ./nScout` |
| **Linux** | libpcap (usually preinstalled). | `sudo setcap cap_net_raw,cap_net_admin+eip ./nScout` |

## Optional configuration

Place a `.env` file next to the executable to override defaults:

```ini
MONGO_URL=mongodb://localhost:27017
DB_NAME=nscout
EMERGENT_LLM_KEY=sk-...           # enables plain-English AI explanations
CORS_ORIGINS=*
```

If `MONGO_URL` is unreachable, nScout still runs — only the "Saved Sessions"
feature is disabled.

## Troubleshooting

- **"Mongo connection failed"** – install MongoDB locally
  (<https://www.mongodb.com/try/download/community>) or point `MONGO_URL` at a
  managed instance (Atlas, Railway, etc.). The app still runs without Mongo —
  only the *Saved Sessions* feature is disabled.
- **"No interfaces listed"** – install Npcap on Windows or run with
  elevated privileges. The **Simulated** interface always works.
- **AI explanations say "AI key not configured"** – set `EMERGENT_LLM_KEY`
  in your `.env`.
