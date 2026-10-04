# EtherLens AI — Standalone Build

This folder is a self-contained copy of EtherLens. Share it with colleagues —
no Python, Node, or developer tools required on their machine.

## Run it

**Windows**
1. Double-click `EtherLens.exe`.
2. A console window opens and your browser auto-launches at `http://127.0.0.1:8001`.
3. Click **Start** to begin monitoring.

**macOS / Linux**
```bash
./EtherLens
```
Then open <http://127.0.0.1:8001> in your browser.

## Live packet capture

EtherLens auto-detects whether it can capture real packets. If permissions are
missing, it transparently falls back to **Simulated** or **PCAP** mode so you
can still demo every feature.

| OS | What to install | One-time command |
|---|---|---|
| **Windows** | [Npcap](https://npcap.com) (free) | Install the MSI, then run EtherLens as Administrator. |
| **macOS** | ChmodBPF (ships with Wireshark) *or* run with `sudo`. | `sudo ./EtherLens` |
| **Linux** | libpcap (usually preinstalled). | `sudo setcap cap_net_raw,cap_net_admin+eip ./EtherLens` |

## Optional configuration

Place a `.env` file next to the executable to override defaults:

```ini
MONGO_URL=mongodb://localhost:27017
DB_NAME=etherlens
EMERGENT_LLM_KEY=sk-...           # enables plain-English AI explanations
CORS_ORIGINS=*
```

If `MONGO_URL` is unreachable, EtherLens still runs — only the "Saved Sessions"
feature is disabled.

## What's inside?

- `EtherLens(.exe)` – single launcher that starts the FastAPI backend and
  serves the React UI at the same origin.
- `frontend_build/` – compiled React app (static files).
- `_internal/` or `*.so` / `*.dll` – Python runtime bundled by PyInstaller.
- `.env.example` – template for configuration.

## Troubleshooting

- **"Mongo connection failed"** – install MongoDB locally
  (`brew install mongodb-community` / `winget install MongoDB.Server`) or point
  `MONGO_URL` at a managed instance (Atlas, Railway, etc.).
- **"No interfaces listed"** – install Npcap on Windows or run with
  elevated privileges on macOS/Linux. The **Simulated** interface always works.
- **AI explanations say "AI key not configured"** – set `EMERGENT_LLM_KEY`
  in your `.env`.
