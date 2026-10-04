# nScout

A Wireshark-class network monitor with a modern SaaS UI, AI-powered packet
explanations, Geo + ASN enrichment, Follow-stream reassembly, threat alerts,
save-and-replay sessions, PCAP import/export, and Slack / Discord webhooks.

Ships as a single-folder Windows app your colleagues can double-click.

---

## Quick start — build the Windows app

```powershell
# If PowerShell blocks the script, just use build.bat (double-click).
.\build.ps1
```

Prereqs on the build machine:
- Python 3.10 or newer (<https://python.org>)
- Node.js 18 or newer (<https://nodejs.org>)
- Yarn — `npm install -g yarn`

Output: `dist\nScout\` — a self-contained folder (~370 MB).
Share it as a zip; recipients just unzip and double-click `nScout.exe`.

## Automated release build

Push a tag to GitHub and the Windows build runs for you automatically:

```powershell
git tag v0.1.0
git push --tags
```

GitHub Actions attaches `nScout-windows-x64.zip` to the release.

## Live packet capture

nScout auto-detects whether it can capture real packets. If it can't, it
transparently falls back to **Simulated** or **PCAP-upload** mode so you can
still demo every feature.

To unlock live capture on Windows:
1. Install [Npcap](https://npcap.com) (free, from the Wireshark team)
2. Launch nScout as **Administrator**

Then the Interface dropdown will list `Ethernet`, `Wi-Fi`, `Loopback`, etc.

## Development

```powershell
# Backend
cd backend; uvicorn server:app --reload --port 8001

# Frontend (separate shell)
cd frontend; yarn install; yarn start
```

Then visit <http://localhost:3000>.

## Configuration

Put a `.env` next to the binary (or in `backend/`) to override defaults:

```ini
MONGO_URL=mongodb://localhost:27017
DB_NAME=nscout
EMERGENT_LLM_KEY=sk-...           # enables plain-English AI explanations
CORS_ORIGINS=*
```

If `MONGO_URL` is unreachable, nScout still runs — only the "Saved Sessions"
feature is disabled.

## License

Add your own license file before publishing.
