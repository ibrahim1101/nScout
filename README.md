# nScout

Wireshark-class network monitor with a modern SaaS UI, AI-powered packet
explanations, Geo + ASN enrichment, threat alerts, Follow-stream reassembly,
save-and-replay sessions, PCAP import/export, Slack & Discord alerts.

Runs two ways out of the box:

| Mode | Best for | Start command |
|---|---|---|
| **Standalone desktop app** | Colleagues who want "double-click and go" | `./build.sh` then share `dist/nScout/` |
| **Lite web service** | Teams, homelab, VPS, any Docker host | `docker compose up -d` → http://localhost:8001 |

---

## 1. Lite web service (Docker)

```bash
docker compose up -d
open http://localhost:8001
```

That's it. The compose file brings up:
- `nscout` — the FastAPI backend serving the compiled React UI on `:8001`
- `mongo` — MongoDB 7 for saved sessions and settings

To unlock **live packet capture** on a Linux host:
```bash
docker compose -f docker-compose.yml -f docker-compose.capture.yml up -d
```
This grants `CAP_NET_RAW` + `CAP_NET_ADMIN` and shares the host network stack.
On macOS/Windows Docker runs inside a VM — use the standalone build below for
native capture.

Pre-built images are published to GHCR on every `v*` tag push:
```bash
docker run --rm -p 8001:8001 ghcr.io/<your-org>/nscout:latest
```

## 2. Standalone desktop app (PyInstaller)

```bash
./build.sh         # macOS / Linux
.\build.ps1        # Windows
```

Produces `dist/nScout/` — a self-contained folder (~370 MB) that your
colleagues can unzip and double-click. See [BUNDLE_README.md](./BUNDLE_README.md)
for per-OS capture permission instructions.

Automated builds: push a `vX.Y.Z` tag → GitHub Actions produces
`nScout-windows-x64.zip` and `nScout-linux-x64.tar.gz` as release assets.

## 3. Development

```bash
# Backend
cd backend && uvicorn server:app --reload --port 8001

# Frontend (separate shell)
cd frontend && yarn install && yarn start
```

Then visit http://localhost:3000.

---

## Configuration

Environment variables (set in `.env` next to the binary, or in the compose
file, or in your shell):

| Var | Purpose | Default |
|---|---|---|
| `MONGO_URL` | MongoDB connection string | `mongodb://localhost:27017` |
| `DB_NAME` | Database name | `nscout` |
| `CORS_ORIGINS` | Comma-separated allowed origins | `*` |
| `EMERGENT_LLM_KEY` | Enables plain-English AI explanations and threat triage | (empty — AI disabled) |

Settings persisted inside Mongo:
- Webhook URLs (Slack, Discord) and severity threshold → `etherlens_settings`
- Saved capture sessions → `etherlens_sessions`

---

## License

Internal project. Add your own license file before publishing.
