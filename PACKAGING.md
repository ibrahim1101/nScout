# Packaging EtherLens AI for Distribution

EtherLens AI is a **React (frontend) + FastAPI (backend) + MongoDB (data)** app, so a true single-file `.exe` isn't quite right. Here are the three practical ways to let colleagues "install and use it", from easiest to most polished.

---

## Option 1 — Docker Desktop (easiest, works on Win / macOS / Linux)

Give your colleagues two files and they type one command.

**`docker-compose.yml`**
```yaml
version: "3.9"
services:
  mongo:
    image: mongo:7
    volumes: ["mongodb_data:/data/db"]
  backend:
    build: ./backend
    environment:
      - MONGO_URL=mongodb://mongo:27017
      - DB_NAME=etherlens
      - CORS_ORIGINS=*
      - EMERGENT_LLM_KEY=${EMERGENT_LLM_KEY}
    # live capture needs host network + privileges:
    network_mode: host
    cap_add: ["NET_RAW", "NET_ADMIN"]
    depends_on: [mongo]
  frontend:
    build: ./frontend
    ports: ["3000:3000"]
    environment:
      - REACT_APP_BACKEND_URL=http://localhost:8001
volumes:
  mongodb_data:
```

Then share: `docker compose up -d` → open `http://localhost:3000`.

---

## Option 2 — PyInstaller single-folder app (true "double-click to run")

Bundle backend + a static build of the frontend into one executable.

1. **Build the frontend as static files**:
   ```bash
   cd frontend
   yarn build          # produces /frontend/build/*
   ```
2. **Serve the static files from FastAPI** (one-liner addition to `server.py`):
   ```python
   from fastapi.staticfiles import StaticFiles
   app.mount("/", StaticFiles(directory="frontend_build", html=True), name="ui")
   ```
3. **Copy** `frontend/build` → `backend/frontend_build/` so PyInstaller includes it.
4. **Bundle with PyInstaller**:
   ```bash
   pip install pyinstaller
   cd backend
   pyinstaller --name etherlens \
       --add-data "frontend_build:frontend_build" \
       --add-data ".env:." \
       --collect-all scapy --collect-all emergentintegrations \
       --onedir server.py
   ```
5. **Users double-click** `dist/etherlens/etherlens.exe` → opens `http://localhost:8001`.
   Point MongoDB at a local/managed instance (set `MONGO_URL` in a `.env` next to the binary) or embed [TinyDB] / [SQLite] in place of Mongo for a zero-dependency build.

**Live capture permissions** — you still need:
- **Windows**: install [Npcap](https://npcap.com) (free)
- **macOS**: `sudo` first launch or `chmod +e` on the capture binary
- **Linux**: `sudo setcap cap_net_raw,cap_net_admin+eip ./etherlens`

Without those, the app automatically falls back to Simulated Mode.

---

## Option 3 — Tauri desktop app (polished `.exe` / `.dmg` / `.AppImage`)

Highest quality — a 10 MB native window around the web UI.

1. `cargo create-tauri-app etherlens-desktop` (choose React / existing frontend).
2. Point Tauri's `distDir` at `frontend/build`.
3. In `tauri.conf.json`, add a `beforeDevCommand` that spawns `python -m uvicorn server:app --port 8001` and a `beforeBuildCommand` that copies the PyInstaller bundle (`dist/etherlens`) into `src-tauri/resources/`.
4. `cargo tauri build` → ships signed `.msi` (Windows), `.dmg` (macOS), `.deb`/`.AppImage` (Linux). Each is ~15 MB + the Python bundle.

Users get a real desktop icon, auto-updater, native menus, no browser needed.

---

## Live-capture permission cheat-sheet

| OS      | What to install / do                                                                 |
|---------|---------------------------------------------------------------------------------------|
| Windows | Install **Npcap** (free). Run EtherLens as Administrator the first time.              |
| macOS   | `sudo chmod +rw /dev/bpf*` once, or run with `sudo`. For a signed app: BPF entitlement.|
| Linux   | `sudo setcap cap_net_raw,cap_net_admin+eip $(which python)` or run as root.            |

Without any of the above the app still runs — it just stays in **Simulated Mode** (watermarked in the header).

---

## Which should you pick?

- **Internal team, dev-savvy** → Option 1 (Docker).
- **Non-technical colleagues on their own laptop** → Option 2 (PyInstaller) + Npcap on Windows.
- **Public release / looks professional** → Option 3 (Tauri).

I can build any of these for you — just tell me which route and I'll produce the Dockerfiles / PyInstaller spec / Tauri scaffold in the next turn.
