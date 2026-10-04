"""nScout desktop launcher.

Starts the FastAPI backend on an available port, serves the bundled React UI
at the same origin, and automatically opens the user's default browser.

Shipped inside the PyInstaller bundle; also runnable in dev with:
    python backend/launcher.py
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def _bundle_dir() -> Path:
    """Return the directory containing bundled resources (frontend_build/, .env.example)."""
    if getattr(sys, "frozen", False):  # PyInstaller
        return Path(sys._MEIPASS)
    return Path(__file__).parent


def _pick_port(preferred: int = 8001) -> int:
    for port in (preferred, 8002, 8080, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
        except OSError:
            continue
    return 8001


def _ensure_env():
    """Load .env from CWD first, then fall back to the bundled .env.example."""
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        return
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        load_dotenv(cwd_env)
        return
    sample = _bundle_dir() / ".env.example"
    if sample.exists():
        load_dotenv(sample)
    # Reasonable defaults so a user can double-click and go
    os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
    os.environ.setdefault("DB_NAME", "nscout")
    os.environ.setdefault("CORS_ORIGINS", "*")


def main() -> None:
    _ensure_env()
    port = _pick_port(8001)
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print(" nScout – starting")
    print(f"  Open in browser: {url}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    # Open browser shortly after the server is up.
    def _open():
        time.sleep(1.4)
        try:
            webbrowser.open(url)
        except Exception:
            pass
    threading.Thread(target=_open, daemon=True).start()

    # Import after env is set so server.py reads the right MONGO_URL/DB_NAME.
    import uvicorn
    from server import app  # noqa: F401 – imported for side-effects

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
