"""nScout desktop launcher.

Starts the FastAPI backend on an available port, serves the bundled React UI
at the same origin, and opens the browser only after the server is ready.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import uvicorn  # noqa: F401
import fastapi  # noqa: F401


def _bundle_dir() -> Path:
    if getattr(sys, "frozen", False):
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


def _ensure_env() -> None:
    """Load optional user configuration and always provide portable defaults."""
    try:
        from dotenv import load_dotenv  # type: ignore
        cwd_env = Path.cwd() / ".env"
        if cwd_env.exists():
            load_dotenv(cwd_env)
        else:
            sample = _bundle_dir() / ".env.example"
            if sample.exists():
                load_dotenv(sample)
    except Exception:
        pass

    os.environ.setdefault("MONGO_URL", "mongodb://127.0.0.1:27017")
    os.environ.setdefault("DB_NAME", "nscout")
    os.environ.setdefault("CORS_ORIGINS", "*")


def _open_when_ready(url: str) -> None:
    """Wait for FastAPI to accept requests before opening the browser."""
    health_url = url + "/api/"
    for _ in range(120):
        try:
            with urllib.request.urlopen(health_url, timeout=0.5) as response:
                if 200 <= response.status < 500:
                    webbrowser.open(url)
                    return
        except Exception:
            time.sleep(0.25)
    print(f" nScout did not become ready. Check the errors above, then try {url}")


def main() -> None:
    _ensure_env()
    port = _pick_port(8001)
    url = f"http://127.0.0.1:{port}"

    print("=" * 60)
    print(" nScout - starting")
    print(f"  Open in browser: {url}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    threading.Thread(target=_open_when_ready, args=(url,), daemon=True).start()

    from server import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
