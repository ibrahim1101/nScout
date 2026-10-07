"""nScout desktop launcher.

Starts the FastAPI backend on an available port, serves the bundled React UI
at the same origin, and opens the browser only after the server is ready.
"""
from __future__ import annotations

import argparse
import json
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


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _write_readiness(path: Path, url: str) -> None:
    """Atomically publish sidecar readiness for a supervising desktop shell."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"status": "ready", "url": url}), encoding="utf-8")
    temporary.replace(path)


def _signal_when_ready(url: str, open_browser: bool, readiness_file: Path | None) -> None:
    """Wait for FastAPI, then notify the selected client without racing startup."""
    health_url = url + "/api/"
    for _ in range(120):
        try:
            with urllib.request.urlopen(health_url, timeout=0.5) as response:
                if 200 <= response.status < 500:
                    if readiness_file:
                        _write_readiness(readiness_file, url)
                    if open_browser:
                        webbrowser.open(url)
                    return
        except Exception:
            time.sleep(0.25)
    print(f" nScout did not become ready. Check the errors above, then try {url}")


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local nScout backend and UI")
    parser.add_argument("--port", type=int, default=int(os.environ.get("NSCOUT_PORT", "8001")))
    parser.add_argument("--no-browser", action="store_true", help="Do not launch an external browser")
    parser.add_argument("--readiness-file", type=Path, help="Write local JSON after the API is ready")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _arguments(argv)
    _ensure_env()
    port = _pick_port(args.port)
    url = f"http://127.0.0.1:{port}"
    desktop_mode = _truthy(os.environ.get("NSCOUT_DESKTOP_MODE"))
    open_browser = not (args.no_browser or desktop_mode)

    print("=" * 60)
    print(" nScout - starting")
    print(f"  Local application URL: {url}")
    print("  Press Ctrl+C to stop")
    print("=" * 60)

    threading.Thread(
        target=_signal_when_ready,
        args=(url, open_browser, args.readiness_file),
        daemon=True,
    ).start()

    from server import app
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
