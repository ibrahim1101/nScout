# -*- mode: python ; coding: utf-8 -*-
"""Development-only one-file backend sidecar for the Tauri desktop shell."""
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules


PROJECT_ROOT = Path(".").resolve()
BACKEND = PROJECT_ROOT / "backend"
FRONTEND_BUILD = PROJECT_ROOT / "frontend" / "build"

if not (FRONTEND_BUILD / "index.html").exists():
    raise SystemExit("React build missing; build frontend before the desktop sidecar")

datas = [(str(FRONTEND_BUILD), "frontend_build")]
binaries = []
hiddenimports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "websockets",
    "websockets.legacy",
]

env_file = BACKEND / ".env.example"
if env_file.exists():
    datas.append((str(env_file), "."))

for module in ("scapy", "motor", "pydantic", "uvicorn", "fastapi", "starlette", "pymongo", "websockets"):
    try:
        module_data, module_binaries, module_hidden = collect_all(module)
        datas += module_data
        binaries += module_binaries
        hiddenimports += module_hidden
    except Exception as exc:
        print(f"[nscout-sidecar.spec] WARNING: collect_all({module!r}) failed: {exc}")

hiddenimports += collect_submodules("scapy.layers")
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("websockets")

analysis = Analysis(
    [str(BACKEND / "launcher.py")],
    pathex=[str(BACKEND)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="nscout-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    icon=str(PROJECT_ROOT / "assets" / "nscout.ico"),
)
