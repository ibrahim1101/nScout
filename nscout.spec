# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for nScout.

Bundles the FastAPI backend and the pre-built React UI into a single-folder app.

Build:
    pyinstaller nscout.spec

Output:
    dist/nScout/nScout.exe   (Windows)
    dist/nScout/nScout       (macOS/Linux)
"""
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

APP_NAME = "nScout"
PROJECT_ROOT = Path(".").resolve()
BACKEND = PROJECT_ROOT / "backend"
FRONTEND_BUILD = PROJECT_ROOT / "frontend" / "build"

datas = []
binaries = []

# Explicit hidden imports – uvicorn's workers / protocols are loaded by string
# at runtime, so PyInstaller's static scanner alone misses them.
hiddenimports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "uvicorn.config",
    "uvicorn.main",
    "uvicorn.server",
    # fastapi / starlette dynamic bits
    "anyio",
    "sniffio",
    "h11",
    "websockets",
    "websockets.legacy",
]

# Ship the compiled React UI inside the bundle so the backend can serve it.
if not (FRONTEND_BUILD / "index.html").exists():
    raise SystemExit(
        f"React build not found at {FRONTEND_BUILD}. Run the frontend build before PyInstaller."
    )
datas.append((str(FRONTEND_BUILD), "frontend_build"))

# Bundle the .env template so users can edit it next to the exe.
env_file = BACKEND / ".env.example"
if env_file.exists():
    datas.append((str(env_file), "."))

# Collect scapy, emergentintegrations and friends completely – they do a lot of
# dynamic imports that PyInstaller otherwise misses.
for mod in ("scapy", "motor", "pydantic", "uvicorn",
            "fastapi", "starlette", "pymongo", "websockets"):
    try:
        d, b, h = collect_all(mod)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as e:
        print(f"[nscout.spec] WARNING: collect_all({mod!r}) failed: {e}")

hiddenimports += collect_submodules("scapy.layers")
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("websockets")

block_cipher = None

a = Analysis(
    [str(BACKEND / "launcher.py")],
    pathex=[str(BACKEND)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,          # keep a console so users see the server URL
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(PROJECT_ROOT / "frontend" / "public" / "favicon.ico") if (PROJECT_ROOT / "frontend" / "public" / "favicon.ico").exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name=APP_NAME,
)
