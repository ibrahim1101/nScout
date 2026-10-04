# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for EtherLens AI – bundles the FastAPI backend and the
pre-built React UI into a single-folder app.

Build:
    pyinstaller etherlens.spec

Output:
    dist/EtherLens/EtherLens.exe   (Windows)
    dist/EtherLens/EtherLens       (macOS/Linux)
"""
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules

APP_NAME = "EtherLens"
PROJECT_ROOT = Path(".").resolve()
BACKEND = PROJECT_ROOT / "backend"
FRONTEND_BUILD = PROJECT_ROOT / "frontend" / "build"

datas = []
binaries = []
hiddenimports = []

# Ship the compiled React UI inside the bundle so the backend can serve it.
if FRONTEND_BUILD.exists():
    datas.append((str(FRONTEND_BUILD), "frontend_build"))

# Bundle the .env template so users can edit it next to the exe.
env_file = BACKEND / ".env.example"
if env_file.exists():
    datas.append((str(env_file), "."))

# Collect scapy, emergentintegrations and friends completely – they do a lot of
# dynamic imports that PyInstaller otherwise misses.
for mod in ("scapy", "emergentintegrations", "motor", "pydantic", "uvicorn", "fastapi", "starlette"):
    try:
        d, b, h = collect_all(mod)
        datas += d; binaries += b; hiddenimports += h
    except Exception:
        pass

hiddenimports += collect_submodules("scapy.layers")

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
