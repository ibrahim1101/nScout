#!/usr/bin/env bash
# EtherLens AI – one-shot build script.
# Produces dist/EtherLens/ containing the standalone app.
#
# Usage:
#   ./build.sh         # build on the current OS (Linux / macOS)
#   On Windows, run inside PowerShell:    ./build.ps1
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Installing Python build deps"
python3 -m pip install --quiet --upgrade pip pyinstaller
python3 -m pip install --quiet -r backend/requirements.txt

echo "==> Building React UI"
pushd frontend >/dev/null
yarn install --frozen-lockfile
# Build with no backend URL → UI uses same-origin, which is what the bundled
# FastAPI will serve. REACT_APP_BACKEND_URL="" would still cause ${API} to be
# "/api" because the leading slash is handled by axios baseURL.
REACT_APP_BACKEND_URL="" yarn build
popd >/dev/null

echo "==> Running PyInstaller"
pyinstaller --noconfirm --clean etherlens.spec

echo "==> Done"
echo "    Bundle at: dist/EtherLens/"
echo "    Run:       ./dist/EtherLens/EtherLens"
