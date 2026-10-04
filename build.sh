#!/usr/bin/env bash
# nScout – one-shot build script.
# Produces dist/nScout/ containing the standalone app.
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
if [ -f yarn.lock ]; then
    yarn install --frozen-lockfile
else
    yarn install
fi
REACT_APP_BACKEND_URL="" yarn build
popd >/dev/null

echo "==> Running PyInstaller"
pyinstaller --noconfirm --clean nscout.spec

echo "==> Done"
echo "    Bundle at: dist/nScout/"
echo "    Run:       ./dist/nScout/nScout"
