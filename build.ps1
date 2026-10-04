# nScout - Windows build script.
# Produces dist\nScout\nScout.exe (plus supporting folders).
#
# Usage (from an elevated PowerShell):
#   .\build.ps1
#
# If PowerShell blocks the script with "...is not digitally signed...", use ONE of:
#   powershell -ExecutionPolicy Bypass -File .\build.ps1        # one-shot
#   Unblock-File .\build.ps1; .\build.ps1                       # unblock once
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned         # allow local scripts
# Or just double-click build.bat which handles this automatically.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSCommandPath)

Write-Host "==> Installing Python build deps"
python -m pip install --upgrade pip pyinstaller
python -m pip install -r backend\requirements.txt

Write-Host "==> Ensuring Yarn 1.22.22 is installed"
if (-not (Get-Command yarn -ErrorAction SilentlyContinue)) {
    npm install --global yarn@1.22.22
}

Write-Host "==> Building React UI"
Push-Location frontend
yarn install --non-interactive
$env:REACT_APP_BACKEND_URL = ""
$env:DISABLE_EMERGENT_OVERLAY = "true"
yarn build
if (-not (Test-Path build\index.html)) {
    throw "React build did not produce frontend\build\index.html"
}
Pop-Location

Write-Host "==> Verifying backend launcher imports"
$env:MONGO_URL = "mongodb://localhost:27017"
$env:DB_NAME = "nscout"
python -c "import sys; sys.path.insert(0, 'backend'); import launcher; print('launcher import: OK')"

Write-Host "==> Running PyInstaller"
pyinstaller --noconfirm --clean nscout.spec
if (-not (Test-Path dist\nScout\nScout.exe)) {
    throw "PyInstaller did not produce dist\nScout\nScout.exe"
}
if (-not (Test-Path dist\nScout\frontend_build\index.html)) {
    throw "React UI was not bundled into dist\nScout\frontend_build"
}
if (-not (Test-Path dist\nScout\.env.example)) {
    throw ".env.example was not bundled"
}

Write-Host "==> Done"
Write-Host "    Bundle:  dist\nScout\"
Write-Host "    Launch:  .\dist\nScout\nScout.exe"
Write-Host ""
Write-Host "NOTE: Install Npcap (https://npcap.com) for live packet capture."
Write-Host "      Without it, nScout still runs in Simulated / PCAP mode."
