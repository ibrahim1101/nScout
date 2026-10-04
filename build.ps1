# nScout - Windows build script.
# Produces dist\nScout\nScout.exe (plus supporting folders).
#
# Usage (from an elevated PowerShell):
#   .\build.ps1
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSCommandPath)

Write-Host "==> Installing Python build deps"
python -m pip install --upgrade pip pyinstaller
python -m pip install -r backend\requirements.txt

Write-Host "==> Building React UI"
Push-Location frontend
yarn install --frozen-lockfile
$env:REACT_APP_BACKEND_URL = ""
yarn build
Pop-Location

Write-Host "==> Running PyInstaller"
pyinstaller --noconfirm --clean nscout.spec

Write-Host "==> Done"
Write-Host "    Bundle:  dist\nScout\"
Write-Host "    Launch:  .\dist\nScout\nScout.exe"
Write-Host ""
Write-Host "NOTE: Install Npcap (https://npcap.com) for live packet capture."
Write-Host "      Without it, nScout still runs in Simulated / PCAP mode."
