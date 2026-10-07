# nScout desktop shell (development only)

This Tauri 2 shell preserves the existing React/FastAPI application. It is not
part of the stable v0.3.0 release and must not be published as a v0.4 installer
until clean-VM lifecycle and capture validation are complete.

The shell starts a PyInstaller backend sidecar without opening a terminal or
external browser, passes `--no-browser`,
waits for its atomic readiness file, navigates the native WebView window to the
loopback application URL, and kills the owned child process when the app exits.
It also returns repeat launches to the existing window and records bounded,
content-free lifecycle diagnostics in the application data directory. The
existing browser launcher remains available for source/developer use.

## Development builds

1. Build the React frontend with `REACT_APP_BACKEND_URL` empty.
2. Run `pyinstaller --noconfirm --clean nscout-sidecar.spec` from the repository root.
3. Copy the executable to `desktop/src-tauri/binaries/nscout-backend-<target-triple>`.
   Windows uses `nscout-backend-x86_64-pc-windows-msvc.exe`; Linux and macOS
   use the host triple reported by `rustc -vV` and no `.exe` suffix.
4. In `desktop`, run `npm install`, `cargo test --manifest-path
   src-tauri/Cargo.toml`, and the platform build:

   - Windows: `npm run tauri build -- --bundles nsis`
   - Linux: `npm run tauri build -- --bundles deb,appimage`
   - macOS: `npm run tauri build -- --bundles app,dmg`

The dedicated GitHub workflow automates those steps on Windows, Ubuntu and
macOS and uploads separate development artifacts. It does not attach files to
a GitHub release. A passing build proves package construction only; it does not
establish runtime or capture support on that platform.

Before promotion on each operating system, validate startup timeout/error
handling, dynamic-port selection, single-instance focus, normal and forced
shutdown, orphan cleanup, sleep/resume, install/upgrade/uninstall, shortcuts,
interface enumeration, capture permissions, live capture, PCAP import,
investigation persistence and report/export workflows on clean machines.
Windows additionally requires Npcap and native-capture parity testing. Linux
requires libpcap capability/group guidance. macOS distribution requires a
Developer ID certificate, hardened runtime, signing, notarization and stapling;
CI currently creates unsigned development packages only. The shell keeps at
most two approximately 256 KiB JSONL lifecycle logs and never writes packet or
investigation content to them.
