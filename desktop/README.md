# nScout desktop shell (development only)

This Tauri 2 shell preserves the existing React/FastAPI application. It is not
part of the stable v0.3.0 release and must not be published as a v0.4 installer
until clean-VM lifecycle and capture validation are complete.

The shell starts a hidden PyInstaller backend sidecar, passes `--no-browser`,
waits for its atomic readiness file, navigates the native WebView window to the
loopback application URL, and kills the owned child process when the app exits.
The existing browser launcher remains available for source/developer use.

## Windows development build

1. Build the React frontend with `REACT_APP_BACKEND_URL` empty.
2. Run `pyinstaller --noconfirm --clean nscout-sidecar.spec` from the repository root.
3. Copy `dist/nscout-backend.exe` to
   `desktop/src-tauri/binaries/nscout-backend-x86_64-pc-windows-msvc.exe`.
4. In `desktop`, run `npm install` and then `npm run tauri build -- --bundles nsis`.

The dedicated GitHub workflow automates those steps and uploads a development
artifact only. It does not attach files to a GitHub release.

Before promotion, validate startup timeout/error handling, dynamic-port
selection, one-instance behavior, normal and forced shutdown, orphan cleanup,
sleep/resume, install/upgrade/uninstall, shortcuts, Npcap capture and the native
capture prototype on clean supported Windows VMs.
