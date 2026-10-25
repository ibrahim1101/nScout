# Cross-platform desktop packaging (v0.4 development)

nScout v0.4 keeps one React/FastAPI product core and one Tauri 2 shell for
Windows, Linux and macOS. It does not fork application behavior by operating
system. The desktop shell owns a platform-native PyInstaller backend sidecar,
waits for its loopback readiness signal, opens the application in the native
WebView and stops the owned child during application exit.

## Development build matrix

| Platform | CI package | Sidecar target | Release status |
| --- | --- | --- | --- |
| Windows | NSIS `.exe` | Rust host triple plus `.exe` | Development-only |
| Linux | AppImage and `.deb` | Rust host triple | Development-only |
| macOS | `.app` and `.dmg` | Rust host triple | Unsigned development-only |

The workflow derives the Rust host triple instead of hard-coding Linux or macOS
CPU architecture. Every job builds the same React UI, packages the same FastAPI
launcher, runs the Rust lifecycle tests, and then invokes only the native Tauri
bundle targets for that runner.

## Capture prerequisites

- **Windows:** Npcap remains the supported live-capture backend while native
  Pktmon/WFP parity is researched.
- **Linux:** libpcap is required. Live capture must use a documented least-
  privilege capability or group setup; development builds must not normalize
  running the entire UI as root.
- **macOS:** packet capture uses the platform libpcap/BPF facilities and requires
  explicit validation of interface access and user-facing permission guidance.

Platform-specific capture behavior stays behind nScout's capture-provider
capability interface. Windows Pktmon/WFP code is not used as a Linux/macOS
architecture.

## macOS distribution requirements

CI currently creates unsigned artifacts for build verification only. A public
macOS package requires all of the following before release:

1. An Apple Developer ID Application certificate stored as a protected CI secret.
2. Hardened-runtime signing of the application and every bundled executable,
   including the Python sidecar and its native libraries.
3. Notarization with Apple using protected App Store Connect credentials.
4. Stapling the notarization ticket to the app/DMG and verifying it with
   `spctl` and `stapler` on a clean macOS system.
5. A documented upgrade/uninstall path and capture-permission behavior.

No unsigned or ad-hoc-signed package will be presented as production-ready, and
the development workflow does not require users to bypass Gatekeeper.

## Support gates

A successful CI build proves only that packages can be constructed. nScout will
claim support for an operating system only after clean-machine validation of:

- install, first launch and silent backend readiness;
- single-instance focus, normal/forced shutdown and orphan cleanup;
- sleep/resume, upgrade and uninstall behavior;
- interface enumeration and least-privilege live-capture permissions;
- live packet/protocol capture and imported PCAP workflows;
- investigation, Capture Session and workspace persistence;
- report generation/export and privacy redaction; and
- useful empty/error states when capture access or the sidecar is unavailable.

Development artifacts are never attached to the stable v0.3 release and must
not be published as v0.4 without explicit release authorization.
