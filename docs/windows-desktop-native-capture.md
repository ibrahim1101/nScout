# Windows desktop and native-capture transition (v0.4 development)

This document records development decisions, not released behavior. The stable
v0.3.0 installer still opens nScout in the default browser and requires Npcap
for live capture.

## Desktop shell decision

Tauri 2 is the preferred first implementation because it can preserve the
existing React/FastAPI application: React remains the UI, the PyInstaller
FastAPI executable becomes a bundled sidecar, and Tauri supplies the native
window and Windows installer lifecycle. Tauri explicitly supports Python API
servers packaged as external binaries and produces normal Windows installers.

The backend launcher now supports `--no-browser`, `NSCOUT_DESKTOP_MODE=1`, a
fixed/requested loopback port and an atomic `--readiness-file`. These are the
process-contract primitives needed by a shell without changing web/developer
mode. The current packaged application remains unchanged until the shell is
implemented and validated on Windows.

The development branch now contains a Tauri 2 shell scaffold and a dedicated CI
workflow. It packages the existing backend as a hidden one-file sidecar, waits
for the launcher's atomic readiness file, redirects the native WebView to the
loopback UI, displays a bounded startup failure state and terminates the owned
child during application exit. The workflow uploads a development artifact and
never publishes a release.

The desktop build must still pass these gates before replacing the current launcher:

- hidden sidecar process (no console window) bound only to loopback;
- readiness timeout and actionable startup failure UI;
- one application instance or conflict-safe dynamic port allocation;
- graceful sidecar termination on normal exit and forced cleanup after crash;
- existing browser/developer mode retained;
- nScout icon, Start Menu shortcut, uninstall entry and signed installer;
- Windows CI artifact plus clean-VM install, launch, capture and uninstall test.

Tauri references: [sidecars](https://v2.tauri.app/develop/sidecar/) and
[Windows installers](https://v2.tauri.app/distribute/windows-installer/).

## Native capture feasibility

The runtime now exposes `GET /api/capture/backends`, an explicit provider and
capability inventory. It keeps Scapy/Npcap active and makes the in-box Windows
Packet Monitor probe non-selectable. An opt-in `PktmonCapturePrototype` starts a
bounded, circular, full-packet NIC capture using argument arrays (never a shell),
stops only a capture owned by that object and converts the ETL artifact to
PCAPNG for parity experiments. It is deliberately not connected to the live
engine. This prevents an installed Windows tool from being mistaken for verified
feature parity.

Microsoft documents Pktmon as an in-box Windows 10/11 packet capture and drop
diagnostics tool with Ethernet/Wi-Fi support and PCAPNG output. It can record
full packets, but its primary file pipeline is ETL conversion; packets can be
observed at several stack locations, producing duplicate snapshots. Its
real-time mode, loss behavior, adapter mapping, privilege requirements and
clean recovery still need controlled Windows-VM experiments before nScout can
consume it continuously.

| Requirement | Scapy + Npcap today | Pktmon feasibility | Acceptance evidence needed |
|---|---|---|---|
| Ethernet/IP/TCP/UDP | Supported | Promising | Field-level golden PCAP comparison |
| DNS/HTTP/TLS metadata | Supported | Promising if bytes are retained | Parser parity corpus |
| Payload/hex | Supported when captured | Partial/configurable | Full-packet and truncation tests |
| Connections/TCP health/latency | Supported by nScout parsing | Not verified | Ordering, timestamps, loss and dedup tests |
| Interface selection | Supported | Component-oriented, partial | Stable adapter-to-component mapping |
| Continuous reliable capture | Supported subject to Npcap/permissions | Capture-to-PCAPNG prototype only; live ingestion not verified | Long-running load/drop/restart measurements |

Pktmon is documented by Microsoft at
[Packet Monitor](https://learn.microsoft.com/windows-server/networking/technologies/pktmon/pktmon)
and [command formatting](https://learn.microsoft.com/windows-server/networking/technologies/pktmon/pktmon-syntax).

## Driver contingency

A custom WFP callout is a last resort, not the current plan. If Pktmon or another
supported in-box API cannot supply essential packet bytes or reliable timing,
the missing requirements must be isolated before any driver code begins. Such
work requires WDK-supported APIs, test-signed VM-only development, kernel fuzz
and stress testing, secure service communication, production signing and normal
Windows driver packaging. nScout will never ask users to disable signing or
weaken Windows security, and an unsigned test driver will never be labeled a
production component.

Npcap remains the supported Windows live-capture backend until a native path
passes every required parity and reliability gate. PCAP import and simulated
traffic remain independent of this migration.
