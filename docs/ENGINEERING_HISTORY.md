# nScout — Engineering History and Living Development Journal

> **Living document.** Started 2026-10-09. Maintain this record on the active development branch as milestones occur. This is an engineering audit trail, not marketing copy.
>
> **Evidence labels:** **Verified repository** = documented in checked-in roadmap/README, PR or CI; **Conversation record** = previously discussed/reported and not independently re-run for this entry; **Planned** = not yet delivered; **Unknown** = source logs or precise reproduction unavailable. Never invent terminal output, test totals, failures, dates or command histories.

## 1. Project identity and current handoff

- Repository: https://github.com/ibrahim1101/nScout
- Stable: **v0.3.0 — Security Intelligence** on `main` (Windows installer and portable ZIP, per README).
- Development: **v0.4.0 — Investigation Platform** on `v0.4-investigation-platform`, draft [PR #3](https://github.com/ibrahim1101/nScout/pull/3).
- Verified development checkpoint before this document: `80873282978c7ca0e8fd804c883cf0e0d176c1bb` (Network Map 2.0), 29 PR commits; desktop-development, build-nscout-windows and docker-nscout CI passed. Do not assume this remains the branch head on subsequent runs.
- Architecture: shared React frontend, FastAPI backend, Tauri 2 desktop development shell; platform-specific capture providers. Preserve stable v0.3.0 and existing local evidence.
- Product workflow: **Capture → Understand → Detect → Correlate → Investigate → Preserve Evidence → Report**.
- Scope boundary: Full AI Analyst deferred to v0.5; external threat-intelligence providers and Sensor Mode are later milestones.

## 2. Historical evolution — reconstructed from repository docs and conversations

### Early nScout: packet capture and first release

**Conversation record:** nScout began as a defensive network packet-analysis project, with Windows capture, a web frontend/backend, GitHub-based development and a Windows distribution goal. Early release/build work included troubleshooting GitHub Actions and obtaining downloadable Windows artifacts. A historical conversation references Windows release build #8 (run `37226595505`) and #9 (run `37227328985`), but this journal does **not** claim their final outcome without archived run logs. Early versions included v0.1.0; exact commit-by-commit release chronology remains to be backfilled from tags and Actions.

### Intelligence foundation and v0.3.0

**Verified repository README / conversation record:** The project expanded beyond raw packet lists into:
- Deep Packet Inspector: Ethernet/ARP/IP/TCP/UDP/ICMP/DNS/HTTP and observable TLS metadata, TCP flags, hex/ASCII, timestamps and explanations.
- Bidirectional Connection Intelligence and Connection Story, DNS lookup-to-flow correlation, visible unencrypted HTTP inspection, bounded TLS metadata without HTTPS decryption.
- TCP health: retransmissions, duplicate ACKs, out-of-order, resets, handshake/latency clues.
- Observed device inventory, protocol dashboard, timeline, defensive findings, Detection Engine 2.0 and Host Intelligence.
- PCAP workflows, investigation reporting and Windows release packaging.
- Stable v0.3.0 documented in README as Security Intelligence. The stable installer does **not** include v0.4 features.

**Historical engineering lesson:** Passive capture cannot guarantee a silent host is offline, heuristic findings are not confirmed compromises, and TLS metadata is not decrypted HTTPS payload.

### v0.4.0 — Investigation Platform development

**Verified repository roadmap:** Implemented on development branch (not yet stable):
- Seamless interface switching, optional preservation, bounded packet retention, local-time timestamp corrections and capture health/fallback diagnostics.
- Atomic local Capture Sessions and Investigation Workspace/cases, notes, evidence, finding lifecycle, persistent aliases/watchlists and observed host activity.
- Global Investigation Search over metadata/cases/notes/evidence without raw payload indexing.
- Side-effect-free bounded PCAP/PCAPNG comparison with source hashes and JSON export.
- Persistent explainable metadata-only network baselines and anomaly reasons.
- TLS ClientHello/ServerHello metadata, fingerprint context and warnings.
- Investigation Reporting 2.0: PDF/HTML/JSON/CSV/XLSX/XML, privacy redaction and CSV/XLSX formula-injection defenses.
- AI master switch OFF by default, optional local Ollama, LM Studio and custom loopback OpenAI-compatible providers; no mandatory cloud fallback.
- Settings foundation and searchable keyboard shortcuts.
- Network Map 2.0: search spacing fix, map/list, host focus, filters, connection drill-down and TCP-health context; checkpoint `8087328`.
- Tauri development packaging for Windows NSIS, Linux AppImage/deb and macOS app/DMG with shared sidecar readiness/lifecycle contract. CI build success is **not** clean-machine acceptance.
- Windows native-capture research: provider capability inventory and opt-in bounded Pktmon-to-PCAPNG prototype; not a validated live-capture replacement. Npcap remains fallback/active where required.

### User-approved nScout NEO direction (2026-10-09 conversation)

**Approved design concept; implementation NOT yet verified:**
- Modern dark midnight/charcoal with restrained violet/lavender, compact clean cards/tables and accessible status colors.
- Shared extensible design system across Dashboard, Live Capture, Packet Analysis, Network Map, Live Hosts, Investigations, Findings, Reports, Settings and Evidence Locker.
- Small tasteful cat branding; pixel-art coding cat on loading/startup/update/install states, not large dashboard illustrations.
- Adaptive topology: compact nodes, zoom-dependent labels, grouping/clustering, host filters, details and optional focus mode; represent *observed communication*, not verified physical cabling.
- Remove simulated traffic from production/default UI and silent capture fallback. Show honest errors or real zero-traffic; label imported captures; retain synthetic fixtures **only in isolated tests**.
- Future UI additions (widgets, saved layouts, theme options) should extend components rather than trigger another overhaul.
- The existing hourly v0.4 development automation was updated to include these priorities. Scheduled work is not evidence of completed code.

## 3. Known successes, failures, limitations and lessons

| Area | Evidence/status | What happened / lesson |
| --- | --- | --- |
| Windows release packaging | Verified README for v0.3.0 | Stable installer and portable ZIP exist; protect release assets and main. |
| Early GitHub Actions troubleshooting | Conversation record; outcome unverified | Build #8/#9 were monitored for completion/artifact creation; backfill exact failure steps from archived Actions before making claims. |
| Network Map search overlap | Verified v0.4 roadmap | Search icon/placeholder overlap was fixed during Network Map 2.0. Add visual regression coverage when practical. |
| Timestamp display | Conversation record / roadmap | Local-time display correction introduced; preserve UTC evidence semantics separately. |
| Capture backend failure | Verified roadmap | Failed live startup now stops in an explicit error state; no fake production traffic is generated as fallback. |
| Durable workspace | Verified roadmap | Atomic JSON local persistence plus bounded seven-day navigation/filter recovery are implemented; clean-system crash recovery still needs release-gate validation. |
| Report export safety | Verified roadmap | Redaction and spreadsheet formula-injection defense added; regression-test all export types. |
| Desktop packaging | CI success at checkpoint | Windows/Linux/macOS development packaging passes workflow checks; physical clean-install and capture fidelity unverified. |
| Native Windows capture | Prototype/research only | Pktmon-to-PCAPNG feasibility is not live capture parity; retain Npcap until complete comparisons pass. |
| AI integration | Verified roadmap | Local provider support and OFF-by-default switch; actual user-hosted model compatibility tests remain necessary. |
| nScout NEO UI | Planned | Reference-inspired mockups approved; no implementation or performance validation should be claimed yet. |

### Failures not yet reconstructable

Some past failures and commands occurred in conversations or ephemeral CI logs not currently embedded in the repository. Exact stack traces, failing test names, remediation attempts and pass/fail outputs are **unknown until recovered**. This journal intentionally leaves these gaps visible. Future maintainers should add dated entries with log links and commands, not plausible reconstructions.

## 4. Reproducible inspection commands (examples, NOT claimed historical executions)

Use these on a local checkout after checking branch and safety; commands are reference instructions, not a transcript of earlier runs:

```powershell
git clone https://github.com/ibrahim1101/nScout.git
cd nScout
git fetch origin
git switch v0.4-investigation-platform
git status --short
git log --date=iso --oneline --decorate -30
git diff origin/main...HEAD --stat
```

```powershell
# Requires GitHub CLI authentication; inspect historical runs and their logs.
gh pr view 3 --repo ibrahim1101/nScout
gh run list --repo ibrahim1101/nScout --limit 30
gh run view 37226595505 --repo ibrahim1101/nScout --log-failed
gh run view 37227328985 --repo ibrahim1101/nScout --log-failed
```

For build/test commands, use **the actual current README, workflow YAML and project scripts** rather than guessing a one-size-fits-all invocation. Record the exact commands and outputs in the dated entries below.

## 5. Current gaps and release gates

- Sticky Advanced Packet Search; contextual bookmarks; remaining empty/error states.
- Implement and test NEO shared tokens/components, per-page migration, scalable topology, and isolated pixel-cat loading state.
- Audit remaining production simulation entry points while preserving explicitly selected demos and deterministic automated tests.
- Windows/Linux/macOS clean-machine Tauri install/launch/backend readiness/shutdown, capture permissions and interface enumeration, evidence persistence and export checks.
- Windows native Pktmon/WFP fidelity parity against Npcap (packets, protocol fields, DNS/HTTP/TLS, TCP health, interface reliability); do not remove Npcap prematurely.
- Real local LLM server tests; macOS signing/notarization; full regression and user acceptance.
- Do **not** merge PR #3 or publish v0.4 until authorized.

## 6. Append-only development log template

Add a dated entry for **every significant success, failure, debugging attempt, benchmark, workflow or decision**. Never rewrite prior failures to make the story cleaner.

```markdown
### YYYY-MM-DD HH:MM TZ — Short milestone or failure
- Branch / before SHA / after SHA:
- Objective and why:
- Files changed / implementation:
- Commands actually executed (exact):
- Environment (OS, runtime, dependency versions):
- Tests: command, count, pass/fail/skip and evidence:
- CI: workflow name, run URL, conclusion:
- Failure symptoms / log excerpt (redact secrets):
- Hypotheses and attempts (including rejected fixes):
- Root cause / fix / verification:
- Security, compatibility and migration impact:
- Remaining blockers / next step:
- Docs/README/roadmap updates:
```

## 7. Handoff instructions for future chats and hourly development

1. Read this journal, `docs/v0.4-investigation-platform.md`, `docs/cross-platform-desktop.md`, `docs/windows-desktop-native-capture.md`, README, PR #3 and latest CI **before editing**.
2. Inspect current branch head; this journal's checkpoint can become stale.
3. Choose the next unfinished priority, run relevant tests, make small commits, and verify GitHub Actions.
4. Append truthful detailed results **including failed attempts** to this journal. Keep README and roadmap consistent.
5. Never treat mockup telemetry as live data, simulation as live capture, a successful package build as platform acceptance, or a planned feature as implemented.
6. Keep `main`/v0.3.0 stable; do not merge/release without explicit approval.


### 2026-10-11 10:00 IST — Local nScout preference profiles
- Branch / before SHA / implementation SHA: `v0.4-investigation-platform` / `871ee3972611553d15869903443ea68867dd0270` / `dc770472694ce394432bbfd29b7fb7e79304e1c9`.
- Objective and why: implement the next unfinished v0.4 priority as reusable local preference profiles without requiring a cloud account.
- Files changed / implementation: added an atomic JSON preference-profile store, bounded create/list/delete API, Settings controls to save/load/delete profiles, four regression tests, and README/roadmap documentation.
- Commands actually executed: `python -m py_compile backend/etherlens/preference_profiles.py backend/server.py`; `python -m pytest -q tests/test_preference_profiles.py`; `python -m pytest -q --ignore=tests/backend_test.py --ignore=tests/test_v2_features.py --ignore=tests/test_v3_features.py`; `npx prettier --write src/components/etherlens/SettingsDrawer.jsx`; `npm run build`; `git diff --check`.
- Environment: Linux automation runner, Python 3.12, pinned backend requirements, React production build through the repository npm script.
- Tests: 4 new profile tests passed; full focused backend suite passed 142 tests; optimized React build compiled successfully.
- CI: GitHub Actions runs 38112137238 (Windows), 38112137146 (Docker/API) and 38112137155 (Windows/Linux/macOS desktop) all completed successfully at head `a840878b65f1c75cb9387fa794c41c8feb8fefcb`.
- Failure symptoms / log excerpt: initial pytest attempt failed because the runner lacked `pytest` and `python-dotenv`; pinned `backend/requirements.txt` and `backend/requirements-dev.txt` were installed, after which the real tests passed. An initial `yarn build` attempt failed because Yarn was unavailable; the repository's `npm run build` succeeded.
- Root cause / fix / verification: missing local runner dependencies/tools, not a source defect. Installed pinned Python dependencies and used the available npm build path.
- Security, compatibility and migration impact: profiles contain only allow-listed non-secret preferences. Webhook URLs, AI provider details/models, credentials, packet data and investigation evidence are excluded. Storage is capped at 50 profiles and written atomically under `NSCOUT_DATA_DIR`.
- Remaining blockers / next step: verify GitHub CI, then implement bounded workspace crash recovery and honest capture empty/error states.
- Docs/README/roadmap updates: local-profile behavior, storage path and exclusions documented.

### 2026-10-11 11:00 IST — Bounded workspace crash recovery
- Branch / before SHA / implementation SHA: `v0.4-investigation-platform` / `a840878b65f1c75cb9387fa794c41c8feb8fefcb` / `b180630611fb94a1b9400819064a5c1c849dcad0`.
- Objective and why: complete the next v0.4 recovery increment without silently persisting captured evidence in browser storage.
- Files changed / implementation: added a versioned seven-day workspace-recovery helper, Dashboard restoration/persistence wiring, three focused frontend tests, and README/roadmap documentation.
- Commands actually executed: `npx prettier --write src/components/etherlens/Dashboard.jsx src/components/etherlens/workspaceRecovery.js src/components/etherlens/workspaceRecovery.test.js`; `npm test -- --watchAll=false --runInBand src/components/etherlens/workspaceRecovery.test.js`; `CI=true npm run build`; `git diff --check`.
- Environment: Linux automation runner, repository React/CRACO toolchain.
- Tests: 3/3 workspace-recovery tests passed; optimized React build compiled successfully without ESLint warnings.
- CI: GitHub Actions runs 38121648224 (Docker/API), 38121648274 (focused regression and conventional Windows) and 38121648217 (Windows/Linux/macOS desktop) all completed successfully at journal head `75e0cca171d7f3468f9202879b0227a12b50603c`.
- Failure symptoms / log excerpt: the first production build succeeded but reported one `react-hooks/exhaustive-deps` warning for the initial recovery notice effect.
- Hypotheses and attempts: adding the mutable `recovered` object directly as a dependency would have reset the notice timer after rerenders; instead its initial value is retained in a ref.
- Root cause / fix / verification: the effect intentionally consumed startup-only state but did not declare it. A startup ref plus explicit dependency removed the warning; tests and a second CI-mode build passed.
- Security, compatibility and migration impact: only primary workspace ID, packet text filter and protocol filter are stored, with 512-character bounds and seven-day expiry. Packets, payloads, PCAP content, selected packet details, evidence, credentials and AI/webhook configuration are excluded. Disabling recovery deletes the record.
- Remaining blockers / next step: inspect CI, then implement honest capture empty/error states without synthetic fallback claims.
- Docs/README/roadmap updates: recovery scope, expiry, validation and evidence boundaries documented.

### 2026-10-11 12:00 IST — Honest live-capture startup failure
- Branch / before SHA / implementation SHA: `v0.4-investigation-platform` / `535dd13ac012c8966b0301dc176614ddad9ea331` / `3b9f7b39903e9905fb5236ba71a69f1f10965706`.
- Objective and why: remove the misleading production behavior that generated synthetic packets after a requested live interface failed to start, while preserving explicitly selected simulation for deterministic tests and demos.
- Files changed / implementation: added a bounded live-sniffer readiness handshake, explicit capture-start error state, HTTP 503 propagation for start/switch failures, detailed frontend notification, updated capture documentation and regression coverage.
- Commands actually executed: `python -m py_compile backend/etherlens/engine.py backend/server.py`; `python -m pytest -q tests/test_capture_controls.py`; `python -m pytest -q --ignore=tests/backend_test.py --ignore=tests/test_v2_features.py --ignore=tests/test_v3_features.py`; `npx prettier --write src/components/etherlens/Dashboard.jsx`; `CI=true npm run build`; `git diff --check`.
- Environment: Linux automation runner, Python 3.12 with pinned backend requirements, React/CRACO production build.
- Tests: 8/8 capture-control tests passed, including zero synthetic packets after failed live startup; the full focused backend suite passed 143 tests; optimized React build compiled successfully.
- CI: GitHub Actions runs 38118569501 (focused regression and conventional Windows), 38118569587 (Docker/API) and 38118569547 (Windows/Linux/macOS desktop) all completed successfully at implementation head `3b9f7b39903e9905fb5236ba71a69f1f10965706`.
- Failure symptoms / log excerpt: the first test attempt used the repository root and could not import `etherlens`; rerunning from `backend/` exercised the configured package path. The next focused run exposed two pre-existing tests that attempted real adapter capture; they now use deterministic ready-sniffer doubles and no longer require capture privileges.
- Root cause / fix / verification: `AsyncSniffer.start()` returns before its worker confirms socket readiness, and the old exception path changed `mode` to `simulated`. Startup now waits up to three seconds for Scapy's `started_callback`; synchronous failure or readiness timeout leaves capture stopped in `error`, broadcasts metadata-only failure context and raises `CaptureUnavailableError`. Explicit `simulated` selection is unchanged.
- Security, compatibility and migration impact: capture failures can no longer be mistaken for observed network evidence. Error text identifies only the selected interface and exception class; packet/evidence content is not logged. Npcap/libpcap and platform permission requirements are unchanged.
- Remaining blockers / next step: inspect CI, continue remaining honest empty/error states, then address detection-preset preference wiring and clean-system release gates.
- Docs/README/roadmap updates: capture-health behavior now distinguishes explicit simulation from failed live capture and documents the HTTP 503 diagnostic path.

### 2026-10-11 13:00 IST — Context-aware packet-stream empty states
- Branch / before SHA / implementation SHA: `v0.4-investigation-platform` / `fe4a7faae3233a3958f12c46ddd58129dab9c43c` / `c2320355b134f2b1f5b1c56c99f608194f142316`.
- Objective and why: ensure analysts can distinguish a capture failure, quiet live interface, filtered result set, empty imported capture and idle workspace instead of seeing one ambiguous “no packets” message.
- Files changed / implementation: added a pure capture-empty-state classifier, wired it into the existing Packet Analyzer table and documented the evidence semantics without changing the NEO visual design.
- Commands actually executed: `npx prettier --write src/components/etherlens/PacketAnalyzer.jsx src/components/etherlens/captureEmptyState.js src/components/etherlens/captureEmptyState.test.js`; `CI=true npm test -- --watchAll=false --runInBand src/components/etherlens/captureEmptyState.test.js`; `CI=true npm test -- --watchAll=false --runInBand`; `CI=true npm run build`; `git diff --check`.
- Environment: Linux automation runner, repository React/CRACO toolchain.
- Tests: 5/5 focused empty-state tests passed; the complete frontend suite passed 8/8 tests; optimized React build compiled successfully.
- CI: pending GitHub Actions after push.
- Failure symptoms / log excerpt: none in source validation. npm emitted its existing `http-proxy` configuration warning and Node emitted the existing `fs.F_OK` deprecation warning; neither failed tests or build.
- Root cause / fix / verification: Packet Analyzer previously rendered one hard-coded empty row for every zero-row condition. The classifier prioritizes backend error evidence, then retained-but-filtered packets, running capture diagnostics, empty offline capture, and idle state; regression tests cover each branch.
- Security, compatibility and migration impact: backend-provided error reasons are displayed without inventing packet evidence. The helper uses aggregate status only and does not store or expose packet payloads. Existing packet rows and capture controls are unchanged.
- Remaining blockers / next step: inspect CI, continue detection-preset preference wiring and remaining release-gate validation.
- Docs/README/roadmap updates: documented the five distinct packet-stream empty states and refreshed completed recovery/fallback journal status.

### 2026-10-11 14:00 IST — Persisted backend detection presets
- Branch / before SHA / implementation SHA: `v0.4-investigation-platform` / `75e0cca171d7f3468f9202879b0227a12b50603c` / `34aa9c4e857d9452dbe8352fa5c4d6b8ac012926`.
- Objective and why: finish the detection-sensitivity preference path so the Settings choice changes explainable backend heuristics instead of remaining a browser-only value.
- Files changed / implementation: added an atomic versioned detection-settings store; GET/POST Settings API; conservative, balanced and sensitive threshold sets; active-preset propagation through security, host, dashboard, investigation, report and PCAP-import analysis; exact threshold disclosure; Settings load/save wiring; six new regression tests plus one updated contract mock; and README/roadmap documentation.
- Commands actually executed: `python -m py_compile backend/etherlens/detection_settings.py backend/etherlens/security_intelligence.py backend/etherlens/intelligence.py backend/server.py`; `python -m pytest -q tests/test_detection_settings.py tests/test_security_intelligence.py`; `python -m pytest -q --ignore=tests/backend_test.py --ignore=tests/test_v2_features.py --ignore=tests/test_v3_features.py`; `npx prettier --write src/components/etherlens/SettingsDrawer.jsx`; `npm test -- --runInBand`; `CI=true npm run build`; `git diff --check`.
- Environment: Linux automation runner, Python 3.12 with pinned backend requirements, repository React/CRACO toolchain.
- Tests: 16/16 focused detection tests passed; full focused backend suite passed 149 tests; complete frontend suite passed 8/8 tests; optimized React build compiled successfully.
- CI: pending GitHub Actions after implementation push.
- Failure symptoms / log excerpt: the initial focused test command failed because the ephemeral runner lacked `pytest`; installing the pinned backend requirements resolved the environment issue. The first full backend run then failed one host-profile test whose monkeypatched legacy callable did not accept the new `preset` keyword. The production code was unaffected; updating that mock to the current contract produced 149/149 passing tests. The first frontend test process remained open after reporting 8/8 passed, so it was stopped and the CI-mode production build was run separately and passed.
- Root cause / fix / verification: the selected preset previously existed only in browser preferences and local profile bundles. Backend analysis always used hard-coded balanced thresholds. The server now loads balanced by default, persists a validated selection atomically and passes it to every security-intelligence call; behavioral regression proves eight fast SYN probes are a sensitive lead but not a balanced lead.
- Security, compatibility and migration impact: the settings file contains one allow-listed non-secret value and is capped at 16 KiB. Corrupt or future-version files fall back to balanced with a warning. Existing balanced thresholds remain unchanged, so current installations preserve behavior until an analyst explicitly selects another preset. Findings remain heuristic leads, not verdicts.
- Remaining blockers / next step: inspect GitHub CI, then continue contextual bookmark coverage, remaining empty/error-state audit and clean-system release gates. Stable v0.3, Npcap fallback and draft PR status remain unchanged.
- Docs/README/roadmap updates: documented the persistence path, default, affected rules, threshold disclosure and non-verdict boundary; refreshed the verified backend test count to 149.

