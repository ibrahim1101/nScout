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
| Capture backend fallback | Verified roadmap | Capture health and fallback visibility added; new policy requires **no fake production traffic** on capture failure. |
| Durable workspace | Verified roadmap | Atomic JSON local persistence independent of MongoDB; crash recovery still incomplete. |
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

- Workspace crash recovery; sticky Advanced Packet Search; detection presets and settings integration; contextual bookmarks; better empty/error states.
- Implement and test NEO shared tokens/components, per-page migration, scalable topology, and isolated pixel-cat loading state.
- Audit and remove production simulated-traffic paths without regressing legitimate live capture, PCAP replay or deterministic automated tests.
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
- CI: pending GitHub Actions after push.
- Failure symptoms / log excerpt: initial pytest attempt failed because the runner lacked `pytest` and `python-dotenv`; pinned `backend/requirements.txt` and `backend/requirements-dev.txt` were installed, after which the real tests passed. An initial `yarn build` attempt failed because Yarn was unavailable; the repository's `npm run build` succeeded.
- Root cause / fix / verification: missing local runner dependencies/tools, not a source defect. Installed pinned Python dependencies and used the available npm build path.
- Security, compatibility and migration impact: profiles contain only allow-listed non-secret preferences. Webhook URLs, AI provider details/models, credentials, packet data and investigation evidence are excluded. Storage is capped at 50 profiles and written atomically under `NSCOUT_DATA_DIR`.
- Remaining blockers / next step: verify GitHub CI, then implement bounded workspace crash recovery and honest capture empty/error states.
- Docs/README/roadmap updates: local-profile behavior, storage path and exclusions documented.

