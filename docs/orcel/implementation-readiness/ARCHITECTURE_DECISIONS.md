# Architecture decisions (2026-10-18 cross-platform revision)

Status column meanings: **FOUNDER-DIRECTED** = stated by the founder in the 2026-10-18 directive; **KEPT** = existing adopted decision this revision keeps unchanged; **ADOPTED** = Fable's recommendation adopted by the founder on 2026-10-18 (`docs/orcel/grants/2026-10-18-founder-attestation.md`); **PROPOSED** = still waiting on an open founder decision; **FOUNDER DECISION** = cannot proceed without an explicit answer (ids in `backlog/tasks.json` `founder_decisions`).

## 1. Decision register

| Id | Decision | Status | Authoritative document |
|---|---|---|---|
| AD-01 | Windows, macOS and Linux are first-class targets; the WP24 "defer macOS/Linux" disposition is withdrawn | FOUNDER-DIRECTED | CROSS_PLATFORM_ARCHITECTURE.md |
| AD-02 | Copy first, adapt second, build only when necessary, at the smallest reliable boundary | FOUNDER-DIRECTED | this file §3; SOURCE_TRANSPLANT_MATRIX.md |
| AD-03 | `orceld` remains the sole authority; donors run subordinate inside Orcel-owned hosts; AI proposes, Orcel authorizes, executes, verifies | KEPT | `docs/orcel/ARCHITECTURE.md`; SECURITY_INTEGRATION.md |
| AD-04 | macOS and Linux native hosts: one Rust `orcel-native-host` embedding vendored Cua Driver platform crates (WRAP, allowlisted, in-process, no listener) | ADOPTED | CUA_INTEGRATION.md |
| AD-05 | Windows native host: keep the qualified Go host; decide consolidation after the XP-20 bake-off | KEPT + ADOPTED measurement | CUA_INTEGRATION.md §2, backlog XP-20, FD-07 |
| AD-06 | One private host protocol `orcel-computer-host/2` with capability negotiation and platform-tagged identities, superset of `/1` | ADOPTED | CROSS_PLATFORM_ARCHITECTURE.md §4 |
| AD-07 | Public tool names (`uia.*`, `desktop.*`) stay as compatibility identifiers on every OS | KEPT | CROSS_PLATFORM_ARCHITECTURE.md §5 |
| AD-08 | New crate `orcel-platform` owns per-OS paths, process/session identity, IPC peer credentials, secret storage hooks; no shared-temp fallback | ADOPTED | backlog XP-01, XP-03 |
| AD-09 | Approvals stay OS-owned on every platform: CFUserNotification + LocalAuthentication on macOS; GTK4 helper + polkit `auth_self` on Linux | ADOPTED | backlog XP-09, XP-10 |
| AD-10 | Browser: single engine, single pipe, playwright-core worker (kept); actions from playwright-core's own `tools/backend` (COPY_ADAPT); Browser Use contributes heuristics and semantics, not action code | KEPT + ADOPTED | BROWSER_INTEGRATION.md |
| AD-11 | Web intelligence is one host pipeline (search optional, map, crawl, extract, document parse, change tracking); Firecrawl units transplanted by file; no hosted index | ADOPTED | WEB_INTELLIGENCE_INTEGRATION.md |
| AD-12 | One kernel journal (`orcel-journal`) for every mutating provider; no blind retry; per-provider reconciliation; SPACE-style generation fencing for remote leases | ADOPTED | AGENT_RUNTIME_INTEGRATION.md §3.2 |
| AD-13 | Control Room: Tauri 2 on all three OSes; AgentKit protocol/client for events; UI never answers approvals; WPF kept on Windows until the parity gate | PROPOSED (FD-03 open) | AGENT_RUNTIME_INTEGRATION.md §3.4 |
| AD-14 | Optional sandboxes through `orcel-sandbox` (cua-vmm `Runtime` subset): gVisor containers on Linux first, QEMU, Lume, Firecracker later; never required for computer use | ADOPTED | SECURE_EXECUTION_INTEGRATION.md |
| AD-15 | Multi-device unchanged in shape (existing relay, per-target grants, no LAN/QUIC prerequisite); endpoints gain macOS/Linux key storage | KEPT | `docs/orcel/MULTI_DEVICE_ARCHITECTURE.md` |
| AD-16 | Native host lives in a separate Cargo workspace so the kernel's 62-package lockfile is unaffected | ADOPTED | CUA_INTEGRATION.md §2.5 |
| AD-17 | FSL components of Cua (Spaces, spacesd, driver bench) are authorized for reuse (FD-04 confirmed 2026-10-18); Spaces/spacesd stay out by architecture, driver bench is a BM-02 candidate | ADOPTED (FD-04 confirmed) | CUA_INTEGRATION.md §1 |
| AD-18 | No mandatory paid service, hosted browser, scraping API, GPU or microVM; search adapters only with user keys | KEPT + FOUNDER-DIRECTED | WEB_INTELLIGENCE_INTEGRATION.md §7 |
| AD-19 | Founder AI remains server-side and optional for Core; CUA-S1 is a research reference only | KEPT | `docs/orcel/ORCEL_AI_SERVER_ARCHITECTURE.md` |
| AD-20 | Planning backlog lives in `docs/orcel/implementation-readiness/backlog/`; a task becomes a SpecGrain only on activation | ADOPTED | IMPLEMENTATION_BACKLOG.md |

## 2. What this revision changes in the adopted plan

| Adopted item | Change | Reason |
|---|---|---|
| WP24 "DEFER macOS/Linux until funded requirements" | REMOVE | Founder directive AD-01 |
| UI decision "Keep WPF for Windows v1" | REVERSAL TRIGGER MET for condition (a) as a founder-directed requirement (funding not separately recorded); toolkit change still gated by condition (c) | UI_UX_AND_APP_SIZE_BUDGET.md "Exact reversal conditions" |
| F0 app API "private per-user stdio/named-pipe adapter" | IMPROVE: specify Unix socket + peer credentials from the start | AD-08 |
| F5 "complete Windows Core" | IMPROVE: becomes "complete Core on each OS"; macOS/Linux increments X1-X5 run alongside | AD-01 |
| F8 "additional OS hosts only with an approved need" | REMOVE (the need is approved) | AD-01 |
| SG-000101/102 Firecrawl modules | IMPROVE: exact file-level units (WI-01..05) | AD-11 |
| SG-000104 UI-TARS parser | KEEP | unchanged |
| SG-000106 installer/runtime | IMPROVE: per-OS packaging tasks XP-16..18 | AD-01 |
| Everything else in F0-F7, SG-000096, SG-000108 | KEEP; no restart | in progress or adopted |

## 3. Prioritized reuse analysis

Ranked by product value, evidence strength, effort and risk. Only findings with source evidence are listed.

**Top source transplants**
1. Cua `platform-macos` + `platform-linux` (+ minimal core) → macOS/Linux native host (XP-05..12). Largest saving; accepted upstream matrix.
2. playwright-core 1.63.0 `src/tools/backend/*` → typed browser actions, stale-ref recovery, verifier (BR-01, BR-02, BR-07). Already-admitted dependency.
3. AgentKit protocol + client → Control Room events with replay and gap rejection (CR-02).
4. Cua fixtures + shared-web catalog → cross-platform conformance suite (XP-08).
5. cua-vmm `Runtime` + container/qemu backends → optional sandboxes (SX-01, SX-02).
6. Firecrawl `crawler.rs` filters, `map-cosine.ts`, `change-tracking-diff.ts`, `pdf.rs`/`document.rs` (WI-01, WI-02, WI-04, WI-05).
7. SPACE `fc_api`, `snapshot_files`, guest `process`/`idempotency` (SX-04, SX-05).
8. crawl4ai BM25/pruning filters (WI-03).
9. browser-use clickable-elements and paint-order heuristics (BR-04).
10. Stagehand cross-frame snapshot (BR-06).

11. (Reuse review 2026-10-18) Cua `biometric.rs` for STRONG presence on macOS/Linux, Cua containment as `orcel-contain`, Cua `cua-keyvault` peer and code identity, Cua macOS bundle and notarization scripts, Cua Spaces Tauri scaffolding, Agent-Native Toolkit AgentKit React pieces, `cua-bench` (REUSE_REVIEW.md).

**Top unnecessary rewrites eliminated**
1. A from-scratch macOS AX/ScreenCaptureKit/background-input host.
2. A from-scratch Linux AT-SPI/X11/Wayland host (Open Computer Use's Linux host is X11-only and shells out to xdotool/ffmpeg).
3. Browser form/keyboard/tab/dialog/upload actions (exist in the admitted playwright-core).
4. A Control Room event protocol and reconnect logic.
5. A VM/container runtime abstraction.

**Top simplifications**
1. One journal instead of per-feature journals (RJ-01).
2. One host protocol version for all OSes (XP-04).
3. One Control Room instead of WPF + future per-OS shells (CR-03/04).
4. One native-host language for macOS/Linux, with a measured path to one for Windows (XP-20).

**Top reliability improvements**
1. Kernel-wide intent journal with reconciliation and no blind retry (RJ-02).
2. Stale-ref recovery bound to role/name/frame (BR-01).
3. Postcondition verifier with evidence (BR-07).
4. Resume summary to external clients after reconnect (RJ-03).
5. Background delivery that never steals focus where proven (XP-11/12).

**Top performance improvements (to be measured)**
1. Relevance filtering reduces tokens per extraction (WI-03, M-WI-02).
2. Fewer failed steps from stale refs and occlusion (BR-01, BR-04, M-BR-02).
3. Background semantic actions avoid activate/raise round trips (XP-11, M-NAT-03).
4. Sacrificial-worker cost on Windows observation to be measured; a persistent worker considered only with data (A-09, XP-20).

**Top cross-platform gaps**
1. Approval presenters and presence (XP-09/10).
2. Native host (XP-05..12).
3. Process confinement (XP-13).
4. Browser engine verification and network sink (XP-14).
5. Packaging, TCC identity, signing (XP-16..18).
6. Secret storage (XP-19).
7. macOS CI (XP-02).

**Top security risks**
1. Shared-temp fallback for approval/audit state (S-01): fix first.
2. 0.0.0.0 no-route proxy reaches loopback on Unix (S-06).
3. Vendored donor code reaching sockets, CDP or QuickJS (S-02).
4. SkyLight private API behavior drift (S-05).
5. Linux engine verification weaker than Windows/macOS (S-07).
6. UI answering approvals through imported code (S-16).
