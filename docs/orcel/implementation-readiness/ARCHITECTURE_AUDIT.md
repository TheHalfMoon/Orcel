# Orcel architecture audit (2026-10-18)

Status: ADOPTED planning record (founder, 2026-10-18), authored by Fable. It grants no authority and changes no code. Base: `main@40fc9f0a17b158188d20084126e2742b1632002c` (Merge PR #343, CI success). Evidence labels follow `ORCEL_MASTER_PLAN.md`: VERIFIED SOURCE FACT, TESTED RESULT, ENGINEERING INFERENCE, ESTIMATE, UNPROVEN ASSUMPTION, OPEN DECISION. Every finding below was read in source at the base revision; no Orcel or donor code was built or run for this audit.

## 1. What Orcel is today

VERIFIED SOURCE FACT. A Rust authority kernel (`orceld`) behind a Node MCP edge, with owned private hosts for desktop and browser work. Line counts include tests.

| Component | Path | Lines | State at the base revision |
|---|---|---:|---|
| Browser host (policy, confinement, crawl, extraction, WebMCP, transfers) | `crates/orcel-browser-host` | 23,440 | Live engine work under SG-000108 (slices merged through #335; #336 open) |
| Policy | `crates/orcel-policy` | 17,676 | Profiles, FullControlLease, remote leases |
| Kernel | `crates/orceld` | 15,212 | Dispatch, providers, live browser intent journal (`live_browser.rs`) |
| UI automation registry | `crates/orcel-provider-uia` | 14,542 | Identity, bindings, digests, protected surfaces; adapter trait `UiaAdapter` |
| MCP edge | `apps/orcel-mcp` | 14,060 | 40 tools; stdio, loopback HTTP, relay; OAuth 2.1; pairing |
| Lifecycle | `crates/orcel-lifecycle` | 11,334 | Per-user Windows install/update/rollback/doctor |
| Browser worker | `apps/orcel-browser-worker` | 8,707 | playwright-core 1.63.0; aria snapshot; extraction (browser-use port); WebMCP declarative |
| Browser provider | `crates/orcel-provider-browser` | 7,210 | Contract layer |
| Git, process, fs, clipboard, network providers | `crates/orcel-provider-*` | 14,433 | Qualified Windows behavior |
| Relay | `apps/orcel-relay` | 4,720 | Self-hostable relay |
| Approval broker and ledger | `crates/orcel-approval` | 4,440 | Repaired by #286 |
| Windows Computer Host (Go) | `apps/orcel-computer-host` | 3,768 | Private stdio host derived from Open Computer Use |
| WPF preview | `apps/orcel-desktop-preview` | 876 | Read-only foundation (PR #282) |

Active grains: SG-000096 (shell and process sessions) and SG-000108 (live browser engine), both `GRAIN`. Open PRs: #336 (SG-000108 slice 3b-i, CONFLICTING with main since 2026-10-14), #328 (Hala research, CONFLICTING), #342 (website copy, MERGEABLE).

## 2. Verified strengths to keep

1. **One authority.** Every effect passes `orceld`; hosts are private stdio processes with closed vocabularies (`apps/orcel-computer-host/protocol.go` `allowedOperations`, `validateRequest`). Donor code never gets caller authority. Keep unchanged.
2. **Adapter boundary already exists.** `UiaAdapter` (`crates/orcel-provider-uia/src/lib.rs`, line ~863) keeps policy, identity allocation, stale checks, redaction, bounds and protected-surface exclusion in the registry, and adapters "stay small". This is exactly the seam a cross-platform host needs. ENGINEERING INFERENCE: macOS/Linux support is mostly a new adapter plus host, not a registry rewrite.
3. **Exact identity bindings.** Requests bind pid, start generation, window nonce, element runtime id and, for raw input, the last human-input tick. These are the right invariants for every OS.
4. **Crash containment.** The Go supervisor never observes; each observation runs in a one-shot sacrificial worker (`main_windows.go`). Keep the pattern for the new host.
5. **Unknown-outcome discipline.** The SG-000108 download journal (`crates/orceld/src/live_browser.rs`) records `pending` before dispatch and reconciles destinations after a lost reply. The approval ledger is one-writer and durable after #286.
6. **Browser confinement depth.** Pipe-only engine attachment, host-built argv, pinned resolution, no-route proxy, SharedWorker removal, feature disables measured against real leaks (#324).
7. **Extraction already reuses donor code well.** The browser-use extraction pipeline was ported with stronger hidden-text and escaping rules (`BROWSER_AGENT_DONORS_DECISION.md`).
8. **Lean kernel dependency graph.** VERIFIED: `Cargo.lock` has 62 packages and no async runtime. Large donor graphs must not enter it.

## 3. Gaps, duplication, risks

Severity is the planning priority, not a CVSS score.

| # | Finding | Evidence | Severity | Owner task |
|---|---|---|---|---|
| A-01 | **Windows-only product.** Approval UI, presence, lifecycle layout, clipboard, process confinement, browser engine verification, and the desktop host are Windows-only. macOS/Linux builds fail closed. The adopted roadmap deferred other OSes (WP24 "DEFER macOS/Linux until funded requirements"). | `crates/orcel-approval/src/lib.rs` `platform_prompt` (`cfg(not(windows))` returns "local approval UI is Windows-only"); `DefaultPresenceVerifier = NoPresenceVerifier` off Windows; `crates/orcel-lifecycle/src/layout.rs` requires `LOCALAPPDATA` | Blocking for the new goal | X0-X5 tasks |
| A-02 | **Shared temp fallback for security state.** Off Windows, approval history and audit default to `std::env::temp_dir()/orcel/...`, which is `/tmp/orcel` on Linux and a per-user but non-obvious path on macOS. Another local user can pre-create or symlink `/tmp/orcel`. | `crates/orcel-approval/src/lib.rs` `default_approval_history_path`; `crates/orcel-audit/src/lib.rs` lines 72-84 | High once any non-Windows build runs | XP-01 |
| A-03 | **No-route proxy is Windows-specific.** `NO_ROUTE_PROXY = "http://0.0.0.0:9"` is commented "Windows-only; on Linux it is loopback". On Linux/macOS a local listener on port 9 would receive the confined browser's traffic. | `crates/orcel-browser-host/src/confinement.rs` | High for the macOS/Linux browser port | XP-14 |
| A-04 | **CI never runs macOS.** Rust and Node matrices are `[ubuntu-latest, windows-latest]`. | `.github/workflows/ci.yml` lines 17-18, 38-39 | Medium | XP-02 |
| A-05 | **Tool and type names say "UIA".** Public tools (`uia.tree/observe`, `uia.element/*`, `uia.screenshot/capture`) and Rust types (`UiaAdapter`, `UiaRegistry`) are Windows terms. Renaming tools is a governed breaking change. | `docs/p16/TOOL_CONTRACT.md` | Low | Keep names as frozen compatibility identifiers; document them as platform-neutral (CROSS_PLATFORM_ARCHITECTURE.md section 5) |
| A-06 | **Journal is browser-specific.** The only intent journal lives in `live_browser.rs`; fs, git, desktop, clipboard and process mutations have no pre-dispatch intent record, so a crash after dispatch cannot be reconciled per provider. | `crates/orceld/src/live_browser.rs` | Medium | RJ-01, RJ-02 |
| A-07 | **Browser actuation vocabulary is narrow.** The worker supports navigate, observe, activate (click by aria ref), download, extract, WebMCP discover/execute. No fill, select, check, key press, hover, drag, upload, tabs or dialogs. | `apps/orcel-browser-worker/src/main.ts` op switch | Medium (product capability) | BR-02, BR-03, BR-05 |
| A-08 | **Firecrawl reuse not realized.** The adopted plan said to adapt `crawler.rs`; slice 7 shipped "Orcel-native ... no Firecrawl code is copied", with prefix-only include/exclude. | `crates/orcel-browser-host/src/crawl.rs` header | Low (works, but rebuilt what a permitted donor had) | WI-01 |
| A-09 | **Observation latency cost of the sacrificial worker is unmeasured.** Every list/tree/capture spawns a worker process (8 s timeout, 2 attempts). Safe, but each observation pays process start. | `apps/orcel-computer-host/main_windows.go`, `protocol.go` (`workerTimeoutMS`, `workerAttempts`) | Low until measured | M-NAT-01, XP-20 |
| A-10 | **Execution frontier document is stale.** `EXECUTION_FRONTIER.md` says "Last verified 2026-10-10 · main 37a1a0f" and "F3 implementation not started", while SG-000108 has merged more than 25 slices since. | `docs/orcel/EXECUTION_FRONTIER.md` | Low | Updated in this change |
| A-11 | **Inconsistent donor pins.** Desktop Commander has three pins across records (P20 ledger `bc1e944e`, reuse matrix `ea3ed35a`, a local checkout `c774c3b5`); Firecrawl two (`7120d169`, `f84845c8`); UI-TARS two. | `ORCEL_P20_DONOR_LEDGER.md`, `SOURCE_REUSE_MATRIX.md` | Low | `donor_registry.json` records all and names the authoritative one |
| A-12 | **Founder grant record cites old paths.** `docs/orcel/grants/2026-10-13-founder-source-authorization.md` points at `docs/aladdin/...` paths that no longer exist after the rename. | that file | Low | Not edited (founder record); listed for a founder-approved correction |
| A-13 | **Approval UI cannot be shared with the Control Room without changing who decides.** Kernel-owned OS dialogs are the approval surface; any cross-platform UI must keep displaying broker state only. | `ARCHITECTURE.md` ownership table | Design constraint | XP-09, XP-10, CR-02 |

## 4. What is unnecessarily custom or duplicated

1. **macOS/Linux desktop control would be a rewrite** if built from scratch. Cua Driver already provides Rust AX, AT-SPI, X11, Wayland (Sway, GNOME, KDE identity), capture and background input with an accepted cross-OS E2E matrix (SOURCE-DOCUMENTED: `libs/cua-driver/docs/action-support.md`: Windows 122/122, macOS 145/145 effective, Linux X11 116/116, Sway 116/116 at the listed upstream commits). See CUA_INTEGRATION.md.
2. **Browser actions would be a rewrite** if built from Browser Use (its action layer evaluates page script). The typed tools that ship inside the already-admitted `playwright-core` 1.63.0 (`src/tools/backend/*`) do the same jobs through locators. See BROWSER_INTEGRATION.md.
3. **A Control Room event protocol would be a rewrite.** AgentKit already specifies append-only, contiguous, replayable events, gap rejection, reconnect-is-not-retry and explicit approval binding (`packages/agentkit/ARCHITECTURE.md` invariants 1, 2, 12, 16, 22, 23). See AGENT_RUNTIME_INTEGRATION.md.
4. **Sandbox backends would be a rewrite.** `cua-vmm` already defines one `Runtime` trait over Lume, QEMU (hvf/kvm/whpx/tcg) and OCI containers with gVisor; SPACE provides a production Firecracker client and a guest agent. See SECURE_EXECUTION_INTEGRATION.md.
5. **Two native host languages.** Go for Windows, Rust for the new hosts. Kept for now because the Go host is qualified; XP-20 decides consolidation with data.

## 5. Risks of the new direction (summarized; detail in SECURITY_INTEGRATION.md)

- Importing a large donor graph (Cua platform crates pull tokio, objc2, zbus, x11rb, wayland-client, image) into the kernel would undo item 8 of section 2. Mitigation: a separate Cargo workspace for the native host (XP-05).
- macOS background input depends on SkyLight private SPI (`platform-macos/src/input/skylight.rs`). It can break on OS updates. Mitigation: capability-gated with a public-API fallback (XP-12).
- TCC permission identity on macOS requires a stable code signature; unsigned development builds will lose grants on every rebuild. Requires FD-05.
- Linux browser engine verification is weaker than Authenticode/codesign (package ownership, not vendor signature on the binary). Recorded as residual risk (SECURITY_INTEGRATION.md S-07).

## 6. Conclusion

The kernel, authority model and owned-host pattern are sound and should not change. What blocks the founder's goal is platform reach, not architecture: one new native host, per-OS approval presenters, per-OS paths/identity/confinement, and packaging. The fastest safe route reuses Cua for the host internals, AgentKit for the UI event contract, playwright-core's own tool backend for browser actions, and cua-vmm/SPACE for optional sandboxes. ENGINEERING INFERENCE.
