# Orcel improved architecture

Status: ADOPTED planning direction (founder decision, 2026-10-09; Sol revision governs where it differs from the Opus baseline). Grants no authority: every capability still needs its own grain, review and qualification. Current execution state: `EXECUTION_FRONTIER.md`. Evidence baseline of this revision: PR #283 at `87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985`, PR #282 at `10540885f3c52bd0c0d2f00cc23e3cafe067fe36`.

## Preferred design

Keep the existing authority and compatibility interfaces. Use the current Node MCP edge and a thin WPF Windows app. Add a constrained Playwright-core browser worker. Finish existing process work through SG096. Introduce the smallest task record that explains execution and supports reconciliation. Core needs no founder inference; hosted AI is a separate client of exactly the same local kernel.

`WPF / external MCP client / founder AI -> authenticated input adapter -> orceld -> authorized providers and owned workers -> observations + checked receipts`

This is an ENGINEERING INFERENCE. It preserves working components and reduces new ownership; its latency and full installation size remain unmeasured.

## Ownership and isolation

| Component | Owns | Must not own |
|---|---|---|
| WPF shell | Display, explicit device selection, user intent, progress, cancel/takeover requests | Approval tokens, permission decisions, arbitrary command execution |
| Existing MCP edge | Tool discovery, transport, client binding, OAuth/pairing | Device authority or cloud-derived privilege |
| orceld | Policy, exact targets, leases, broker interaction, dispatch, task/step records, interruption | Model inference or subscription logic |
| Browser worker | Installed-browser lifecycle, bounded AX/DOM extraction and typed actions | Raw public CDP endpoint, unrestricted evaluate, shell, donor policy engine |
| Computer Host | Existing UIA, capture and authorized input execution | Choosing a stronger method or protected-screen access |
| Process/files providers | Existing identity-bound operations and owned process cleanup | Ambient model-generated shell or implicit path expansion |
| Relay | Existing bounded routing and session binding | Target grants or approval authority |
| Founder AI service | Tenant sessions, bounded planning, model/speech routing, cost telemetry | Minting local targets, approvals, leases or completion proof |

One signed, pinned Node runtime may serve separate edge and browser processes. Separate processes have separate private channels and lifecycles; runtime deduplication does not mean shared privilege. Inventory production dependencies and notices. No runtime npx@latest, bundled browser, Electron or model weights.

## App API proposal

Use a private per-user stdio/named-pipe adapter whose authenticated peer and session are bound to the actual local user. Named pipes require explicit ACLs and peer/process validation; loopback alone is not authentication. Freeze a small versioned contract, not an entire future platform:

- status/capabilities and paginated enrolled-device reads;
- submit intent with explicit target device and opaque task id;
- bounded event subscription with sequence/cursor, snapshot after gaps;
- task/step status and receipt reads;
- cancel, immediate stop and takeover;
- request broker presentation of an exact proposal, never submit an approved token from UI.

The read-only first slice is implemented (CR-01): `orcel-app-api/1`, specified in [ORCEL_APP_API_1.md](implementation-readiness/protocol/ORCEL_APP_API_1.md), serves `status.get`, `capabilities.get` and `events.subscribe` over a per-user named pipe (Windows) or a Unix socket in the private state root (macOS, Linux). Every other method above remains PROPOSED.

Method names above are PROPOSED, not currently exported tools. Preserve all existing MCP tool names, scopes, failure codes and orcel identifiers. Adding methods or changing relay payloads requires the existing governance process.

The UI renders observe -> proposed -> awaiting user -> dispatched -> verified, with explicit error/unknown branches. These display stages map to existing execution states; they do not redefine P20. Host completion alone does not establish task success. Show exact device, path/origin, data destination and cloud/model availability. Disabled capability controls explain what is unavailable; do not animate fabricated progress.

Immediate stop only reduces authority: close admission, interrupt owned workers, release input, and record what remains unknown. It must work while cloud, renderer or Hello is unavailable. Separately preserve the existing protected persistent emergency-revoke operation; do not make the stop button wait for its STRONG approval flow. Resume never restores old leases or redispatches an unknown mutation.

## Minimal task record

Record task id, target device/epoch, request principal/session, authorized scope, step id, proposal/target generation, state, dispatch timestamp, error and postcondition evidence reference. Bound bytes and retention. Receipts can be signed by the target identity when qualified, but a signature proves origin, not correctness: independent checkers verify file contents, artifact hashes, browser download and termination.

Use read-only observation batching and per-step generation checks. A multi-action proposal is not a blanket authorization. Re-observe after mutations unless an authorized deterministic transaction provides an independently checkable postcondition. Avoid a new general DAG engine for the first local task.

## Server and devices

Start hosted AI with one control service and separate model/speech workers as needed. All Orcel AI inference, orchestration and voice processing run on founder-controlled servers. External AI services remain Core integrations. Local deterministic policy/execution and audio capture are not hosted model inference.

For one controller and two targets, extend the existing identity/OAuth/outbound relay with explicit target grants and a small bounded coordinator. Do not add LAN listeners, hole punching or a new transport to make the initial journey work. Existing relay frame vocabulary is frozen; new proposal/transfer capabilities need a reviewed versioned application contract compatible with it or an explicitly authorized protocol successor.

## Reversibility and limits

Disable unqualified live browser, remote or AI adapters without reviving old authority. Security migration rollback must preserve fail-closed state; never revert to the defective ledger with live approvals. WPF can be replaced later because UI logic and kernel authority are separated, but that is still a UI rewrite with accessibility and packaging work. Playwright could be replaced only when measurements show a material bottleneck and equivalent security/feature tests pass.

Do not declare helpers isolated merely because their IPC is private. Pin executables, limit resources and APIs, enforce policy at dispatch, validate outputs, and qualify actual network/file confinement. The fast track reduces scope; it does not relax authority.

For comparative browser options, see the source-reuse matrix and implementation roadmap. Preferred live browser: constrained Playwright-core worker, dedicated installed-browser profile, bounded AX/DOM refs, generation validation, staged approved downloads. No generic evaluate endpoint, cookie export or unconfined browser traffic. Rust CDP is deferred until measurements justify replacement and parity tests pass.

## Preserved source inventory (Opus, baseline attributed)

The following inventory is retained from Opus at main `61e664b`. Source inspection supports the main capability/gap distinctions; line counts and release/build measurements are attributed to the original session rather than independently remeasured. The original categorical production-reachability row is a source inventory, not installed-release E2E proof.

## 1. Current-code inventory (what exists today)

Opus reports source reading at the base revision. Line counts include tests.

| Component | Path | Lines | Language | State | Notes |
|---|---|---:|---|---|---|
| Authority daemon | `crates/orceld` | 13,011 | Rust | VERIFIED, production-reachable | Single policy and dispatch kernel; MCP edge talks to it over stdio JSON (`apps/orcel-mcp/src/kernel.ts`). |
| Policy | `crates/orcel-policy` | 17,679 | Rust | VERIFIED | Workspace, executable registry, FullControlLease (`full_control.rs`, `full_control_store.rs`), remote session leases, per-SG policy modules. |
| Approval broker and ledger | `crates/orcel-approval` | 2,293 | Rust | VERIFIED (Opus, at 61e664b); DEFECT REPRODUCED, since REPAIRED by PR #286 | SOFT dialog via `MessageBoxW`; STRONG via Windows Hello `UserConsentVerifier`; append-only JSONL ledger with SHA-256 chain. Issue #278 reproduced (see `SECURITY_THREAT_MODEL.md`). |
| UIA provider and registry | `crates/orcel-provider-uia` | 14,542 | Rust | VERIFIED | Typed process/window/element identities, generations, protected-surface exclusion, invoke/value/select/toggle/scroll, frames, proposals, coordinates, input leases, interruption epoch. |
| Windows Computer Host | `apps/orcel-computer-host` | 3,768 | Go | VERIFIED, size UNMEASURED | Private stdio host derived from Open Computer Use: `list_windows`, `observe_window`, `capture_window`, `cursor_position`, `semantic_action`, `window_action`, `input_move/click/drag/scroll/type_text/key/hotkey`. No listener. |
| Process provider | `crates/orcel-provider-process` | 4,788 | Rust | VERIFIED (Safe), SG-000096 in progress | Registered, hash-pinned executables; AppContainer and Job Object primitives; Full User shell not armed. |
| Filesystem provider | `crates/orcel-provider-fs` | 1,630 | Rust | VERIFIED | Workspace-bound read/write/edit/move/mkdir/remove with content-hash binding. |
| Git provider | `crates/orcel-provider-git` | 5,339 | Rust | VERIFIED | Status/diff/log/branch/stage/commit/fetch/push with destination policy (fetch/push fail closed in installed runtime). |
| Clipboard and network | `crates/orcel-provider-clipboard`, `crates/orcel-provider-network` | 2,592 | Rust | VERIFIED | Text-only clipboard with secret denial; HTTPS GET with public-address pinning. |
| Browser provider | `crates/orcel-provider-browser` | 7,123 | Rust | VERIFIED as CONTRACT-ONLY | Origin, redirect, download/upload governance is real; the DOM snapshot is a deterministic template (`lib.rs:1730`, "Deterministic structural template bound to the page origin"). There is no live DOM engine behind it. |
| Browser host | `crates/orcel-browser-host` | 7,894 | Rust | VERIFIED as SUPERVISION-ONLY | Launches Chrome/Edge headless with an ephemeral profile and serves only hello/ping/shutdown (`src/main.rs`). No CDP session is driven. |
| MCP edge | `apps/orcel-mcp` | 13,761 | TypeScript | VERIFIED | 40 tools: 26 in the remote `core` profile, 14 local-only (`tool_contract.ts`); stdio, loopback Streamable HTTP, relay device transports; OAuth 2.1; device identity and pairing. |
| Relay | `apps/orcel-relay` | 4,720 | TypeScript | VERIFIED | Self-hostable relay with route binding, quotas, file store; container built in CI. |
| Lifecycle | `crates/orcel-lifecycle` | 11,085 | Rust | VERIFIED | Per-user install, update, rollback, doctor, release qualification. |
| Website | `apps/web` | 738 | TypeScript | VERIFIED | GitHub Pages marketing site only. There is no desktop GUI application on `main`; draft PR #282 (opened during this research) proposes a read-only WPF preview in `apps/orcel-desktop-preview`. |

Release state (VERIFIED via `gh release view v0.1.0`): the only published release is "Cotra 0.1.0" (`cotra-0.1.0-windows-x64.zip`, 4,839,256 bytes). It predates SG-000094 to SG-000096 and requires a separately installed Node.js 20+.

Documentation drift (VERIFIED): `README.md` lists 31 tools; the code exposes 40. `Cargo.toml` `repository` still points to `TheHalfMoon/Orcel`. The README product name is still Orcel. These are identity-migration items for #281, not authority changes.

### 1.1 Answers to the inventory questions

| Question | Answer |
|---|---|
| Implemented | Authority kernel, approvals, workspace FS, Git, clipboard, HTTPS fetch, UIA semantic actions, window capture, bounded raw input under Full User, device identity, pairing, OAuth, relay, lifecycle, release supply chain. |
| Production-reachable | Local: all 40 tools (desktop actions require a locally granted Full User lease). Remote: the 26-tool `core` profile only. |
| Test-only or contract-only | Browser DOM observation and actuation (template data), browser host (supervision only), remote full control (contract and lease isolation only). |
| Blocked by governance | Full User shell and interactive sessions (SG-000096 T02 to T05; the #278 gate is cleared by PR #286, activation still requires its own grains), Full Admin, Persistent Admin, remote full control, browser profile expansion. |
| Exists but not integrated | Browser host supervision is not connected to any DOM engine; Go host is not in any published release. |
| Duplicated (apparent; confirm in CU-01) | `orcel-browser-host` exports its own coordinate/input-lease (`src/coordinates.rs`) and capture (`src/capture.rs`) contracts, while `orcel-provider-uia` owns frames, proposals, coordinates, and input leases for the desktop. Before adding browser actuation, decide one owner for coordinate and capture identity (recommended: the UIA registry for desktop surfaces, the browser engine only for in-page DOM targets). |
| Extend directly | UIA registry, approval broker (repaired by PR #286), FullControlLease, process provider, relay, device identity. |
| Replace | Browser provider snapshot/actuation internals (replace the template with a constrained Playwright worker behind the same contracts). |
| Preserve as compatibility interface | `orcel` CLI, `orceld`, `@orcel/*`, `ORCEL_*`, `orcel.*` OAuth scopes, storage paths, MCP name `orcel`, tool names, failure-code vocabulary. |
