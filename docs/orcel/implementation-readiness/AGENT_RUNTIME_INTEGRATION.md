# Agent-Native → Orcel agent runtime, durable execution, Control Room and macOS blueprint

Status: PROPOSED (Fable, 2026-10-18). Donor: [BuilderIO/agent-native](https://github.com/BuilderIO/agent-native/tree/9c277b79cb87eb27da538e572dd710986e2fa06d) at `9c277b79` (2026-10-17). License: packages declare MIT in `package.json`; the root declares ISC; **no LICENSE text file** exists at the root or in `packages/agentkit`, `packages/toolkit`, `packages/core`. Copied files carry an MIT notice naming Builder.io as the copyright holder (to be confirmed against package metadata at import) and cite the founder authorization. Rows: `transplant_matrix.json` `T-AN-*`.

## 1. Runtime model: what Orcel runs and what it does not

Adopted (unchanged): the AI proposes, Orcel authorizes, executes and verifies. Orcel's kernel is not an LLM agent loop. Planners are external MCP clients (Claude, ChatGPT, Codex, others) or the founder-hosted AI service (F7). "Agent runtime" inside Orcel therefore means: task and step identity, durable intent journal, approvals, leases, cancellation, reconciliation, verification, and an event stream for humans. Agent-Native is valuable exactly where it specifies those mechanics; its LLM engine is not imported.

## 2. Agent-Native inspected (VERIFIED SOURCE FACT)

| Area | Path | Size | Finding |
|---|---|---|---|
| AgentKit protocol, validation, client, HTTP transport, conformance | `packages/agentkit/src` | 16,237 lines | Headless, provider-neutral; 24 written invariants (`packages/agentkit/ARCHITECTURE.md`) including append-only ordered replayable events (1), reconnect after last accepted sequence (2), explicit approval authorization not inferred from labels (12, 23), `resubscribeRun` is never a retry (16), contiguous sequences with gap rejection before cursor advance (22), capability omission means unknown (20) |
| Production agent | `packages/core/src/agent/production-agent.ts` | 14,237 lines | Monolithic loop bound to its SQL run store and model engine |
| Run store | `packages/core/src/agent/run-store.ts` | 3,730 lines | SQL persistence of runs and events |
| Tool-call journal | `packages/core/src/agent/tool-call-journal.ts` | 391 lines | Classifies started/done pairs, input fingerprints, and writes a resume note: "Interrupted / unknown outcome ... do not assume they succeeded OR failed; if re-running could duplicate a side effect, verify state first" |
| Durable background, resume, reaper | `durable-background.ts`, `run-loop-with-resume.ts` | 440 + 685 | Resume after process death |
| Desktop app | `packages/desktop-app` | Electron (`electron-builder.yml`, `electron.vite.config.ts`) | Native macOS helper and a Chrome host |
| macOS helper | `packages/desktop-app/native/macos/AgentNativeComputerHelper.swift` | 639 lines | JSON request handler: `snapshot` of the focused app's AX tree, `mutate` with `input.click/type/key/scroll` posting `CGEvent` to `.cghidEventTap` (moves the real cursor), `releaseAll`. Focused-application scope, no capture, no window identity binding |

## 3. Decisions

### 3.1 AgentKit: COPY_ADAPT for the Control Room event contract (CR-02)

`orceld` keeps durable truth. The app API (CR-01) emits run/step events; the Control Room uses AgentKit's validated protocol and deterministic client to project them. Changes on import:
- Remove every command that answers an approval. The Control Room shows "waiting for approval on this device" and the OS dialog does the rest (XP-09/XP-10). AgentKit's invariant 12 already separates display from authorization; Orcel goes further and gives the UI no approval path at all.
- Transport: an `AgentTransport` over the Tauri command bridge to the local app API, not HTTP.
- Keep the conformance suite and run it against that transport.

App API skeleton (`orcel-app-api/1`, read-only in CR-01):

| Method | Result | Notes |
|---|---|---|
| `status.get` | daemon version, uptime, policy revision, profile state | truthful unavailable states |
| `capabilities.get` | per-OS capability table (from host hellos and providers) | drives disabled controls with reasons |
| `devices.list {cursor, limit≤100}` | enrolled devices page | no secrets |
| `events.subscribe {after_seq}` | stream of `{seq, run_id, step_id, kind, at, data}` | gap → `snapshot` event, client must resubscribe |
| `task.get {task_id}` / `task.list {cursor}` | task + steps + journal states + evidence refs | bounded |
| later: `task.cancel`, `stop.request` | reduce authority only | `stop` never waits for a STRONG prompt (adopted rule) |

### 3.2 Durable execution: one journal in the kernel (RJ-01..RJ-03)

Compared (VERIFIED SOURCE FACT unless marked):

| System | Durable unit | Unknown outcome | Fit |
|---|---|---|---|
| Orcel SG-000108 | download intent line (`pending` → `settled`/`abandoned`/`reconciled`) in `intents.jsonl` | destination reconciliation | Right model, browser-only |
| Orcel approval ledger | approval records, one writer, hash chain | n/a | Right durability primitive |
| Agent-Native | SQL run events + tool-call journal | resume note tells the model not to assume | Right client-facing semantics |
| SPACE | operation ids polled to completion; execution generation fencing; `Process.Start` ends `unknown` when cut | "a retried start would run it twice" | Right fencing semantics |
| Cua | session/action records, Computer History (metadata only, macOS preview) | not a durable mutation journal | Not used |

One design: `crates/orcel-journal` (extracted from `live_browser.rs`, RJ-01) with states `pending → dispatched → settled | abandoned | unknown → reconciled`, one writer, durable append, bounded. Every mutating provider writes `pending` before dispatch (RJ-02) and implements `reconcile()`; `unknown` blocks dependent steps until a fresh approval; nothing is retried automatically. Remote leases adopt SPACE-style generation fencing: a reply from an older lease generation is discarded. The client gets Agent-Native's resume semantics through a read-only `task_resume_summary` tool (RJ-03).

Not adopted: a general workflow/DAG engine, SQL persistence, or an in-kernel model loop.

### 3.3 Agent teams and A2A: DEFER

External clients already coordinate their own sub-agents; Orcel sees tool calls with principals and sessions. Agent-Native's A2A and team roster are REFERENCE until a concrete product journey needs Orcel-side coordination (none in F0-F6).

### 3.4 Desktop packaging and UI shell

Agent-Native ships Electron. Cua ships Tauri, SwiftUI and Electron for the same app. Orcel today has a 876-line WPF preview (PR #282). Comparison (sources: UI_UX_AND_APP_SIZE_BUDGET.md criteria; numbers are not measured here):

| Criterion | WPF | Tauri 2 | Electron | Native per OS (SwiftUI + GTK + WPF) |
|---|---|---|---|---|
| OS reach | Windows only | Windows, macOS, Linux | all three | all three, three codebases |
| Bundled runtime | none (.NET Framework in box) | none (system WebView2/WKWebView/WebKitGTK) | Chromium + Node (~100+ MB, ESTIMATE) | none |
| Fit with "no bundled browser" rule | n/a | yes | **conflicts** (ships Chromium) | yes |
| Rust kernel affinity | IPC | Rust backend, same toolchain | Node main process | IPC |
| Reusable frontend | none | AgentKit headless client (TS); Toolkit components | same | none |
| Accessibility | native UIA | WebView accessibility per OS; must be tested (WebKitGTK weakest, ENGINEERING INFERENCE) | Chromium a11y | native |
| Security surface | small | IPC allowlist + CSP; no remote content | larger (Node in main) | small |
| Existing investment | 876 lines | 0 | 0 | 876 lines |

Proposal: **Tauri 2 for one Control Room on all three OSes** (CR-03), WPF kept on Windows until the CR-04 parity gate passes. The UI_UX reversal condition (a) "macOS/Linux becomes a funded near-term product requirement" is met by the founder directive of 2026-10-18; condition (b) "a real reusable frontend" is met by AgentKit's client and selected Toolkit components; condition (c) is still the measured gate. FD-03 asks the founder to confirm the direction. Electron is rejected (bundled Chromium contradicts the no-bundled-browser policy and the 400 MB budget pressure). Cua Spaces' web UI is FSL and tied to its daemon: rejected.

### 3.5 macOS helper: REJECT Agent-Native's, adopt Cua's platform crate

Two native input engines on one OS is forbidden by the directive and by Orcel's single-owner rule. Cua `platform-macos` supersedes the Agent-Native helper on every axis that matters for authority: exact window identity, background delivery that does not move the user's cursor, capture with consent state, and an upstream test matrix. The helper's phantom-cursor overlay is a UX idea only; Cua's `cursor-overlay` crate is the equivalent and stays disabled in the host (the Control Room can show an agent-activity indicator instead, required by multi-device indicator rules).

## 4. Tests the runtime work must add

- Journal fault injection at each transition for each provider (RJ-02).
- Resume summary after crash: no completed step listed as unknown and vice versa (RJ-03).
- AgentKit conformance against the app API transport, including sequence gap and duplicate delivery (CR-02).
- Control Room cannot reach any mutating method (static bundle check + IPC allowlist test) (CR-03).
