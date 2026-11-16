# Orcel unified platform: integration specification (EGM draft)

**Status: DRAFT SPECIFICATION, DOCS ONLY (revision 5).** This document activates no grain, imports no donor code,
adds no dependency, tool, listener or authority, and changes no canonical state. Every packet below needs its own
activated grain, exact-head qualified PR, review gates and, where it touches authority, a fresh-context security
judge. Draft grain JSONs live in [`unified-grains/`](unified-grains/), not in `.specgrain/specs/`.

- **Revision 2** resolves the two fresh-context reviews of revision 1 (`c8c48081`): readiness findings R1 to R15 and
  security findings S1 to S13. **Revision 3** resolves the re-reviews of `e9cc14d4` (readiness RR1 to RR3, security
  SN1 to SN6, and the grain consistency check). **Revision 4** resolves the security re-check of `5d1651cd` (B1 and B2,
  the section 4.14 executor boundary). **Revision 5** applies the four nits of the re-check of `c19e7b94`. Section 13
  maps each finding to its resolution.
- **Base:** branch `plan/donor-inventory` at `c72d33fa`, on `origin/main` `4dd5cfc93b524e3e99eed9097c3e81917676bee8`.
- **Inputs read in full:** the founder blueprint and source pins from PR #785 (`UNIFIED_PLATFORM_BLUEPRINT_2026-11-16.md`,
  `UNIFIED_SOURCE_PINS_2026-11-16.json`); [`DONOR_INVENTORY.md`](DONOR_INVENTORY.md) and
  [`capability_inventory.json`](capability_inventory.json) (96 records); `docs/security/SG-000093_FULL_CONTROL_AUTHORITY_MODEL.md`;
  `docs/security/SG-000108_ENGINE_ATTACHMENT_DECISION.md` and `SG-000108_CRAWL.md`; the SG-000010 notes
  (`SG-000010_NO_SHELL.md`, `_ZERO_NETWORK.md`, `_BOUNDED_PROCESS_SPAWN_NOTE.md`), `SG-000019_STRONG_PRESENCE_NOTE.md`,
  `SG-000040_NETWORK_FETCH_NOTE.md`, `SG-000064_CLIPBOARD_NETWORK_NOTE.md` and `SG-000060_PROTECTED_EXECUTABLE_REGISTRY_NOTE.md`;
  `docs/canonical/CURRENT.md`; the P20 freeze `docs/p20/sg000092_architecture_freeze.json`; and the code in
  `crates/orcel-contracts`, `crates/orcel-policy` (`full_control.rs`, `full_control_store.rs`, `shell_session.rs`,
  `protected_state.rs`), `crates/orcel-lifecycle/src/full_control.rs`, `crates/orcel-provider-network`,
  `crates/orcel-provider-uia`, `crates/orcel-browser-host`, `crates/orceld`, `apps/orcel-browser-worker`,
  `apps/orcel-doc-parser`, `apps/orcel-mcp` and `apps/orcel-contain`.
- **Upstream facts** were read on 2026-11-16 with `gh api` at the exact SHAs named. No donor was cloned, built or run.
- **Vocabulary.** MUST and MUST NOT are binding on the packets. `C-nn` is a binding constraint, `WPw-nn` a work
  packet in wave `w`, `J-n` a user journey, `G-n` a release gate, `FD-UP-n` a founder decision.

## Contents

1. Binding design constraints
2. Architecture
3. Crates and packages
4. Contracts v1
5. Firecrawl parity matrix
6. Donor file to destination mapping (Waves 1 and 2)
7. Dependency versions
8. Packets
9. Platform floors
10. Acceptance journeys and release gates
11. Founder decisions needed
12. Draft grains and what this document does not do
13. Review resolutions (revision 2)

## 1. Binding design constraints

Three independent Goldfish reviews found the blueprint not implementable as written, and two fresh-context reviews of
revision 1 found further gaps. Their conclusions are adopted here as constraints. A packet that cannot meet one stops
and asks; it does not reinterpret it.

### 1.1 Authority

- **C-01. One permission-mode model.** SG-000093 is the only mode model: `Safe` (sole default), `Full User`,
  `Full Admin`, `Persistent Admin` (unavailable until SG-000099) and `Remote Full Control` (unavailable until
  SG-000105). The blueprint's "Observe / Workspace / Full Control / Headless" names are not modes. They map onto
  SG-000093 as: Observe and Workspace are `Safe` plus existing per-action approvals; local Full Control is `Full User`
  (or `Full Admin` with an `AdminLease`); remote Full Control is `Remote Full Control`; headless jobs run under
  whichever mode their dispatch was admitted in, never a mode of their own.
- **C-02. Leases bind exactly** the OS user identity, the interactive logon session, the device, the Orcel session,
  the authority profile, the policy revision, the authority epoch, issue time and bounded expiry (60 s to 12 h,
  `crates/orcel-policy/src/full_control.rs`). Any mismatch fails closed. Emergency revoke advances the epoch, so every
  earlier lease fails before the next mutation dispatches.
- **C-03. Only the authenticated local user control path mints authority** (`LocalGrantProof`). No agent, MCP caller,
  donor runtime, relay or remote principal can mint, widen, renew, persist or convert a lease (`UntrustedGrantOrigin`).
  Grant and renewal require a STRONG platform-presence approval (SG-000019), which `crates/orcel-lifecycle/src/full_control.rs`
  already demands for Full User; synthetic input cannot satisfy it (C-25).
- **C-04. Full Control is a new executor class consuming leases, dispatched only by `orceld`.** It is not a relaxation
  of Safe paths and **a lease never replaces an approval**: as in SG-000095, the lease is an additional gate on top of
  the per-action approval the shape already requires. It MUST NOT loosen the SG-000010 no-shell, zero-network and
  bounded-spawn rules, the SG-000060 protected executable registry, the SG-000040 one-shot fetch approval, or the
  SG-000108 per-action SOFT approvals in `Safe` mode. Every Full Control packet carries a test proving that with no
  lease the Safe path is byte-for-byte unchanged. Any approval-reducing semantics inside a trusted session are FD-UP-10.
- **C-05. Every Full Control dispatch writes an audit event first** carrying the opaque lease id, the SHA-256 binding
  digest and the authority epoch, and never the raw SID, raw device or session values, token handles or credential
  material. If the audit write fails, the dispatch is refused (C-29).
- **C-06. The "gateway" is `orceld`.** Anything in front of it (`apps/orcel-mcp` transports, the loopback REST routes,
  the relay uplink, the desktop app) is a stateless front that holds no authority, decides no scope, approval or
  staleness, and only forwards a `RequestEnvelope` over a private pipe.
- **C-07. Agent runtimes are untrusted callers above the authority layer.** `apps/orcel-agent` (SG-000129, Python,
  DeerFlow-derived), external MCP clients, SDK users and any donor agent loop reach Orcel only as MCP or API callers.
  Discovery filtering is never authorization (`apps/orcel-mcp/src/tool_contract.ts`).
- **C-08. Broader-authority fallback is never automatic** (`broader_fallback_allowed() == false`). A lease failure
  after dispatch does not imply retry. Engine fallback (Obscura to Chromium) is reported in the result and audit,
  never silent, and never crosses an approval or capability boundary.

### 1.2 Same-user threat model (added in revision 2)

A Full User agent acts as the same OS user and logon session as Orcel. Without further measures it could read the
lease store and its HMAC key, the `LocalGrantProof` material, the loopback tokens, rewrite the audit log, or drive the
grant and stop surfaces with synthetic input.

- **C-25. Grant, renew and stop surfaces are protected.** Grant and renew require STRONG presence (OS-mediated:
  Windows Hello / credential UI, macOS LocalAuthentication, Linux polkit), which synthetic input cannot complete. The
  grant prompt, the Full Control indicator and the emergency-stop surface are added to `PROTECTED_WINDOW_MARKERS`
  (`crates/orcel-provider-uia/src/lib.rs`) and its native-host mirror, so observation, capture and desktop input refuse
  them. Desktop input refuses to target them, with a test per surface. **The STRONG grant prompt itself states the C-27
  residual** in plain words ("While Full Control is on, the agent can type into any window that is not an Orcel
  security window, including a terminal, and so can run programs as you"), so the user consents to it on every grant
  and renewal; a test pins the text in the prompt.
- **C-26. Executor children and their descendants cannot reach Orcel state or Orcel processes.** Every process an
  executor starts under a lease runs with an OS boundary that denies the Orcel state root (`%USERPROFILE%\.orcel` and
  every `protected_state.rs` override: the lease store, authority key, approval history, audit logs, MCP and REST
  tokens, secret store, job store and the stop-request directory of section 4.13) and denies opening `orceld` and the
  indicator as processes. The mechanism is FD-UP-9; the recommended Windows mechanism is concrete in section 4.14
  (restricted tokens whose restricting lists exclude the user SID and carry a per-install executor SID, so executors
  cannot open the user's other processes; process-starting executors on a separate desktop with every Job Object UI
  limit; explicit deny ACEs on the state root and on the `orceld` and indicator process objects). A test per OS tries
  to read and write each protected file and to open each protected process, and a same-user process such as explorer
  with write, thread and handle rights, from an executor child and from its grandchild, and expects denial.
- **C-27. Residual, stated not hidden.** Desktop input (SG-000095) can type into any non-protected window, including a
  terminal the user left open, and so reaches same-user code execution outside Orcel's executors. SG-000095's recorded
  residuals apply; this plan does not widen them, C-26 does not claim to close them, and C-25 shows them in the grant
  prompt.
- **C-28. A visible indicator is a precondition.** The dispatcher refuses every Full Control dispatch unless the
  protected Full Control indicator (WP1-12, protocol in section 4.13) has sent a heartbeat within the last 2 s, and the
  indicator sends heartbeats only while it is visibly on screen (topmost, not minimised, not cloaked, on a monitor).
  Its out-of-band stop works when `orceld` hangs: it terminates the executor Job Objects it was handed and writes a
  revoke request that `orceld` honours before any further dispatch. The indicator never holds the authority key, acts
  on hardware input only, and treats close or hide requests as Stop. Locking the session (Ctrl+Alt+Del then Lock, or
  Win+L), which no user-mode code can block or synthesize, always stops Full Control.
- **C-29. Audit integrity is anchored outside executor reach.** The chain head is written to the Windows Event Log
  (Application log, source `Orcel`, written per user without registration, section 4.8) and shown by the indicator;
  on macOS to the unified log and on Linux to the journal (Wave 2). Argv, URLs and query strings are recorded as
  SHA-256 digests, never raw. An audit write failure refuses the dispatch, and **no durable anchor means no Full
  Control**: the indicator display alone is never accepted as the anchor.
- **C-30. Check, audit and dispatch are one critical section.** The dispatcher holds the authority-epoch lock from
  the lease check until the executor has started (process created and assigned to its Job Object); emergency stop takes
  the same lock. Lease expiry ends running sessions and jobs; every job unit re-checks the lease before it starts.
  The `Admin` executor class is refused in Wave 1.

### 1.3 Isolation

- **C-09. Every donor-derived runtime runs as a supervised child of a Rust host crate.** Windows: Job Object (kill on
  close, process limit, memory and CPU limits) plus a capability-less AppContainer. macOS: Seatbelt profile through
  `sandbox-exec`, owned by `orceld` running as a per-user launchd agent. Linux: cgroup v2 limits, seccomp, Landlock ABI 3
  or later, `PR_SET_PDEATHSIG` and `PR_SET_NO_NEW_PRIVS`. `apps/orcel-contain` already installs these boundaries for
  one-shot helpers and is the reference.
- **C-10. Host-built argv, scrubbed environment, launch from the hashed handle.** The host builds the complete argv and
  an empty-by-default environment; the child adds nothing (`ignoreDefaultArgs: true` precedent, SG-000108 decision 1).
  The binary is executed from the handle that was hashed (Linux `fexecve` of the hashed descriptor, as orcel-contain
  does; Windows: the file is opened deny-write and kept open across `CreateProcess`, and the image path is re-verified
  after start), so a swapped file cannot run.
- **C-11. Private stdio or anonymous-pipe IPC only, no listening sockets.** Inherited handles are limited by
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` on Windows and `close_range` on Unix. Donor MCP servers, HTTP listeners and CDP
  ports are disabled or patched out. The SG-000074 frame format (`u32` little-endian length plus JSON,
  `crates/orcel-browser-host/src/proto.rs`) is the base of the sidecar contract (section 4.9).
- **C-12. Obscura speaks CDP over a pipe.** Orcel's argv rules forbid `--remote-debugging-port` and
  `--remote-debugging-address` (`crates/orcel-browser-host/src/argv.rs`); Chromium already runs over
  `--remote-debugging-pipe`. At the pinned SHA, Obscura's CDP server is TCP plus WebSocket only
  (`crates/obscura-cdp/src/server.rs` binds a `std::net::TcpListener`; `obscura serve --port`, default 9222). A pipe
  transport is a required patch before Obscura can ship (WP2-05, FD-UP-6).
- **C-13. Web-intelligence sidecars have no ambient network.** The OS boundary denies the sidecar every socket
  (capability-less AppContainer; seccomp; Seatbelt `network*` deny), and network code is removed at compile time where
  the donor allows it (Obscura `obscura-net` egress, WP2-05). Page traffic is fulfilled by the host's governed fetch
  through CDP `Fetch` interception; interception is a convenience, the OS denial is the boundary. A forced proxy is an
  alternative only with its own security decision.
- **C-14. Port, don't ship runtimes.** Prefer porting algorithms into existing Rust and TypeScript crates over shipping
  new runtimes. Python and Go are not in the shipped core unless a later founder decision says so. Python may run in CI
  as a contract-test client only (Firecrawl Python SDK, section 7).

### 1.4 Licensing

- **C-15. No new AGPL code.** Firecrawl's AGPL-3.0 code (`apps/api`, `apps/local`, `apps/go-html-to-md-service`,
  `apps/playwright-service-ts`, `apps/nuq-postgres`, `apps/test-site`, `apps/test-suite`) is not copied into any Orcel
  unit by this plan. The Firecrawl API contract is reimplemented in Apache-2.0 code, with request and response shapes
  derived from the MIT SDKs (`apps/js-sdk`, `apps/python-sdk`), not from the AGPL `apps/api/openapi.json`, which MUST NOT
  be vendored.
- **C-16. Existing FD-06 ports stay as they are.** `crawl_scope.rs`, `map_rank.rs`, `change_tracking.rs` (in
  `crates/orcel-browser-host`) and `apps/orcel-doc-parser` rely on the FD-06 founder attestation and the notice
  `docs/orcel/notices/firecrawl-AGPL-3.0.txt`. They are listed by path in an allowlist file
  (`docs/orcel/notices/fd06-files.txt`, WP1-01); the licence scan accepts AGPL markers only in those files and refuses
  any new one in `crates/`, `apps/`, `packages/` or `tests/`. This plan neither widens nor removes that reliance and
  records that no copyright-holder-signed grant is in the repository (`DONOR_INVENTORY.md` section 1).
  `SG-000108_CRAWL.md` records `crawl.rs` itself as a native rebuild with no copied line.
- **C-17. An AGPL Firecrawl server could only ever be an optional, separately distributed sidecar**, never a default,
  never bundled, never in a kernel crate. Choosing it is FD-UP-1.
- **C-18. Fleet:** a reporting adapter only, from MIT parts; nothing from `ee/`. **UU Remote:** no source; remote desktop
  is built on the existing relay (SG-000052 to SG-000058, SG-000057 self-host) and WebRTC later.
- **C-19. Stealth and fingerprinting are BLOCKED** (Obscura `--stealth`, Scrapling stealth and `curl_cffi`, Crawlee
  fingerprints and impersonating clients, Firecrawl `proxy: "stealth"`) pending FD-UP-2.
- **C-20. Per-crate and per-package licence checks run in CI** (WP1-01).

### 1.5 Scope and sequencing

- **C-21. Founder goals are all retained; only their order changes.** Nothing in a later wave is dropped.
- **C-22. Acceptance is by user journeys** (section 10), not donor checklists.
- **C-23. A claim needs a test.** Capability discovery reports `unsupported` explicitly; no tool returns a simulated
  success. Parity rows without a passing test stay `not_started`.
- **C-24. Existing work is extended, not replaced.** No donor tree replaces the repository root; the trusted runtime
  grows through tested adapters.

## 2. Architecture

### 2.1 Layers and trust boundaries

```text
 UNTRUSTED CALLERS (C-07)
 +--------------------------------------------------------------------------------------------+
 | Desktop app (WPF today; Tauri SG-000119) | orcel CLI | MCP clients | SDKs (TS W2, Py W3)    |
 | apps/orcel-agent (Python, DeerFlow-derived) | donor agent loops, if any, as callers only     |
 +--------------------------------------------------------------------------------------------+
            | MCP stdio | MCP Streamable HTTP 127.0.0.1 + MCP token | REST 127.0.0.1 + REST token | relay
            v
 STATELESS FRONTS, NO AUTHORITY (C-06)
 +--------------------------------------------------------------------------------------------+
 | apps/orcel-mcp: tool_contract.ts catalog -> MCP tools; loopback REST /v1,/v2 Firecrawl       |
 | routes (W1, hand-mapped, per-client REST tokens) and /api/v1 OpenAPI routes (W2, generated)  |
 | relay_device uplink (SG-000055) adds a RemoteContext; it never adds authority                |
 +--------------------------------------------------------------------------------------------+
            | private stdio pipe: one RemoteRequestEnvelope per line (orcel-contracts)
            v
 orceld: THE GATEWAY AND SOLE AUTHORITY
 +--------------------------------------------------------------------------------------------+
 | decode -> capability report -> policy (orcel-policy) -> per-action approval (orcel-approval) |
 |   Full User additionally: indicator alive? -> epoch lock -> lease check -> audit -> start    |
 | job queue (orcel-jobs, W1) | audit hash chain + Event Log anchor (orcel-audit, W1)           |
 | emergency stop: epoch lock -> epoch advance -> cancel jobs -> kill executor Job Objects      |
 +--------------------------------------------------------------------------------------------+
     | in-process providers                      | supervised children (C-09..C-13, C-26)
     v                                           v
 +------------------------------+   +-------------------------------------------------------+
 | orcel-provider-fs / -git /   |   | executor children (Full User): AppContainer, state root |
 | -process / -network /        |   |   denied (C-26), Job Object handle shared with indicator|
 | -clipboard / -uia            |   | orcel-browser-host -> apps/orcel-browser-worker        |
 | orcel-web (pure mapping, W1) |   |   -> Chromium (--remote-debugging-pipe)   [today]      |
 +------------------------------+   |   -> Obscura (pipe patch, no sockets)     [W2 trial]   |
                                    | orcel-contain -> apps/orcel-doc-parser (pdf/docx/xlsx, |
 PROTECTED SURFACES (C-25, C-28)    |   html for the fetch engine W1)                       |
 +------------------------------+   | apps/orcel-native-host (macOS/Linux GUI), Go host (Win) |
 | grant prompt (STRONG)        |   | orcel-sidecar host (W2) -> mobile, fleet adapters (W3) |
 | Full Control indicator + stop|   +-------------------------------------------------------+
 +------------------------------+                      |
                                                       v
                                           OS (Windows / macOS / Linux)
```

### 2.2 Two request walk-throughs

**Firecrawl-compatible scrape (Wave 1, Windows, Safe mode).** The Firecrawl JS SDK, configured with an explicit
`apiUrl: "http://127.0.0.1:<port>"` and `apiKey: <REST token>` (section 4.12), posts `/v2/scrape`. The loopback front
checks `Host`, `Origin` and the REST token, resolves the token to its client principal, translates the body with the
`orcel-web` schema into `RequestEnvelope { capability: "web", operation: "scrape" }` (section 4.0 naming) and forwards
it. `orceld` checks the capability report (engine available on this OS and build), runs policy, raises one SOFT
approval bound to the request digest (URL, engine, formats, resolved-address-set digest, `orcel_session_id`),
dispatches to the engine (`fetch` through the Windows SG-000040 transport plus the contained parser, or `chromium`
through the browser host's `extract_page`), audits, and returns the result. The front shapes it as Firecrawl's
`{ "success": true, "data": Document }`.

**Full Control desktop input (Wave 1, Windows, Full User).** The user grants Full User from the local control path
with STRONG presence; the lease is stored by `full_control_store.rs` and the indicator appears. An MCP caller asks for a
desktop input action (SG-000095, the executor already enabled for Full User). `orceld` confirms the indicator heartbeat,
takes the epoch lock, loads the lease, re-reads the native identity (`current_windows_identity`), checks every binding
(C-02), confirms `executor_enabled_now(FullUser, DesktopInput)`, raises the shape's own approval as SG-000095 requires,
writes the dispatch audit event (C-05), sends the action to the native host (the DesktopInput executor child, section
4.14), then releases the lock. Emergency stop (indicator button or `orcel` CLI) takes the lock, advances the epoch,
cancels jobs and kills executor Job Objects; if `orceld` is hung, the indicator terminates the Job Objects it was handed
and writes a revoke request that `orceld` honours before any further dispatch (section 4.13).

### 2.3 What is deliberately absent

- No second authorization channel: no donor MCP server, HTTP listener, CDP port or admin feature is reachable.
- No founder-hosted service, SaaS database, paid API or required relay (blueprint decision 6).
- No webhook egress from jobs in Wave 1 (Firecrawl `webhook` is refused, section 5.4).
- No network transport outside Windows in Wave 1 (section 8.2, WP1-08; the macOS and Linux transport is WP2-12).

## 3. Crates and packages

### 3.1 Inventory

"Wave" is when the unit is created or first changed by this plan. Licence is the unit's own licence; donor notices
travel with ported files (section 6.1).

| Unit | Path | State | Wave | Licence | Depends on (Orcel units) | Role in this plan |
| --- | --- | --- | --- | --- | --- | --- |
| orcel-contracts | `crates/orcel-contracts` | exists | W1 | Apache-2.0 | none (serde, serde_json) | Leaf. Gains contract modules of section 4 |
| orcel-platform | `crates/orcel-platform` | exists | W2 | Apache-2.0 | none | Per-OS identity readers for macOS and Linux (W2) |
| orcel-policy | `crates/orcel-policy` | exists | W1 | Apache-2.0 | contracts, platform, approval, providers | Lease issue and check stay here; `mode_selectable_on` (WP1-10) |
| orcel-approval | `crates/orcel-approval` | exists | W1 | Apache-2.0 | contracts, platform | Approvals gain the `orcel_session_id` binding (S10) |
| orcel-audit | `crates/orcel-audit` | exists | W1 | Apache-2.0 | contracts, platform | Hash chain and Event Log anchor (section 4.8) |
| orcel-journal | `crates/orcel-journal` | exists | W1 | Apache-2.0 | none (fs4) | Storage primitive reused by orcel-jobs |
| orcel-jobs | `crates/orcel-jobs` | **new** | W1 | Apache-2.0 | contracts, journal | Embedded durable queue, throttle, checkpoint, store |
| orcel-web | `crates/orcel-web` | **new** | W1 | Apache-2.0 | contracts only | Firecrawl-compatible schemas, pure; emits `WebCrawlRequest` (contracts) |
| orcel-browser-host | `crates/orcel-browser-host` | exists | W1, W2 | Apache-2.0 | contracts | Crawl, map, extraction reused (W1); engine contract and Obscura adapter (W2) |
| orcel-provider-network | `crates/orcel-provider-network` | exists | W2 | Apache-2.0 | contracts | Windows WinHTTP SG-000040 transport reused in W1; macOS/Linux transport WP2-12 |
| orcel-provider-uia | `crates/orcel-provider-uia` | exists | W1 | Apache-2.0 | contracts, platform | New protected window markers (C-25) |
| orcel-lifecycle | `crates/orcel-lifecycle` | exists | W1 | Apache-2.0 | approval, platform, policy, tunnel | Grant/renew with STRONG presence (exists); REST token commands; indicator launch |
| orcel-sidecar | `crates/orcel-sidecar` | **new** | W2 | Apache-2.0 | contracts, platform | Generic supervised-child host and sandbox profiles |
| orcel-provider-mobile | `crates/orcel-provider-mobile` | **new** | W3 | Apache-2.0 (+ MIT notice, phone-harness) | contracts, sidecar | Android ADB provider |
| orcel-fleet-report | `crates/orcel-fleet-report` | **new** | W3 | Apache-2.0 | contracts | Read-only inventory reporting adapter |
| orceld | `crates/orceld` | exists | W1 to W3 | Apache-2.0 | all kernel crates | Web and job dispatch, `WebCrawlRequest` to `CrawlSpec` translation, `FetchCrawlDriver`, Full Control dispatcher |
| orcel-indicator | `apps/orcel-indicator` | **new** | W1 | Apache-2.0 | orceld over a pipe; policy store revoke path | Protected Full Control indicator and out-of-band stop (Windows W1) |
| orcel-mcp | `apps/orcel-mcp` | exists | W1, W2 | Apache-2.0 | orceld over a pipe only | Catalog entries, loopback REST routes, OpenAPI generation (W2) |
| orcel-browser-worker | `apps/orcel-browser-worker` | exists | W2 | Apache-2.0 (+ MIT notice, browser-use) | browser host over a pipe only | Engine-neutral snapshot refs and actions (agent-browser port) |
| orcel-doc-parser | `apps/orcel-doc-parser` | exists | W1 | Apache-2.0 (+ FD-06 notice) | provider-process (test) | New `html` format for the fetch engine; own workspace, `rust-version = "1.88"` |
| orcel-contain | `apps/orcel-contain` | exists | W2 | Apache-2.0 | provider-process | Boundary reference for orcel-sidecar |
| orcel-native-host | `apps/orcel-native-host` | exists | W2, W3 | Apache-2.0 (+ vendored Cua notices) | platform | macOS/Linux GUI; iPhone Mirroring (W3) |
| orcel-relay | `apps/orcel-relay` | exists | W3 | Apache-2.0 | none in-process | Remote screen signalling on the SG-000057 relay |
| firecrawl-compat | `tests/firecrawl-compat` | **new** | W1 | Apache-2.0 (+ MIT notice for adapted SDK tests) | none (black-box over loopback) | Contract harness; never shipped |
| browser-corpus | `tests/browser-corpus` | **new** | W2 | Apache-2.0 (+ Apache notice, agent-browser) | none (black-box) | Dual-engine qualification corpus; never shipped |
| @orcel/sdk | `packages/orcel-sdk-ts` | **new** | W2 | Apache-2.0 | none (HTTP client) | TS SDK generated from the OpenAPI document |
| orcel-sdk (Python) | `packages/orcel-sdk-py` | **new** | W3 | Apache-2.0 | none (HTTP client) | Python SDK; a client library, not shipped core (C-14) |
| obscura (patched) | `third_party/obscura` (separate workspace) | **new** | W2 | Apache-2.0 + vendored MIT/OFL | none | Pinned vendored source plus Orcel patches; built in CI (WP2-05) |

### 3.2 Dependency direction

```text
 orcel-contracts  <-- every kernel crate (leaf; serde only; no IO; no platform code)
 orcel-platform   <-- policy, approval, audit, sidecar, providers, lifecycle, orceld
 orcel-journal    <-- orcel-jobs, orceld
 orcel-jobs       <-- orceld                  (never <- providers or browser-host)
 orcel-web        <-- orceld                  (pure: depends on orcel-contracts only)
 browser-host     <-- orceld                  (orcel-web never depends on it; orceld translates)
 orcel-sidecar    <-- provider-mobile, fleet-report, browser-host (W2), orceld
 orceld           <-- nothing in-process; apps reach it only over a pipe
```

Rules, enforced by a `cargo metadata` test added in WP1-01:

1. No kernel crate (`crates/*`) depends on any `apps/*`, `tests/*`, `packages/*` or `third_party/*` unit.
2. `orcel-contracts` has no dependency beyond `serde` and `serde_json` (plus the dev-dependency `schemars`, section
   4.0), and no `cfg(target_os)` code.
3. `orcel-web` depends on `orcel-contracts` only; `orcel-jobs` on `orcel-contracts` and `orcel-journal` only. Neither
   has a network, process or platform dependency.
4. Separate workspaces stay separate (`apps/orcel-contain`, `apps/orcel-doc-parser`, `apps/orcel-native-host`,
   `third_party/obscura`), so tokio and V8 never enter `orceld`'s lockfile (AD-16 precedent).
5. A crate's licence set (its own plus its resolved dependencies) passes the allowlist of WP1-01.

## 4. Contracts v1

All types live in `crates/orcel-contracts/src/` as new modules: `identity.rs`, `lease.rs`, `session.rs`, `tool.rs`,
`capability.rs`, `job.rs`, `event.rs`, `sidecar.rs`, `web.rs`, `error.rs`. They are wire types only: no issuance, no
checking and no secret material. Issuance and checking stay in `orcel-policy`.

### 4.0 Versioning, naming and conventions

- Every top-level wire object carries `"contract": "orcel.<name>/<major>"`, starting at `/1`. A major bump is a
  breaking change and needs its own grain; additive optional fields keep the major.
- **Inbound authority-bearing objects** (leases, grants, remote context, sidecar control frames) use
  `#[serde(deny_unknown_fields)]`, as `FullControlLease` and `RemoteContext` do today. Outbound reports may gain
  optional fields.
- Enums are `snake_case` on the wire, except `FailureCode`, which keeps its frozen `SCREAMING_SNAKE_CASE`.
- Time is `u64` milliseconds since the Unix epoch (`*_ms`). Digests are lowercase hex SHA-256 (`*_sha256` or
  `*_digest`). Identifiers are opaque strings of at most 256 bytes (`MAX_AUTHORITY_FIELD_BYTES`).
- `INTERNAL_PROTOCOL_VERSION` stays `1`; contracts carry their own majors. A golden JSON fixture per type lives in
  `crates/orcel-contracts/tests/fixtures/*.json`.
- **JSON Schema** (draft 2020-12) files in `docs/orcel/contracts/schema/` are generated by `schemars` =1.2.3 (MIT,
  MSRV 1.74), added as a **dev-dependency** of `orcel-contracts` only, so it never ships and never enters a runtime
  lockfile path. A test regenerates the schemas and fails on drift; the golden fixtures are the validation that serde
  accepts exactly what the schema describes (round-trip plus unknown-field refusal).
- **Canonical JSON** for the new contracts' digests (`spec_digest`, `action_digest`, audit `digest`): UTF-8, object
  keys sorted by code point, no insignificant whitespace, integers without exponent, strings with minimal escaping (RFC
  8785 style), produced by one function, `orcel_contracts::canonical_json`. **Exempt and unchanged:** the SG-000093
  lease identifiers and `binding_digest` (`full_control.rs`), the SG-000018/SG-000019 approval digests, and the
  SG-000040 approval digest. They keep their existing domain-separated encodings, and existing leases and approvals
  stay valid.
- **Capability and operation naming (pinned).** The envelope's `capability` and `operation` fields follow the
  catalog's existing style (`network`/`fetch`, `search`/`query`, `browser.dom`/`fill`): a lowercase capability,
  dotted only for sub-areas, and a lowercase operation. Prose writes the pair as `capability/operation`. The new pairs
  are `web/scrape`, `web/map`, `web/crawl_start`, `web/batch_scrape_start`, `job/status`, `job/cancel`, `job/errors`
  and `job/list`. MCP tool names are `web_scrape`, `web_map`, `web_crawl_start`, `web_batch_scrape_start`,
  `web_job_status`, `web_job_cancel`, `web_job_errors` and `web_job_list`. Capability report entries use the same
  `capability/operation` string plus `engine`.
- **`workspace_id` for web calls.** Web operations touch no workspace. MCP web tools take `workspace_id` with the
  transport's configured default, as `web_search` and `web_fetch` do; loopback REST calls use the loopback server's
  configured default workspace, because Firecrawl bodies cannot carry one. Policy evaluates the workspace as for
  `web_fetch`.

### 4.1 Principal and device

```rust
pub enum PrincipalKind { LocalUser, McpClient, RestClient, RemotePrincipal, AgentRuntime, Sidecar }

pub struct Principal {
    pub contract: String,            // "orcel.principal/1"
    pub kind: PrincipalKind,
    pub principal_id: String,        // opaque; LocalUser: SHA-256 of the OS identity binding; RestClient: token id
    pub client_profile_id: Option<String>,
    pub display: String,             // bounded, escaped by prompt_display before any prompt
}

pub struct Device {
    pub contract: String,            // "orcel.device/1"
    pub device_id: String,           // derive_device_id(authority key), full_control_store.rs
    pub os: OsFamily,                // windows | macos | linux
    pub os_build: String,            // e.g. "10.0.26100", "15.6", "Ubuntu 24.04 6.8.0"
    pub arch: Arch,                  // x86_64 | aarch64
    pub device_epoch: u64,           // SG-000055 epoch; remote leases bind it
}
```

Only `LocalUser` can appear as the issuing principal of a lease (C-03). `AgentRuntime`, `RestClient` and `Sidecar`
principals are recorded in audit for attribution and job ownership, never as authority.

### 4.2 Per-OS identity binding

```rust
#[serde(tag = "os", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsIdentityBinding {
    Windows { user_sid: String, logon_session_luid: u64 },               // TokenUser + TokenStatistics.AuthenticationId (today)
    Macos   { uid: u32, audit_session_id: u32, console_user: bool },     // getuid + getaudit_addr ai_asid (W2)
    Linux   { uid: u32, login_session_id: String, seat: Option<String> }, // sd_pid_get_session / logind (W2)
}
```

- Wave 1 implements `Windows` only and keeps `FullControlLease`'s existing fields (`windows_user_sid`,
  `logon_session_id`) byte-for-byte, so `orcel-full-control-lease/1` leases stay valid. Wave 2 introduces
  `orcel-full-control-lease/2` with `os_identity: OsIdentityBinding` and a migration that invalidates, never converts,
  v1 leases (a user re-grants with STRONG presence).
- Each reader returns the binding from the running process's own kernel credentials, never from an environment
  variable or an argument. macOS and Linux readers are WP2-01. Until then Full User is refused on those OSes with
  `LEASE_UNSUPPORTED_PLATFORM`, implemented by WP1-10 (section 8.2).

### 4.3 Lease and grant

```rust
pub struct LeaseView {                       // wire projection; no secret; never accepted as proof
    pub contract: String,                    // "orcel.lease-view/1"
    pub lease_id: String,                    // domain-separated SHA-256 (SG-000093, unchanged)
    pub mode: AuthorityMode,                 // safe | full_user | full_admin | persistent_admin | remote_full_control
    pub binding_digest: String,              // SG-000093 binding digest (unchanged encoding)
    pub authority_epoch: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub executors: Vec<ExecutorClass>,       // enabled now, not the ceiling
    pub state: LeaseState,                   // active | expired | revoked | invalidated
}

pub struct GrantRef {                        // a per-action approval, existing orcel-approval nonces
    pub contract: String,                    // "orcel.grant-ref/1"
    pub approval_class: ApprovalClass,       // none | soft | strong
    pub action_digest: String,               // what was approved, exactly
    pub nonce_id: String,                    // one-shot, short expiry (SG-000018)
    pub orcel_session_id: String,            // bound: a restart invalidates every outstanding grant (S10)
}

pub struct DispatchAuthority {               // attached by orceld to every dispatch and audit event
    pub mode: AuthorityMode,
    pub lease: Option<LeaseRef>,             // Some for every Full Control dispatch (C-05)
    pub grant: Option<GrantRef>,             // Some for every approved dispatch, with or without a lease (C-04)
}
pub struct LeaseRef { pub lease_id: String, pub binding_digest: String, pub authority_epoch: u64 }
```

`AuthorityMode`, `ExecutorClass` and `ExecutionState` move from `orcel-policy` to `orcel-contracts` with identical
serde spellings and are re-exported from `orcel-policy` so no caller changes. `FullControlLease` and `AdminLease` stay
in `orcel-policy` (they are issued there and their ids are keyed by `LocalGrantProof`). New approvals bind
`orcel_session_id` in their digest (WP1-06 for web shapes; existing shapes keep their digests until their own grain).

### 4.4 Session

```rust
pub struct Session {
    pub contract: String,                    // "orcel.session/1"
    pub orcel_session_id: String,            // validate_runtime_session; replaced on restart
    pub client_session_id: String,           // RequestEnvelope.client_session_id
    pub principal: Principal,
    pub transport: Transport,                // stdio | loopback_mcp | loopback_rest | relay
    pub tool_surface_profile: String,        // core | desktop_structured | browser_structured
    pub remote: Option<RemoteContext>,       // SG-000055, only from the uplink
    pub started_at_ms: u64,
}
```

A lease and every new approval bind `orcel_session_id`, so a restart invalidates them (C-02, S10).
`client_session_id` is never authority.

### 4.5 Tool registry entry

The TypeScript catalog in `apps/orcel-mcp/src/tool_contract.ts` stays authoritative for MCP. Wave 1 adds a Rust mirror
so `orceld` and the generated OpenAPI agree mechanically:

```rust
pub struct ToolEntry {
    pub contract: String,                    // "orcel.tool/1"
    pub name: String,                        // e.g. "web_scrape"
    pub capability: String,                  // "web"
    pub operation: String,                   // "scrape"
    pub effect: EffectClass,                 // read | preview | write | destructive | execute | network | desktop_* | clipboard
    pub approval: ApprovalClass,             // required in every mode (C-04)
    pub lease_gate: Option<ExecutorClass>,   // Full Control executor class that ADDITIONALLY gates the call; never replaces approval
    pub remote: RemoteExposure,              // local_only | scopes(["orcel.web.read", ...])
    pub profiles: Vec<String>,               // discovery only
    pub platforms: Vec<OsFamily>,            // where an implementation exists
    pub input_schema: String,                // path of the JSON Schema
    pub output_bound: String,
    pub since: String,                       // grain id
}
```

A test in `apps/orcel-mcp` compares the TS catalog with `docs/orcel/contracts/tools.json` generated from the Rust mirror;
any difference fails CI. The founder's stated wish for no repetitive approval dialogs inside a trusted session is
recorded as FD-UP-10; until it is decided, no entry may drop its approval because a lease is present.

### 4.6 Capability discovery

```rust
pub struct CapabilityReport {
    pub contract: String,                    // "orcel.capability-report/1"
    pub device: Device,
    pub build: BuildKind,                    // release | live_browser_dev | live_browser_test
    pub entries: Vec<CapabilityEntry>,
}
pub struct CapabilityEntry {
    pub capability: String,                  // "web/scrape"
    pub engine: Option<String>,              // "fetch" | "chromium" | "obscura"
    pub status: CapabilityStatus,
}
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    Unavailable { reason: String },          // could work here but is not ready (no engine found, disabled)
    Unsupported { reason: String },          // not implemented on this OS or build; never a silent fallback
    Blocked     { policy: String },          // e.g. "FD-UP-2 stealth", "cloud-only", "Fleet EE"
}
```

`orcel capabilities` (CLI), the `capabilities` MCP tool and `GET /api/v1/capabilities` (W2) return the same report.
Every call that hits a non-`Available` entry fails with the matching `FailureCode` (section 4.10), never a degraded
success. In Wave 1, `web/*` with engine `fetch` is `Available` only on Windows; on macOS and Linux it is `Unsupported`
("no native SG-000040 transport on this OS; WP2-12").

### 4.7 Job state machine

Jobs reuse the frozen SG-000093 vocabulary. No new state is added.

```rust
pub struct Job {
    pub contract: String,                    // "orcel.job/1"
    pub job_id: String,                      // 128-bit random, base32
    pub kind: JobKind,                       // web_crawl | web_batch_scrape
    pub owner: String,                       // Principal.principal_id; only the owner may read or cancel (S7)
    pub orcel_session_id: String,
    pub spec_digest: String,                 // canonical_json(spec) SHA-256; the approval binds it
    pub state: ExecutionState,               // not_started | dispatched | completed | cancelled | outcome_unknown
    pub outcome: Option<JobOutcome>,         // only when state == completed
    pub authority: DispatchAuthority,
    pub progress: JobProgress,               // { total, completed, failed, skipped }
    pub created_at_ms: u64, pub updated_at_ms: u64, pub expires_at_ms: u64,
}
pub enum JobOutcome { Succeeded, Partial, Failed { code: FailureCode } }
```

| From | To | Trigger |
| --- | --- | --- |
| (new) | `not_started` | Job admitted by policy; approval pending or granted, nothing dispatched |
| `not_started` | `cancelled` | Caller cancel, approval denied, approval prompt timed out (SOFT prompt expiry), emergency stop, or `orceld` restart |
| `not_started` | `dispatched` | First unit handed to an executor |
| `dispatched` | `completed` | Every unit finished; `outcome` set (`Partial` if some units failed) |
| `dispatched` | `cancelled` | Cancel, stop or lease expiry, and every executor confirmed it stopped |
| `dispatched` | `outcome_unknown` | An executor died, a stop could not be confirmed, or `orceld` restarted mid-job |

Terminal states are `completed`, `cancelled` and `outcome_unknown`. On restart, `orceld` moves every `not_started` job to
`cancelled` and every `dispatched` job to `outcome_unknown`, because their approvals were bound to the old
`orcel_session_id`; nothing resumes automatically. `outcome_unknown` is never retried (C-08); the caller may submit a new
job. Unit-level retries happen inside `dispatched` and are idempotent reads only.

### 4.8 Event audit chain

`orcel-audit` today appends JSON lines with no chain, and `orcel-policy` has `AuthorityAuditEvent` with
`AuditKind { Granted, Revoked, Expired, Invalidated }` for lease lifecycle. Wave 1 adds a chain around both without
changing what is redacted:

```rust
pub struct AuditEvent {
    pub contract: String,                    // "orcel.audit-event/1"
    pub seq: u64,                            // 0-based, gapless per log file
    pub prev_digest: String,                 // digest of seq-1; for seq 0 the last digest of the previous file, or 64 zeros
    pub at_ms: u64,
    pub kind: AuditEventKind,                // request | decision | approval | dispatch | state | lease | emergency_stop | sidecar | rotation | anchor
    pub request_id: Option<String>,
    pub job_id: Option<String>,
    pub principal_id: Option<String>,
    pub capability: Option<String>, pub operation: Option<String>,
    pub authority: Option<DispatchAuthority>,// lease id + binding digest + epoch for every Full Control dispatch (C-05)
    pub state: Option<ExecutionState>,
    pub detail: serde_json::Value,           // bounded, redacted; argv, URLs and query strings only as SHA-256 digests
    pub digest: String,                      // SHA-256(canonical_json(self without "digest"))
}
```

- **Relation to `AuditKind`.** Lease lifecycle keeps `AuthorityAuditEvent` unchanged: a `lease` event carries it
  verbatim in `detail`. A Full Control dispatch is a new `dispatch` event whose `authority.lease` is the `LeaseRef`.
  `AuditKind` gains no variant.
- **Write-before-dispatch.** The `dispatch` event is durably appended (flushed) before the executor starts. If the
  append fails, the dispatch is refused with `INTERNAL_ERROR` and nothing runs (C-29).
- **Anchoring.** Every 32 events, on every `lease` and `emergency_stop` event and on shutdown, `orceld` writes an
  `anchor` event and records `(file id, seq, digest)` outside executor reach: the Windows Event Log (WP1-03), the
  indicator display (WP1-12, informational only), and in Wave 2 the macOS unified log and the Linux journal.
- **Per-user Event Log write, no registration.** Registering an event source creates a key under
  `HKLM\SYSTEM\CurrentControlSet\Services\EventLog` and needs administrator rights, so Orcel does **not** register one.
  `RegisterEventSourceW(NULL, L"Orcel")` with an unregistered name returns a handle that writes to the Application log;
  `ReportEventW` with event id 4100 and category 0 stores the anchor as insertion strings
  (`orcel-anchor/1|<file id>|<seq>|<digest>|<orcel_session_id>`). Viewers show a "description cannot be found" note,
  which does not affect the stored strings. By default the Application log's security descriptor lets an
  interactive standard user write and read but not clear it; clearing needs administrator rights. A same-user process
  can add forged anchor records but cannot remove genuine ones, and a forged record conflicts with the chain and is a
  break. **This is a claim to prove, not assume:** WP1-03 runs the write, read-back and clear-refusal test as a
  standard (non-administrator) account created for the test on the Windows runner, and again on the founder's PC. If a
  machine's policy denies the write (a changed `CustomSD`), the anchor is unavailable, the capability report says so,
  and every Full Control dispatch is refused with `PROVIDER_UNAVAILABLE` and the reason "no durable audit anchor"
  (C-29); there is no indicator-only fallback.
- **Verification against anchors.** `orcel audit verify` queries every Orcel anchor record still present in the
  Application log (`EvtQuery`, provider name `Orcel`, event id 4100) and checks each one: its `(file id, seq)` must exist
  in the chain with the same digest; two records for the same `(file id, seq)` with different digests are a break; a
  record whose `seq` is beyond the chain's last line means the tail was truncated. The Application log rolls over
  (default size, overwrite oldest), so only anchors still present are checked; `verify` reports the oldest anchor it
  found so the coverage is visible.
- **Rotation** starts a new file whose `seq 0` `prev_digest` is the last digest of the previous file, recorded in a
  `rotation` event.
- **What the chain detects.** `orcel audit verify` recomputes the chain and reports the first break: an edit, insertion,
  deletion or reorder before the newest line. **Truncation of the tail** is detected only against the newest anchor
  outside the log (the Event Log record or the indicator), not by the chain alone. A same-user writer who rewrites the
  whole log is detected only if an anchor survives; C-26 keeps executor children away from the log, and C-27 states
  what remains. A break is evidence, not a repair: nothing is rewritten.

### 4.9 Sidecar IPC: handshake, heartbeat, kill

Generalizes SG-000074 (`proto.rs`): anonymous pipes, `u32` little-endian length plus JSON, closed vocabularies, unknown
frames rejected without action.

```rust
pub const SIDECAR_GENERATION: u32 = 1;
pub const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;   // as MAX_FRAME_BYTES today
// data frames: per-sidecar bound declared in the host's launch spec, at most 8 MiB

#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostToSidecar {
    Hello { generation: u32, session_nonce: String, limits: SidecarLimits },
    Heartbeat { seq: u64 },
    Request { id: u64, body: serde_json::Value },        // sidecar-specific, closed per kind
    Cancel { id: u64 },
    Shutdown { deadline_ms: u64 },
}
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum SidecarToHost {
    Hello { generation: u32, session_nonce: String, kind: String, version: String },
    HeartbeatAck { seq: u64 },
    Response { id: u64, body: serde_json::Value },
    Progress { id: u64, done: u64, total: Option<u64> },
    Error { id: Option<u64>, code: String },
    Bye {},
}
```

- The sidecar's reported `kind` and `version` are informational. Identity comes from the launch hash (C-10); a version
  string never decides policy, admission or capability status.
- `session_nonce` proves liveness and pairing of this pipe to this launch. It is not authentication: the pipe is
  private and inherited, and no frame grants authority.

| Phase | Rule |
| --- | --- |
| Launch | Resolve by pinned absolute path; refuse a group- or world-writable file; hash it and compare with the pin; execute from the hashed handle (C-10); empty environment plus an explicit allowlist; complete argv; inherited handles limited to the two pipes (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `close_range`) |
| Boundary | Windows: capability-less AppContainer (no `internetClient`, no `privateNetworkClientServer`) plus Job Object; macOS: Seatbelt deny-by-default including `network*`; Linux: seccomp denying non-`AF_UNIX` `socket`, `bind`, `listen`, plus Landlock and cgroup v2 |
| Handshake | First frame both ways is `Hello` within 5 s; generation and `session_nonce` must match; anything else kills the child |
| Listener check | Where the boundary cannot deny sockets outright, the host scans the child's sockets (`GetExtendedTcpTable`/`GetExtendedUdpTable` by PID on Windows) after `Hello` and every 5 s thereafter, killing on any listener |
| Heartbeat | Host sends `Heartbeat` every 2 s; three missed `HeartbeatAck` kill the child and mark its units `outcome_unknown` |
| Cancel | `Cancel` then 2 s grace; no `Response` or `Error` means kill |
| Shutdown | `Shutdown` then `Bye` within `deadline_ms` (at most 5 s), else kill |
| Kill | Windows `TerminateJobObject`; macOS and Linux `SIGKILL` to the process group plus `PR_SET_PDEATHSIG` / parent-death sentinel; `cgroup.kill` on Linux where delegated |
| Host death | Child sees end of file on stdin and exits; kill-on-close job, PDEATHSIG and sentinel cover a crashed host |

### 4.10 Errors

`FailureCode` keeps every existing variant and wire spelling. Wave 1 adds, at the end, each with a frozen-spelling test
like `remote_session_inactive_has_the_frozen_wire_spelling`:

| New code | Meaning | REST / Firecrawl HTTP |
| --- | --- | --- |
| `LEASE_REQUIRED` | A lease-gated executor was asked for without an active lease | 403 |
| `LEASE_INVALID` | A lease exists but a binding, the epoch, the policy revision or expiry does not match | 403 |
| `LEASE_UNSUPPORTED_PLATFORM` | No identity binding on this OS yet | 501 |
| `INDICATOR_UNAVAILABLE` | Full Control dispatch refused because the protected indicator is not alive (C-28) | 503 |
| `UNSUPPORTED` | Capability entry is `unsupported` | 501 |
| `POLICY_BLOCKED` | Capability entry is `blocked` (stealth, cloud-only, EE) | 403 |
| `JOB_NOT_FOUND` | Unknown, expired or not owned by the caller | 404 |
| `QUEUE_FULL` | Queue, store or per-principal pending-approval bound reached | 429 |
| `RATE_LIMITED` | Per-origin politeness budget exhausted for a synchronous call | 429 |
| `OUTCOME_UNKNOWN` | The job or unit ended in `outcome_unknown`; never retried automatically | 500 |

Existing codes map as: `INVALID_REQUEST` 400; `CAPABILITY_DENIED`, `WORKSPACE_DENIED`, `APPROVAL_DENIED`,
`APPROVAL_REQUIRED`, `PATH_ESCAPE`, `REMOTE_SESSION_INACTIVE` 403; `TARGET_STALE`, `PATH_RACE_DETECTED` 409;
`APPROVAL_UNAVAILABLE`, `PROVIDER_UNAVAILABLE` 503; `PROCESS_TIMEOUT` 408; `OUTPUT_LIMIT` 413; `POSTCONDITION_FAILED`,
`INTERNAL_ERROR`, `PROCESS_TERMINATION_UNVERIFIED` 500. A missing or wrong REST token is 401 before any envelope exists.
Firecrawl-shaped bodies are `{ "success": false, "error": <message>, "code": <FailureCode> }`. A test enumerates
`FailureCode` and fails if any variant lacks a mapping.

### 4.11 Web contracts, crawl execution and the job queue

**`orcel-contracts::web`** holds the Orcel-owned request that crosses from the pure mapping layer into `orceld`:

```rust
pub struct WebCrawlRequest {                 // contract "orcel.web-crawl/1"; no browser-host types
    pub start_url: String,
    pub include_paths: Vec<String>, pub exclude_paths: Vec<String>, // at most 16 each, 256 bytes each
    pub max_pages: u32,                      // at most 50 (MAX_CRAWL_PAGES)
    pub max_depth: u32,                      // at most 5 (MAX_CRAWL_DEPTH)
    pub deadline_s: u32,                     // at most 600 (MAX_CRAWL_DURATION)
    pub sitemap: SitemapMode,                // include | skip | only
    pub robots: bool,                        // always true in W1
    pub search: Option<String>,              // map ranking (WI-02)
    pub extract: Option<ExtractRequest>,     // formats subset of 5.3
    pub engine: Engine,                      // fetch | chromium (| obscura W2)
    pub delay_ms: u32,                       // politeness, at least 250
}
```

**`orcel-web`** (depends on `orcel-contracts` only) holds Apache-2.0 types for the Firecrawl-compatible subset of
section 5, derived field by field from the MIT SDK types (`apps/js-sdk/firecrawl/src/v2/types.ts`,
`apps/python-sdk/firecrawl/v2/types.py`), and pure translations:

```rust
pub struct Ids {                              // supplied by the front, never by the body
    pub request_id: String,                   // UUIDv4 generated by the front per HTTP request or MCP call
    pub client_session_id: String,            // MCP session id, or the REST token id
    pub workspace_id: String,                 // the transport's configured default workspace (4.0)
}
pub fn scrape_envelope(req: &ScrapeRequestV2, ids: &Ids) -> Result<RequestEnvelope, WebRefusal>;
pub fn crawl_request(req: &CrawlRequestV2) -> Result<WebCrawlRequest, WebRefusal>;
pub fn map_request(req: &MapRequestV2) -> Result<WebCrawlRequest, WebRefusal>;
pub fn document_v2(result: &ScrapeResult) -> serde_json::Value; // Firecrawl Document shape
```

`orceld` (`crates/orceld/src/web_dispatch.rs`) translates `WebCrawlRequest` into `orcel_browser_host::crawl::CrawlSpec`,
so `orcel-web` never depends on the browser host.

**Crawl unit granularity (decided).** `crawl.rs` keeps ownership of the crawl frontier, URL dedup, scope, depth, page
and deadline limits through its `CrawlDriver` trait (`fetch_text`, `open`, `links`, `extract`, `lost`). **One crawl or
map job is one `orcel-jobs` unit**: the whole `crawl::crawl` run. `orcel-jobs` does not duplicate the frontier; it
supplies the unit lifecycle, the per-origin throttle (called by the driver before every `open` and `fetch_text`),
cancellation, progress (pages read, from the driver) and the result store. Per-URL units and per-URL dedup in
`orcel-jobs` apply to **batch scrape only**, where each URL is an independent unit. Rationale: the crawl limits and
scope rules are qualified code (SG-000108 slice 7); splitting the frontier would re-open that qualification.

**Drivers.** `WorkerCrawl` (exists, `worker_launch.rs`) drives the chromium engine. **`FetchCrawlDriver`** (new,
`crates/orceld/src/fetch_crawl.rs`, WP1-06) drives the fetch engine on Windows: `fetch_text` and `open` call the SG-000040
transport with the job's pinned resolved-address set (redirects revalidated, same-origin only, 1 MiB body); `links`
and `extract` run the HTML through the contained parser's `html` format (WP1-08); `lost` reports a parser or transport
failure that ended the run.

**`orcel-jobs`** (pure plus files under the private state root; no tokio, no server database):

| Module | Behaviour | Source of the idea (section 6.2) |
| --- | --- | --- |
| `queue.rs` | Durable FIFO of units with in-progress leases, reclaim after timeout; uniqueness by normalized-URL key for batch units | Crawlee `request-queue.ts`, `request-dedup-cache.ts` |
| `throttle.rs` | Per-origin minimum delay and token bucket; honours `Retry-After`; robots `Crawl-delay` when robots is on; callable by drivers | Crawlee `throttling-request-manager.ts`, Scrapling `spiders/throttle.py` |
| `retry.rs` | Exponential backoff with jitter, max 3 attempts, read-only batch units only; 4xx other than 408 and 429 not retried | Crawlee `basic-crawler.ts`, `request-timeout.ts` |
| `concurrency.rs` | Batch concurrency 1 to 4, stepped down on memory pressure and engine failures; no CPU spinning | Crawlee `autoscaling/autoscaled-pool.ts`, `snapshotter.ts`, `system-status.ts` |
| `checkpoint.rs` | Append-only progress log used to report, not resume: on restart, units are ended per section 4.7 | Scrapling `spiders/checkpoint.py` |
| `store.rs` | Results written once per unit; at most 20 MiB per job and **200 MiB across all jobs**; expiry 24 h; `next` cursor | Crawlee `dataset.ts`, `key-value-store.ts` |

**Bounds that hold regardless of mode** (unchanged from SG-000108 slice 7 unless an FD changes them): per crawl at most
50 pages, depth 5, 10 minutes and 1,000 remembered URLs; per batch at most 50 URLs; at most 8 jobs queued and 2 running
device-wide; per principal at most 4 queued jobs and **1 pending approval prompt**; **device-wide at most 2 pending web
approval prompts** across all principals (a third request fails `QUEUE_FULL` without raising a prompt); a pending
approval that is not answered within the SOFT prompt expiry cancels the job.

### 4.12 Loopback REST access

- **Separate token.** The REST routes do not accept the MCP loopback token. Each REST client gets its own token,
  `orcel_rest_<26 base32 chars>` (128 bits of randomness), created by `orcel client add-rest <name>` from the local
  control path, stored hashed (SHA-256) under the state root, mapped to a `RestClient` principal, rotated by
  `orcel client rotate-rest <name>` (the old token fails immediately), and revoked by `orcel client remove-rest <name>`.
  `add-rest` and `rotate-rest` each require a SOFT approval through the local approval broker (the protected system
  dialog, `PROTECTED_WINDOW_MARKERS` "orcel approval"), showing the client name; no MCP or REST caller can reach them.
  `remove-rest` needs no approval, because it only removes access.
- **Ownership.** Jobs are owned by the principal that created them; another principal gets `JOB_NOT_FOUND`.
- **Bounds per principal:** section 4.11.
- **SDK default URL guard.** The Firecrawl SDKs fall back to `https://api.firecrawl.dev` when `apiUrl` and
  `FIRECRAWL_API_URL` are unset, and would send the Orcel token there. `orcel client add-rest` therefore prints a config
  that always sets `apiUrl` explicitly, refuses to emit a config without it, and the docs state the risk. The
  `orcel_rest_` prefix makes a leaked token identifiable and revocable.
- **Wave 2 WebSocket** (crawl watcher) checks `Host`, `Origin` and the REST token on the upgrade request with the same
  rules as HTTP.

### 4.13 Full Control indicator protocol (Windows, Wave 1)

**Process and launch.** `apps/orcel-indicator` is a small Rust program. `orceld` alone launches it: at `orceld` start
when an active lease exists, and whenever the dispatcher first sees an active lease with no live indicator. Launch
follows C-10: pinned absolute path beside `orceld` in the install, hash verified against the build-time pin, executed
from the hashed handle, empty environment, complete argv, and exactly two inherited handles (one anonymous pipe pair,
listed in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`). It runs with the user's normal token, not the executor token, because
it must draw a topmost window; it is **not** placed in an executor Job Object, so killing executors never kills it. If
it exits, `orceld` relaunches it at most once every 10 s and refuses Full Control dispatches meanwhile.

**Peer authentication.** The pipe is anonymous and inherited by exactly one process, so holding it is the binding; no
secret travels on it.
- `orceld` knows the child by the process handle `CreateProcessW` returned and checks, before trusting any frame, that
  the handle's image path (`QueryFullProcessImageNameW`) is the pinned indicator path.
- The indicator receives `orceld_pid` and `orceld_start_time` in `Hello`, opens that process with
  `PROCESS_QUERY_LIMITED_INFORMATION`, and checks that its image path is the pinned `orceld` path, that its creation
  time matches, and that it is the indicator's own parent (`NtQueryInformationProcess`, `InheritedFromUniqueProcessId`).
  Any mismatch makes the indicator show "Not connected to Orcel" and send nothing.
- `orceld` and the indicator each apply a deny ACE for the executor SID (section 4.14) to their own process object at
  startup, so executor children cannot open, read or inject into either (C-26).

**Indicator self-protection.** Before creating its window, the indicator enables, with `SetProcessMitigationPolicy`:
- `ProcessExtensionPointDisablePolicy` (`DisableExtensionPoints`): legacy extension points, including DLLs that
  `SetWindowsHookEx` would load into it, AppInit DLLs and IMEs from outside the system, are not loaded;
- `ProcessSignaturePolicy` (`MicrosoftSignedOnly`): only Microsoft-signed DLLs load after this point. The indicator is
  one statically linked Rust executable that loads only system DLLs, so this works for the unsigned development build
  too (the policy governs DLL loads, not the already-running image); a CI test asserts the indicator starts and draws
  with the policy on;
- `ProcessImageLoadPolicy` (`NoRemoteImages`, `NoLowMandatoryLabelImages`, `PreferSystem32Images`);
- `ProcessDynamicCodePolicy` (`ProhibitDynamicCode`): no executable memory can be created or modified in it.
If any call fails, the indicator shows "Protection unavailable" and sends no heartbeat, so Full Control stays refused.

**Input and window handling.** The native host (profile D) shares the interactive desktop and integrity level, so it
can send input and window messages to the indicator (UIPI allows same-integrity senders). Profile S processes are on
another desktop and cannot. The indicator therefore:
- acts on Stop only for **hardware input**: every mouse, pointer and key message is checked with
  `GetCurrentInputMessageSource`, and messages whose `originId` is `IMO_INJECTED` (or `IMO_UNAVAILABLE`) are ignored.
  The indicator has no other control, so injected input can neither press anything nor drag it;
- treats any request to close, minimise or hide it (`WM_CLOSE`, `WM_SYSCOMMAND` with `SC_CLOSE` or `SC_MINIMIZE`,
  `WM_SHOWWINDOW` false, `WM_QUERYENDSESSION`) as a **Stop** (the fail-safe direction), and rejects position and
  z-order changes it did not make (`WM_WINDOWPOSCHANGING`: restores its position and `HWND_TOPMOST`);
- treats a lost heartbeat condition (below) as unavailable, never as a reason to keep Full Control running.

**Stop paths, and what can block them.**

| Path | How | Can same-session user-mode code block it? |
| --- | --- | --- |
| Stop button | Hardware click on the indicator | A misbehaving native host could swallow input with a low-level hook or `BlockInput`; the static guard of section 4.14 keeps those calls out of the pinned host |
| Hotkey | Ctrl+Alt+Shift+F12 via `RegisterHotKey` | Same as above; never shown as ready if registration failed |
| **Session lock** | Ctrl+Alt+Del then Lock, or Win+L | **No.** The secure attention sequence is handled by Winlogon and cannot be intercepted or synthesized by user-mode code. `orceld` and the indicator both call `WTSRegisterSessionNotification`; on `WTS_SESSION_LOCK` each performs Stop (`orceld` advances the epoch; the indicator terminates held Job Objects and writes a revoke request). A lock requested by software (`LockWorkStation`) only stops, which is safe |

The grant prompt and the indicator both say "Lock your PC (Win+L) to stop Full Control at any time", unless locking is
disabled (below).

**Locking disabled by policy.** At startup and every 10 s the indicator reads `DisableLockWorkstation` under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System` (and the same value under `HKLM`). If either is 1, it
shows "Locking is disabled on this PC: lock-to-stop is unavailable, use the Stop button", never lists lock-to-stop as
ready, and sends `LockStatus { available: false }`; `orceld` records it in the capability report and audits it with the
next `lease` event. Full Control is not refused for this alone, but the user is told on every grant.

**Residual: low-level hooks by other same-user processes.** Any non-executor process already running as the user (not
an Orcel executor, which C-26 and the UI limits confine) can install `WH_MOUSE_LL` or `WH_KEYBOARD_LL` hooks, or call
`BlockInput`, and so swallow clicks on Stop and the hotkey. Orcel cannot prevent this at the same integrity level. It is
covered by the session-lock path: the secure attention sequence is not delivered through low-level hooks, so
Ctrl+Alt+Del then Lock still stops Full Control. Where locking is disabled by policy, this residual is uncovered, and the
indicator says so.

**Frames.** As section 4.9: `u32` little-endian length plus JSON, closed vocabularies, at most 16 KiB per frame,
unknown frames refused without action.

```rust
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrceldToIndicator {
    Hello { generation: u32, orceld_pid: u32, orceld_start_time: u64, nonce: String },
    State { lease: Option<LeaseView>, anchor: Option<AnchorRef> },   // shown, never trusted for authority
    JobHandle { job_id: String, handle: u64 },                        // value valid in the indicator's own handle table
    JobGone { job_id: String },
    StopAck { new_epoch: u64 },
}
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub enum IndicatorToOrceld {
    Hello { generation: u32, nonce: String },
    Heartbeat { seq: u64, visible: Visibility },
    StopRequest { reason: StopReason },                               // button | hotkey | close_or_hide | session_lock
    HotkeyStatus { registered: bool },
    LockStatus { available: bool },                                   // false when DisableLockWorkstation is set
}
pub struct Visibility { topmost: bool, not_minimised: bool, not_cloaked: bool, on_monitor: bool, on_input_desktop: bool }
pub struct AnchorRef { file_id: String, seq: u64, digest: String }
```

**Heartbeat.** The indicator sends `Heartbeat` every 1 s **only if** all five visibility checks pass at that moment:
`WS_EX_TOPMOST` set and the window first in the topmost band (`GetWindow(GW_HWNDFIRST)` walk), `IsWindowVisible` true and
`IsIconic` false, `DwmGetWindowAttribute(DWMWA_CLOAKED)` zero, the window rectangle at least 80% inside a monitor's work
area (`MonitorFromWindow`, `GetMonitorInfoW`), and its thread's desktop is the input desktop (`OpenInputDesktop`
succeeds and `GetUserObjectInformationW(UOI_NAME)` equals the name of `GetThreadDesktop(GetCurrentThreadId())`).
Otherwise it re-asserts topmost, restores itself and sends nothing until the checks pass. `orceld` refuses every Full
Control dispatch when the last heartbeat with all five fields true is older than 2 s (`INDICATOR_UNAVAILABLE`). The
checks are self-reported; their integrity rests on C-26 (executors cannot open the indicator process), the mitigation
policies above (no injected DLLs or dynamic code), the UI limits of section 4.14 (no desktop switching by executors),
and the input handling above.

**Job Object handles.** For every executor child, `orceld` creates the Job Object, assigns the child, then calls
`DuplicateHandle(orceld, job, indicator_process, &h, JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY, FALSE, 0)`. Direction is
`orceld` to indicator only; the rights exclude `JOB_OBJECT_ASSIGN_PROCESS` and `JOB_OBJECT_SET_ATTRIBUTES`, so the
indicator can end executors but cannot add processes or change limits. `orceld` sends the value in `JobHandle` and
`JobGone` when the job ends (the indicator then closes it).

**Stop.**
1. Button (primary, hardware input only), hotkey, a close or hide request, or session lock: the indicator sends
   `StopRequest` (`orceld` also acts on the session lock by itself). `orceld` takes the epoch lock, advances the epoch,
   cancels jobs, terminates every executor Job Object, writes the `emergency_stop` audit event and replies `StopAck`.
2. No `StopAck` within 1 s (`orceld` hung or dead): the indicator calls `TerminateJobObject` on every handle it holds,
   then writes a **revoke request**: a new file `%USERPROFILE%\.orcel\stop\<utc-ms>-<random>.json` containing
   `{ "contract": "orcel.revoke-request/1", "at_ms", "reason", "last_epoch_seen" }`, created with `CREATE_NEW` and
   flushed. It shows "Stopped (Orcel not responding)".
3. `orceld` checks the `stop` directory inside the epoch lock before every Full Control dispatch, at start, and every
   1 s. Any file present advances the epoch (`full_control_store::revoke`, run by `orceld`, which holds the key),
   writes an `emergency_stop` event with `source: "indicator_out_of_band"`, and then deletes the file.

**Why this design.** The indicator never holds the authority key, so it adds no new path to mint or forge authority,
and C-26 is unaffected: the stop directory is inside the state root, which executors cannot write, so an executor can
neither forge nor delete a request. A revoke request is unauthenticated on purpose: it can only remove authority, never
grant it, so a forged request by a non-executor same-user process is at worst a denial of Full Control, which the user
can re-grant with STRONG presence. The Job Object handles let the stop take effect even when `orceld` is hung, and the
revoke request makes it stick before the next dispatch.

**Hotkey.** The indicator calls `RegisterHotKey` for Ctrl+Alt+Shift+F12 (fixed in Wave 1). If registration fails, it
sends `HotkeyStatus { registered: false }`, shows "Hotkey unavailable: use the Stop button", and never shows a hotkey
as ready; the Stop button is always the primary control and is shown first.

### 4.14 Executor process boundaries on Windows (Wave 1)

Revision 4 replaces the revision 3 token, whose restricting list held the user SID and so passed the access check on
every other process the user owns.

| Executor class | Executor child process | Launched by | Token profile | Desktop | Job Object UI limits |
| --- | --- | --- | --- | --- | --- |
| DesktopInput (SG-000095) | The native computer host `apps/orcel-computer-host` (Go), today spawned by `crates/orcel-provider-uia/src/computer_host.rs` (`HostSession::spawn`) through the `ComputerHostAdapter` singleton in `crates/orceld/src/uia.rs` | `orceld` | D | The interactive `WinSta0\Default` (it must act there) | All `JOB_OBJECT_UILIMIT_*` except `HANDLES` |
| ShellProcess (SG-000096, when qualified) and any other process-starting executor | Each session's process and its descendants | `orceld` | S | A dedicated `OrcelExec` window station and desktop per lease | All `JOB_OBJECT_UILIMIT_*` |
| Filesystem (SG-000097, when activated) | In-process provider, no child | n/a | n/a | n/a | n/a; state-root paths refused by the provider |

**Executor SID.** `orceld` creates, once per install, a random SID `S-1-9-<four random 32-bit values>` (resource-manager
authority, never assigned to any account) and records it under the state root.

**Token profile S (process-starting executors).** `CreateRestrictedToken` on `orceld`'s primary token with
`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege` and `SeRestorePrivilege` deleted if present, and the
restricting SID list { executor SID, `Everyone`, `BUILTIN\Users`, `NT AUTHORITY\Authenticated Users`,
`NT AUTHORITY\RESTRICTED` }. **Neither the user SID nor the logon SID is in the list.** Consequences:
- Another process the user owns has a default DACL granting the user SID, `SYSTEM` and the logon SID; none of those is a
  restricting SID, so the restricted check fails and a profile S process cannot open explorer, the terminal, the
  browser, `orcel-mcp`, `orceld` or the indicator at all.
- It reaches only what grants one of its restricting SIDs: system directories readable by `Users`, and **workspace roots
  granted explicitly to the executor SID** by `orceld` with no-follow ACL grants for the lease's duration (the
  SG-000060 contained-tier pattern, Chromium-style), plus a private temp directory granted the same way. The user's
  profile, credential files (`.ssh`, `.gitconfig`, browser profiles) and the Orcel state root are unreachable unless a
  root is granted; the state root additionally carries the deny ACE below and can never be granted.
- It runs on a dedicated window station and desktop created by `orceld` per lease (`CreateWindowStationW`,
  `CreateDesktopW`, DACLs granting only the executor SID and `orceld`), named in `STARTUPINFOW.lpDesktop`. Window
  messages and Windows hooks do not cross desktops, so it cannot message, hook, close, move or cover the indicator, and
  GUI programs it starts are invisible to the user (stated consequence; console programs work).
- Its Job Object sets every `JOB_OBJECT_UILIMIT_*` flag (`HANDLES`, `READCLIPBOARD`, `WRITECLIPBOARD`,
  `SYSTEMPARAMETERS`, `DISPLAYSETTINGS`, `GLOBALATOMS`, `DESKTOP`, `EXITWINDOWS`), plus kill-on-close.

**Token profile D (the native host).** Same construction with the restricting SID list { executor SID, logon SID,
`Everyone`, `BUILTIN\Users`, `NT AUTHORITY\Authenticated Users`, `NT AUTHORITY\INTERACTIVE` }; **the user SID is not in
the list**. The logon SID is needed because `WinSta0` and `Default` grant it, and `SendInput` needs
`DESKTOP_JOURNALPLAYBACK` on the input desktop, which the default desktop DACL grants to the logon SID.
- Through default process DACLs the logon SID receives read and execute rights on the user's other processes. For a
  process, `GENERIC_READ` maps to `PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION` and `READ_CONTROL`, and
  `GENERIC_EXECUTE` to `PROCESS_QUERY_LIMITED_INFORMATION` and `SYNCHRONIZE`. It does **not** receive
  `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE` or `PROCESS_TERMINATE`, so it
  cannot inject into or act through another process. WP1-10 measures the exact granted rights on the runner and records
  them; if the measured set includes any write, thread or handle right, the packet stops.
- **Residual R-D1:** profile D can read other same-user processes' memory. The native host is Orcel's own pinned
  binary; the agent controls only the closed protocol's actions; today its only process call is
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` (`native_win32_windows.go`). A static guard (WP1-10) fails CI if the Go
  host gains `ReadProcessMemory`, `OpenProcess` with any other right, `SetWindowsHookEx`, `BlockInput`, `CreateDesktop`,
  `SwitchDesktop` or `RegisterRawInputDevices` with `RIDEV_INPUTSINK`.
- Job Object: kill-on-close, one active process, die on unhandled exception, and the UI limits `READCLIPBOARD`,
  `WRITECLIPBOARD` (the Go host has no clipboard call; clipboard stays with `orcel-provider-clipboard` in `orceld`),
  `SYSTEMPARAMETERS`, `DISPLAYSETTINGS`, `GLOBALATOMS`, `DESKTOP` (no `CreateDesktop` or `SwitchDesktop`) and
  `EXITWINDOWS`. It **cannot** take `UILIMIT_HANDLES`, which forbids using window handles owned by processes outside the
  job; the host must find, focus and act on other processes' windows.

**What the native host still needs, and what may be lost.** `SendInput` takes no handle to the target; it needs the
input desktop and `DESKTOP_JOURNALPLAYBACK` (logon SID) and is subject to UIPI (same medium integrity: allowed).
Window enumeration, focus and placement use window handles, which `UILIMIT_HANDLES` would block and profile D allows.
UI Automation clients mostly work without process handles (providers answer over UIA's cross-process channel), but two
things are unproven under a restricted token: COM access checks in target processes that call
`CoInitializeSecurity` with restrictive defaults, and legacy common-control proxies (list view, tree view, tab) that
allocate and read memory in the target process. WP1-10 runs the existing native qualification suites
(`native_qualification_windows_test.go`, `native_input_qualification_windows_test.go`) under profile D and records each
capability that fails. A failing capability is reported `unsupported` under a lease; the token is never widened to fix
it. If observation fails broadly, FD-UP-9's sub-question (b) applies.

**ACLs that make it bite.** At install and at every `orceld` start, `orceld` sets on the state root (protected,
inheritance on): an explicit **deny** ACE for the executor SID covering `GENERIC_ALL`, `WRITE_DAC` and `WRITE_OWNER`; an
`OWNER RIGHTS` (`S-1-3-4`) ACE granting `READ_CONTROL` only, removing the owner's implicit `WRITE_DAC`; and an explicit
full-control grant for the user SID for `orceld` itself. `orceld` and the indicator also set a deny ACE for the executor
SID on their own process objects (belt and braces: profile S already fails their DACLs; profile D would otherwise get
read rights through the logon SID). The same deny ACE covers the other Orcel processes that hold tokens or session
state, narrowing R-D1:
- the `orcel-mcp` front: Node cannot call `SetSecurityInfo` without a native addon, so `orceld` applies the ACE to its
  own launching parent at startup, identified by `InheritedFromUniqueProcessId` with a creation time earlier than its
  own and the image path of the pinned Node runtime, opening it with `READ_CONTROL | WRITE_DAC` only; if the parent
  cannot be identified, Full Control is refused for that session;
- `apps/orcel-agent` (Python): applies the ACE to itself at startup through `ctypes` (`advapi32.SetSecurityInfo` on
  `GetCurrentProcess()`), with the executor SID read from `orceld`'s status response, and refuses to start a Full
  Control session if the call fails. A restricted token's access check passes only if both the normal and the
restricting SID checks pass, and a deny ACE matching a restricting SID fails the second check, so executors and every
descendant are denied while the user's ordinary processes are unaffected.

**Tests (WP1-10).** From each profile (the native host under D; a test shell and its grandchild under S):
- open each protected file for read and write, change the state root's DACL, take ownership: all denied;
- open `explorer.exe`, a second same-user test process, `orcel-mcp`, `orceld` and the indicator with `PROCESS_VM_WRITE`,
  `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD` and `PROCESS_DUP_HANDLE`: all denied for D and S; under S also
  `PROCESS_QUERY_LIMITED_INFORMATION` denied; under D `PROCESS_VM_READ` to `orceld`, the indicator, `orcel-mcp` and
  `orcel-agent` denied (process deny ACE);
- under S, indirect process creation through system services is refused, or the process it creates still carries the
  restricted token (checked by reading the new process's token restricting SIDs): `schtasks /create` and the Task
  Scheduler COM API (`ITaskService`) with an interactive logon type and `/run`; WMI `Win32_Process.Create`; a BITS job
  with `SetNotifyCmdLine`; out-of-process COM/DCOM activation of a local server such as Explorer's `ShellWindows`
  (`IShellDispatch2.ShellExecute`) and `MMC20.Application`. Any of these that yields a process with the user's full
  token fails the packet;
- under S: `FindWindowW` for the indicator fails (other desktop), `SetWindowsHookExW` targeting the indicator's thread
  fails, `PostMessageW(WM_CLOSE)` cannot reach it, a GUI program started by the shell is not visible on `Default`;
- under D: `CreateDesktopW` and `SwitchDesktop` fail (UI limit); clipboard read and write fail; `SendInput` into a test
  Notepad succeeds;
- a normal user process can still read the state root (regression guard for `orceld` itself).

**Stated limits.** Profile D can read same-user process memory (R-D1) and can send input and window messages to any
same-desktop window at its integrity, including the indicator; section 4.13 makes the indicator ignore injected input,
fail safe on close or hide, and adds a stop path no user-mode code can block. Desktop input can still type into a
terminal the user opened, which runs with the user's full token (C-27).

## 5. Firecrawl parity matrix

### 5.1 Upstream contract facts (verified 2026-11-16)

- **Pins.** The inventory pin is `firecrawl/firecrawl@42f4d669954649ce33466a2a50e8215c7f1f4d1c`; PR #785 pinned
  `25a92fc3175babbd75fd50a0e8122aaa44b068ad`. The route tables `apps/api/src/routes/v1.ts` and `v2.ts` were read at both
  SHAs and are identical, so this matrix holds for either. Orcel's existing ports were taken at `f84845c8`.
- **Versions.** The upstream server exposes **v2** (current; `apps/api/openapi.json`, `info.version` `v2`, server
  `https://api.firecrawl.dev/v2`) and **v1** (legacy; `apps/api/v1-openapi.json`). Both OpenAPI files are in the AGPL
  `apps/api` tree and are read as reference only (C-15).
- **SDKs used as contract clients.** `@mendable/firecrawl-js` **4.54.0** (`apps/js-sdk/firecrawl/package.json`, MIT,
  Copyright (c) 2024 Sideguide Technologies Inc.): the default `Firecrawl` client speaks v2, a v1 client remains. It
  reads `apiUrl` (falling back to `FIRECRAWL_API_URL`, then `https://api.firecrawl.dev`, see 4.12) and sends the API key
  as a bearer token. `firecrawl-py` **4.57.0** (`apps/python-sdk/firecrawl/__init__.py`, MIT) has `v1` and `v2` clients.
- **Upstream route counts at the pin:** v2 70 routes, v1 33 route lines of which 6 are commented out
  (`/crawlWebsitePreview`, `/checkJobStatus/:jobId`, `/keyAuth`, the v0 `/search`, `/health/liveness`,
  `/health/readiness`).
- **Parity target.** Orcel implements the **v2** contract for scrape, map, crawl and batch scrape (plus job status,
  cancel, errors and listing) in Wave 1, with **v1 aliases** for `POST /v1/scrape`, `/v1/map`, `/v1/crawl` and the v1
  crawl status, cancel and errors routes. Everything else is a later wave, `unsupported` (501), or out of scope (404).
- **Platform in Wave 1:** Windows (fetch engine in the builds FD-UP-7 allows; chromium engine in `live-browser-dev`
  and `live-browser-test` builds). macOS and Linux answer 501 `UNSUPPORTED` until WP2-12 and SG-000115.

### 5.2 Endpoint matrix

Status vocabulary: `existing-lib` (tested Orcel library code, not exposed), `new` (to build in the stated wave),
`unsupported` (answers 501 `UNSUPPORTED` until its wave), `blocked` (403 `POLICY_BLOCKED`, cloud-only or policy), `n/a`
(hosted SaaS concern; 404). MCP tools are `local_only` in Wave 1 (C-06; remote exposure is a later decision).

| # | Upstream route (v2; v1 alias) | Orcel MCP tool | Orcel backing | Wave | Status today | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `POST /v2/scrape`; `POST /v1/scrape` | `web_scrape` | fetch engine (WP1-08) or `BrowserWorker::extract_page` | W1 | new | Synchronous; one SOFT approval per request |
| 2 | `POST /v2/map`; `POST /v1/map` | `web_map` | `crawl.rs` map mode + `map_rank.rs` via a driver | W1 | existing-lib | One job unit; `search` ranks via WI-02; `sitemap` include/skip/only |
| 3 | `POST /v2/crawl`; `POST /v1/crawl` | `web_crawl_start` | orcel-jobs + `crawl.rs`/`crawl_scope.rs` via a driver | W1 | existing-lib (crawl), new (async) | Returns `{ success, id, url }`; `url` is the loopback status URL |
| 4 | `GET /v2/crawl/{id}`; v1 alias | `web_job_status` | orcel-jobs store | W1 | new | Status mapping in 5.5; `next` cursor; owner only |
| 5 | `DELETE /v2/crawl/{id}`; v1 alias | `web_job_cancel` | orcel-jobs | W1 | new | `{ status: "cancelled" }` only after executors confirm |
| 6 | `GET /v2/crawl/{id}/errors`; v1 alias | `web_job_errors` | `CrawlReport.skipped`, unit failures | W1 | existing-lib (report) | `robotsBlocked` from robots refusals |
| 7 | `GET /v2/crawl/ongoing`, `/v2/crawl/active` | `web_job_list` | orcel-jobs | W1 | new | Only the caller's jobs |
| 8 | `POST /v2/batch/scrape` | `web_batch_scrape_start` | orcel-jobs + scrape | W1 | new | At most 50 URLs; one SOFT approval binds the URL list and address sets |
| 9 | `GET`/`DELETE /v2/batch/scrape/{id}`, `/errors` | `web_job_status`, `_cancel`, `_errors` | orcel-jobs | W1 | new | Same job API as crawl |
| 10 | `POST /v2/search`; `POST /v1/search` | `web_search` (exists) | `crates/orceld/src/search.rs` (BYOK, off by default) | W1 | existing (MCP) | Results only; `scrapeOptions` refused until W2 |
| 11 | `GET /v2/scrape/{jobId}` | `web_job_status` | orcel-jobs | W2 | unsupported | Async scrape result retrieval |
| 12 | `POST /v2/parse`, `GET /v2/parse/formats`, `POST /v2/parse/upload-url`, `PUT /v2/parse/upload/{uploadId}` | `document_parse` | `apps/orcel-doc-parser` under orcel-contain | W2 | existing-lib (parser) | Upload lands in a private staging dir; bounded |
| 13 | WebSocket crawl watcher (`crawl-status-ws`) | none | loopback WS over the job store (4.12) | W2 | unsupported | SDK `watcher` |
| 14 | `GET /v2/team/queue-status`, `GET /v2/concurrency-check` | `web_job_list` | orcel-jobs counts | W2 | unsupported | Local counts, no billing |
| 15 | `POST /v2/extract`, `GET /v2/extract/{id}`; v1 aliases | `web_extract` | model provider (BYOK or local, SG-000104 line) | W3 | unsupported | Needs a model; schema-validated output |
| 16 | `POST /v2/crawl/params-preview` | none | model provider | W3 | unsupported | LLM-derived crawl parameters |
| 17 | `POST /v1/llmstxt`, `GET /v1/llmstxt/{id}`, `POST /v1/deep-research`, `GET /v1/deep-research/{id}` | none | model provider | W3 | unsupported | Re-evaluate with the agent work |
| 18 | `/v2/monitor*` (9 routes) | none | change tracking + scheduler | W3 | blocked (cloud-only) | A local scheduled change check is built; Firecrawl monitor parity is not claimed |
| 19 | `/v2/agent*` (8 routes), `POST /v1/fireclaw` | none | apps/orcel-agent is separate | none | blocked (cloud-only) | Different product contract |
| 20 | `/v2/scrape/{jobId}/interact` (POST, DELETE), `/v2/interact*`, `/v2/browser` | Orcel `browser_*` tools | browser host | none | blocked (cloud-only) | Hosted browser sessions; Orcel's own browser tools are the local equivalent |
| 21 | `/v2/team/credit-usage*`, `/token-usage*`, `/activity`; v1 team routes | none | none | none | n/a | No billing in the zero-cost baseline |
| 22 | `/v2/keyless/*`, `/v2/slack/*`, `/v2/support/*`, `/v2/feedback`, `/v2/search/{jobId}/feedback`, `/v2/team/siem*`, `/v2/team/threat-protection*`, `/v2/search/research/*`, `/v2/search/developer`, `/v2/search/gov` | none | none | none | n/a | Hosted SaaS features |

### 5.3 `POST /v2/scrape` options (field-level)

Upstream request fields at the pin: `url` (required), `formats`, `onlyMainContent`, `onlyCleanContent`, `includeTags`,
`excludeTags`, `maxAge`, `minAge`, `headers`, `waitFor`, `mobile`, `skipTlsVerification`, `timeout`, `parsers`, `actions`,
`location`, `removeBase64Images`, `blockAds`, `proxy`, `storeInCache`, `lockdown`, `checkPromptInjection`, `redactPII`,
`profile`, `threatProtection`, `auditMetadata`, `zeroDataRetention`, `alexandria`, `maxCredits`, `domainTools`,
`toolDetail`. Upstream `formats` accepts strings or `{ type }` objects.

| Field | Orcel W1 | Later | Rule |
| --- | --- | --- | --- |
| `url` | yes | | Public HTTPS on port 443 only (SG-000040 rules for fetch; SG-000075 for chromium); resolved-address set bound into the approval |
| `formats: markdown` | yes | | Default, as upstream |
| `formats: html`, `rawHtml` | yes | | Bounded (1 MiB fetch body; extraction bounds in the browser host) |
| `formats: links` | yes | | From the observation (browser) or the parser (fetch) |
| `formats: changeTracking` | yes (`git-diff` mode) | `json` mode W3 | `change_tracking.rs` (WI-04); state under the private root |
| `formats: screenshot` | no (501) | W2 | Needs the engine capture contract (WP2-04) |
| `formats: json`, `summary`, `question`, `highlights`, `query`, `product`, `menu`, `branding`, `attributes`, `images`, `audio`, `video`, `deterministicJson`, `rawBase64` | no (501) | `json`/`summary` W3 (model); `images`, `attributes` W2; rest not planned | Named in the refusal |
| `onlyMainContent` | yes | | Existing extraction main-content rule |
| `includeTags`, `excludeTags` | yes | | CSS selectors applied by the extractor; at most 16 of each |
| `waitFor`, `timeout` | yes | | Capped by the engine's own timeouts |
| `maxAge` | `0` only | W2 cache | Non-zero answers 501 until the result cache exists |
| `parsers: pdf` | yes | | Through the contained parser (FD-06 path) |
| `actions` | no (501) | W2 | Each action maps to an existing SOFT-approved browser shape; none is approval-free |
| `blockAds` | no (ignored false) | W2 | Scrapling ad-domain list (BSD-3) as navigation blocklist data |
| `headers` | refused (400) | FD-UP-8 | Custom request headers can carry credentials |
| `skipTlsVerification` | refused (400) | never | Contradicts SG-000040 and SG-000075 |
| `proxy: "stealth"`, `mobile`, `location` | refused (403 `POLICY_BLOCKED`) | FD-UP-2 | Fingerprinting and geo-spoofing |
| `proxy: "basic"` / `"auto"` | accepted as no proxy | | Local egress only |
| `storeInCache`, `zeroDataRetention` | accepted as no-ops | | Nothing leaves the device; nothing is cached in W1 |
| `profile`, `lockdown`, `checkPromptInjection`, `redactPII`, `threatProtection`, `auditMetadata`, `alexandria`, `maxCredits`, `domainTools`, `toolDetail`, `onlyCleanContent`, `minAge`, `removeBase64Images` | refused (400, named) | re-evaluated per wave | Hosted or model features |
| `orcel.engine` (extension) | yes | | `fetch` (Windows W1), `chromium` (dev/test builds); `obscura` W2. The result and audit always name the engine that ran; a fallback is reported, never silent |

### 5.4 Map and crawl options

| Upstream field | Orcel W1 | Rule |
| --- | --- | --- |
| map `url`, `search`, `limit` (at most 50 pages read), `includeSubdomains: false`, `ignoreQueryParameters` | yes | Same-origin only (`crawl.rs`); `includeSubdomains: true` refused (one admitted destination) |
| map `sitemap` (`include`, `skip`, `only`); v1 `ignoreSitemap`, `sitemapOnly` | yes | Existing sitemap reading (#317) |
| map `timeout` | yes | Capped at the 10-minute crawl deadline |
| map `location`, `ignoreCache`, `threatProtection`, `auditMetadata` | refused / no-op | As 5.3 |
| crawl `url`, `includePaths`, `excludePaths`, `limit` (at most 50), `maxDiscoveryDepth` (at most 5); v1 `maxDepth` | yes | `MAX_CRAWL_PAGES` 50, `MAX_CRAWL_DEPTH` 5, `MAX_CRAWL_DURATION` 600 s (FD-UP-11 to change); filters narrow, the origin is the boundary |
| crawl `sitemap`, `ignoreQueryParameters`, `regexOnFullURL` | yes | WI-01 regex patterns exist |
| crawl `delay`, `maxConcurrency` | `delay` at least 250 ms; `maxConcurrency` accepted, effective 1 | A crawl is one unit with one page in flight (4.11) |
| crawl `scrapeOptions` | yes, subset of 5.3 | |
| crawl `allowExternalLinks`, `allowSubdomains`, `crawlEntireDomain`; v1 `allowBackwardLinks` | `false` only | Wider scope needs a new admitted-destination rule |
| crawl `ignoreRobotsTxt: true`, `robotsUserAgent` | refused | Robots obedience is on (blueprint "rate/robots compliance") |
| crawl `webhook` | refused | No job egress in W1 |
| crawl `prompt` | 501 | Model, W3 |
| crawl `zeroDataRetention` | no-op | |

**Crawl approval binding (Safe mode).** A crawl, map or batch job's SOFT approval binds the canonical spec digest, the
start origin's **resolved-address set** (sorted, deduplicated, SG-000040 style), the engine, the limits, the principal
and `orcel_session_id`. Every page fetch revalidates the address set; a change stops the job with `TARGET_STALE`.
Admitting many fetches under one approval is an **explicit loosening** of SG-000040's one-shot fetch approval and of
C-04's per-action rule for this new shape only; it is proposed, not decided (FD-UP-5).

### 5.5 Status and response mapping

| Orcel job | Firecrawl `status` | `success` |
| --- | --- | --- |
| `not_started`, `dispatched` | `scraping` | true |
| `completed` + `Succeeded` or `Partial` | `completed` | true (`Partial` adds `warning`) |
| `completed` + `Failed` | `failed` | false, with `error` and `code` |
| `cancelled` | `cancelled` | true |
| `outcome_unknown` | `failed` | false, `code: "OUTCOME_UNKNOWN"` (a `FailureCode`, 4.10; never retried) |

`creditsUsed` is always `0`; `expiresAt` is the job store expiry; `total` and `completed` come from `JobProgress`. The
Document shape follows the SDK `Document` type (`markdown`, `html`, `rawHtml`, `links`, `screenshot`, `metadata`,
`changeTracking`, `warning`), plus `metadata.orcelEngine` naming the engine that ran.

### 5.6 Licence statement for this surface

The Firecrawl-compatible surface is new Apache-2.0 code in `crates/orcel-contracts`, `crates/orcel-web`,
`crates/orcel-jobs`, `crates/orceld` and `apps/orcel-mcp`. It copies no line from AGPL Firecrawl files. Field names and
route shapes are interface facts taken from the MIT SDK types. `tests/firecrawl-compat` may adapt MIT SDK e2e tests
(`apps/js-sdk/firecrawl/src/__tests__/e2e/v2/{scrape,map,crawl,batch}.test.ts`) with the MIT notice kept. The FD-06
ports are unchanged (C-16). Choosing a different approach is FD-UP-1.

## 6. Donor file to destination mapping (Waves 1 and 2)

### 6.1 Methods and notice rules

| Method | Meaning | Notice duty |
| --- | --- | --- |
| `PORT-ALGO` | Re-express the algorithm in Orcel's language and structure; no file copied | Credit in `THIRD_PARTY_NOTICES` and a header comment naming upstream path and SHA; Apache/MIT/BSD notice where the port is close enough to be a derivative |
| `PORT-CODE` | Translate or copy code closely | Upstream licence text and copyright line kept beside the file; NOTICE entries kept (Apache-2.0 section 4) |
| `CONTRACT-TEST` | Upstream client or tests run against Orcel; never shipped | Notice in the test package |
| `ORACLE` | Upstream behaviour used as a test oracle; outputs compared, code not copied | Credit only |
| `DATA` | A data file (list, corpus) copied | Licence text beside the data |
| `PATCH` | Upstream source vendored with an Orcel patch, built in its own workspace | Upstream licence, NOTICE and a `PATCHES.md` listing every change |
| `REFERENCE` | Read for design only | none |

All rows below are at these SHAs: Crawlee `7bec9ad5631f8e529ae067494f6841dba3c12683` (branch `master`), Scrapling
`bb223f2f5fc8f743772751a5ce283ef7851ca6be`, Firecrawl `42f4d669954649ce33466a2a50e8215c7f1f4d1c`, Obscura
`0d9a2f764ffdb097269da048002c593865e83a9e`, agent-browser `53384771fbafc261ba67608ac806dd5aa70b84f0`, Browser Use
`4b5b1b0aa0ab45a1d6a2a31984d37d3e748c0134`. Every path was checked present in the upstream tree at that SHA on 2026-11-16.

### 6.2 Wave 1

| Upstream (repo: path) | Licence | Method | Orcel destination | Packet |
| --- | --- | --- | --- | --- |
| crawlee: `packages/core/src/storages/request-queue.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/queue.rs` | WP1-04 |
| crawlee: `packages/core/src/storages/request-dedup-cache.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/queue.rs` (batch unique key) | WP1-04 |
| crawlee: `packages/core/src/storages/request-list.ts` | Apache-2.0 | REFERENCE | `crates/orcel-jobs/src/queue.rs` (static seed lists for batch) | WP1-04 |
| crawlee: `packages/basic-crawler/src/internals/throttling-request-manager.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/throttle.rs` | WP1-04 |
| crawlee: `packages/basic-crawler/src/internals/basic-crawler.ts` (retry and error handling paths), `request-timeout.ts`, `errors.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/retry.rs` | WP1-04 |
| crawlee: `packages/basic-crawler/src/internals/autoscaling/{autoscaled-pool,snapshotter,system-status,memory-load-signal,weighted-avg}.ts` | Apache-2.0 | PORT-ALGO (simplified) | `crates/orcel-jobs/src/concurrency.rs` | WP1-04 |
| crawlee: `packages/core/src/storages/dataset.ts`, `key-value-store.ts` | Apache-2.0 | REFERENCE | `crates/orcel-jobs/src/store.rs` | WP1-04 |
| crawlee: `test/basic-crawler/throttling-request-manager.test.ts`, `test/core/autoscaling/{autoscaled-pool,snapshotter,system-status,weighted-avg}.test.ts` | Apache-2.0 | ORACLE | `crates/orcel-jobs/tests/` (vectors re-derived, not copied) | WP1-04 |
| scrapling: `scrapling/spiders/checkpoint.py`, `scheduler.py`, `throttle.py` | BSD-3-Clause | REFERENCE | `crates/orcel-jobs/src/{checkpoint,throttle}.rs` | WP1-04 |
| firecrawl: `apps/js-sdk/firecrawl/src/v2/types.ts`, `src/v2/methods/{scrape,map,crawl,batch}.ts` | MIT | REFERENCE (interface facts) | `crates/orcel-web/src/v2.rs` | WP1-05 |
| firecrawl: `apps/python-sdk/firecrawl/v2/types.py`, `firecrawl/v1/client.py` | MIT | REFERENCE (interface facts) | `crates/orcel-web/src/{v2,v1}.rs` | WP1-05 |
| firecrawl: `apps/js-sdk/firecrawl` package at 4.54.0 | MIT | CONTRACT-TEST | `tests/firecrawl-compat/js/` (devDependency) | WP1-09 |
| firecrawl: `apps/js-sdk/firecrawl/src/__tests__/e2e/v2/{scrape,map,crawl,batch}.test.ts` | MIT | CONTRACT-TEST (adapted) | `tests/firecrawl-compat/js/*.test.ts` | WP1-09 |
| firecrawl: `apps/python-sdk` package at 4.57.0 | MIT | CONTRACT-TEST (CI only) | `tests/firecrawl-compat/py/` | WP1-09 |
| firecrawl: `apps/api/openapi.json`, `apps/api/v1-openapi.json`, `apps/api/src/controllers/v2/types.ts` | AGPL-3.0 | REFERENCE only, never vendored | section 5 of this document | none |
| orcel (own): `apps/orcel-browser-worker/src/extract/*` (Apache-2.0 with the browser-use MIT notice) | Apache-2.0 / MIT | PORT-CODE (TS to Rust) | `apps/orcel-doc-parser/src/html.rs` | WP1-08 |
| orcel (own): `crates/orcel-browser-host/src/{crawl,crawl_scope,map_rank,change_tracking,robots}.rs` | Apache-2.0 (+ FD-06 notice where recorded) | reuse in place | called by `orceld` web dispatch through `WorkerCrawl` or `FetchCrawlDriver` | WP1-06 |

Full Control on Windows (WP1-10, WP1-12) and the contracts (WP1-02, WP1-03) import no donor file.

### 6.3 Wave 2

| Upstream (repo: path) | Licence | Method | Orcel destination | Packet |
| --- | --- | --- | --- | --- |
| obscura: whole tree at the pin (526 files), with `vendor/taffy` MIT, `vendor/cosmic-text` MIT OR Apache-2.0, `vendor/wreq-util` Apache-2.0, Noto Color Emoji OFL-1.1 | Apache-2.0 | PATCH (vendored, `cargo vendor` of all crates) | `third_party/obscura/` (separate workspace) | WP2-05 |
| obscura: `crates/obscura-cdp/src/server.rs`, `dispatch.rs`, `lib.rs` | Apache-2.0 | PATCH (pipe transport on inherited handles, Chromium `--remote-debugging-pipe` framing, NUL-delimited JSON; TCP listener removed from the Orcel build) | `third_party/obscura/crates/obscura-cdp` | WP2-05 |
| obscura: `crates/obscura-cli/src/main.rs` | Apache-2.0 | PATCH (pipe mode only; `serve`, `--stealth` and MCP compiled out) | `third_party/obscura/crates/obscura-cli` | WP2-05 |
| obscura: `crates/obscura-net/src/*` (HTTP client, `wreq_client.rs`, `blocklist.rs`) | Apache-2.0 | PATCH (egress removed at compile time: every request answered through the CDP `Fetch` domain by the host broker) or, if not separable, denied by the sandbox (C-13) | `third_party/obscura/crates/obscura-net` | WP2-05 |
| obscura: `crates/obscura/tests/stealth_transport.rs` | Apache-2.0 | excluded (feature off) | none (C-19) | WP2-05 |
| obscura: `crates/obscura-mcp/*` | Apache-2.0 | excluded | none (C-11) | WP2-05 |
| obscura: `crates/obscura-cdp/src/domains/{page,pdf,accessibility,domsnapshot,fetch}.rs`, `crates/obscura-browser/src/{pdf,accessibility}.rs` | Apache-2.0 | REFERENCE (behaviour driven over CDP) | `crates/orcel-browser-host/src/engine/obscura.rs` | WP2-05 |
| obscura: `crates/obscura-cdp/src/domains/lp.rs` (`LP.getMarkdown`) | Apache-2.0 | ORACLE | `crates/orcel-browser-host/tests/extraction_oracle.rs` | WP2-06 |
| obscura: `crates/obscura/tests/*.rs` (12 files) | Apache-2.0 | ORACLE (run upstream in `third_party` CI) | `third_party/obscura` CI job | WP2-05 |
| agent-browser: `cli/src/native/snapshot.rs`, `element.rs` | Apache-2.0 | PORT-ALGO | `crates/orcel-browser-host/src/observation.rs`, `apps/orcel-browser-worker/src/snapshot.ts` | WP2-07 |
| agent-browser: `cli/src/native/actions.rs`, `interaction.rs`, `pointer.rs` | Apache-2.0 | PORT-ALGO | `apps/orcel-browser-worker/src/actions/` (hover, drag, scroll, double-click) | WP2-07 |
| agent-browser: `cli/src/native/screenshot.rs`, `diff.rs` | Apache-2.0 | PORT-ALGO | `crates/orcel-browser-host/src/capture.rs` (page screenshot, PDF, visual diff) | WP2-04 |
| agent-browser: `cli/src/native/tab_binding.rs`, `browser.rs` | Apache-2.0 | PORT-ALGO | `crates/orcel-browser-host/src/tabs.rs` (multi-tab, frames) | WP2-07 |
| agent-browser: `cli/src/native/cdp/{chrome,obscura,discovery}.rs`, `cli/src/connection.rs` | Apache-2.0 | REFERENCE | `crates/orcel-browser-host/src/engine/mod.rs` (engine selection) | WP2-04 |
| agent-browser: `cli/src/native/network.rs` | Apache-2.0 | REFERENCE | `crates/orcel-browser-host/src/navigation.rs` | WP2-07 |
| agent-browser: `cli/src/native/parity_tests.rs`, `e2e_tests.rs`, `evals/cases/*` | Apache-2.0 | PORT-CODE (tests) | `tests/browser-corpus/` | WP2-06 |
| agent-browser: `cli/src/native/a11y/axe.min.js` | MPL-2.0 | excluded in W2 | none (an audit tool needs its own decision) | none |
| browser-use: `browser_use/tools.py`, `browser_use/ax.py` | MIT | REFERENCE | action naming in `apps/orcel-browser-worker/src/actions/` | WP2-07 |
| crawlee: `packages/utils/src/internals/extract-microdata.ts`, `open-graph-parser.ts`, `social.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-browser-host/src/extraction.rs` (metadata) | WP2-08 |
| scrapling: `scrapling/engines/toolbelt/ad_domains.py` | BSD-3-Clause | DATA | `crates/orcel-browser-host/data/ad_domains.txt` + licence | WP2-08 |
| scrapling: `scrapling/parser.py`, `scrapling/core/storage.py`, `scrapling/core/translator.py` | BSD-3-Clause | PORT-ALGO (optional) | `crates/orcel-browser-host/src/adaptive.rs` | WP2-08 |

### 6.4 Not imported in Waves 1 and 2

Firecrawl AGPL trees (C-15); Firecrawl cloud-only engines and controllers; Obscura stealth and MCP; Scrapling
`engines/static.py`, `fetchers/stealth_chrome.py`, `engines/_browsers/_stealth.py`, `engines/toolbelt/fingerprints.py`;
Crawlee `session-pool/fingerprint.ts`, `packages/impit-client`, `packages/got-scraping-client`; Browser Use agent loop,
LLM layer, cloud and telemetry; remote-agent-browser (no licence file; cloud dependency); Mika sandbox (copyleft
binaries); Fleet `ee/`; anything from UU Remote or its unofficial bridges.

## 7. Dependency versions

### 7.1 Already pinned in the repository (unchanged by this plan)

| Item | Version | Where |
| --- | --- | --- |
| Rust toolchain | 1.97.1 | `rust-toolchain.toml`, `apps/orcel-contain/rust-toolchain.toml` |
| Declared MSRV, main workspace | 1.82 | root `Cargo.toml` `rust-version` |
| Declared MSRV, doc-parser workspace | 1.88 | `apps/orcel-doc-parser/Cargo.toml` `rust-version` |
| Node (CI) | 24.19.0 | `.github/workflows/ci.yml` |
| Node (worker floor) | >= 22.15.0 | `apps/orcel-browser-worker/package.json` |
| playwright-core | 1.63.0 | `apps/orcel-browser-worker` |
| @modelcontextprotocol/server | 2.3.1 | `apps/orcel-mcp` |
| zod | 4.6.7 | `apps/orcel-mcp` |
| typescript / @types/node | 5.9.3 / 24.10.1 | apps |
| serde_json | 1.0.151 (lock) | workspace |
| sha2 / fs4 | 0.10 / 1.1 | workspace |
| regex / similar | 1.13.1 / 2.7.0 (lock) | `orcel-browser-host` |
| windows-sys / windows | 0.52 / 0.58 | kernel crates |
| tokio | 1.47 (orcel-contain workspace only) | `apps/orcel-contain` |
| lopdf / pdf-inspector / zip / roxmltree | =0.45.0 / =1.21.0 / =8.6.0 / =0.20.0 | `apps/orcel-doc-parser` |
| cargo-deny | 0.20.2 | CI |

### 7.2 New in Wave 1

| Item | Version | Licence | Scope | Why |
| --- | --- | --- | --- | --- |
| html5ever | =0.40.1 (MSRV 1.85, within the doc-parser workspace's declared 1.88) | MIT OR Apache-2.0 | `apps/orcel-doc-parser` workspace only | HTML parsing for the fetch engine, with an Orcel-owned minimal tree sink (no `markup5ever_rcdom`) |
| schemars | =1.2.3 (MSRV 1.74) | MIT | `orcel-contracts` **dev-dependency** only | JSON Schema generation and drift test (4.0) |
| @mendable/firecrawl-js | 4.54.0 (exact, matching the pin) | MIT | `tests/firecrawl-compat` devDependency | Contract client |
| firecrawl-py | 4.57.0 (exact, matching the pin) | MIT | CI-only virtualenv, hashes in a lock file | Contract client (C-14) |
| Python (CI only) | 3.12.x from `actions/setup-python` | PSF | CI | Runs the Python contract leg |

No new **runtime** dependency enters any `crates/*` unit in Wave 1: `orcel-jobs` and `orcel-web` use only `serde`,
`serde_json`, `sha2` and `fs4`; the Windows fetch engine reuses the existing WinHTTP transport. Versions were read with
`cargo info` on 2026-11-16; each packet re-checks that a version is at least 14 days old and records its checksum in the
lock file.

### 7.3 Planned for Wave 2 (re-verified when the packet starts)

| Item | Version | Notes |
| --- | --- | --- |
| rustls | latest 0.23.x patch at packet start, exact pin (`cargo info` on 2026-11-16 reported a `0.24.0-dev` prerelease as newest, which MUST NOT be used) | WP2-12 macOS/Linux transport; MIT OR Apache-2.0 OR ISC |
| rustls-platform-verifier | =0.7.1 or the newest at packet start (MSRV 1.85) | WP2-12; OS certificate validation (Security.framework, system store) |
| Obscura | vendored source at `0d9a2f764ffdb097269da048002c593865e83a9e` plus Orcel patches; trial may compare against release `v0.2.7` (tag commit `0ecc41770da5c5300227dd83a15bfa1e5100d5d4`, published 2026-11-13) | Built with `--locked --offline` from vendored crates; V8 prebuilt archives pre-fetched and verified by SHA-256 (WP2-05) |
| Chromium | Chrome and Edge stable as qualified by the browser host at the packet's base (Edge 157 qualified in #771) | Installed engine, not bundled |
| OpenAPI | 3.1.0 document generated with zod 4's built-in `z.toJSONSchema` | No new dependency |
| @orcel/sdk | no runtime dependencies; global `fetch` (Node >= 22.15) | Generated client |

## 8. Packets

### 8.1 Wave 1 summary

| Packet | Title | Prerequisites | Grain (draft) | Native runner needed |
| --- | --- | --- | --- | --- |
| WP1-00 | Governance: activate the Wave 1 grains, correct the donor registry | FD-UP-4 | SG-000131 activation | none |
| WP1-01 | Licence and dependency-direction gates in CI | WP1-00 | SG-000131 | all three |
| WP1-02 | Contracts v1 in `orcel-contracts` (inert) | WP1-00 | SG-000131 | all three |
| WP1-03 | Audit hash chain, Event Log anchor and `orcel audit verify` | WP1-02 | SG-000131 | all three; Windows for the anchor |
| WP1-04 | `orcel-jobs` embedded queue | WP1-02, FD-UP-11 (bounds) | SG-000102 | all three |
| WP1-05 | `orcel-web` Firecrawl-compatible schemas and translation (pure) | WP1-02, FD-UP-1 | SG-000101 | all three |
| WP1-06 | `orceld` web and job dispatch, `FetchCrawlDriver` | WP1-03, WP1-04, WP1-05, WP1-08, FD-UP-1, FD-UP-5, FD-UP-7 | SG-000101 (scrape), SG-000102 (jobs) | Windows |
| WP1-07 | MCP tools, loopback REST routes, REST tokens, SG-000040/SG-000064 guard amendment | WP1-06, FD-UP-1, FD-UP-5, FD-UP-7 | SG-000101, SG-000102 | all three |
| WP1-08 | Fetch engine: HTML to Markdown in the contained parser (Windows transport) | WP1-05, FD-UP-1, FD-UP-7 | SG-000101 | all three (parser), Windows (engine) |
| WP1-09 | Firecrawl contract harness (JS and Python SDKs) | WP1-07, WP1-08, FD-UP-1, FD-UP-5 | SG-000101, SG-000102 | Windows |
| WP1-10 | Full Control dispatcher on Windows | WP1-02, WP1-03, WP1-12, FD-UP-9 | SG-000132 | Windows |
| WP1-12 | Protected Full Control indicator and out-of-band stop | WP1-02, WP1-03 | SG-000132 | Windows |
| WP1-11 | Wave 1 journeys J-1, J-2, J-3 and readiness update | all of the above | closeouts | Windows, plus founder-present runs |

### 8.2 Wave 1 packets in detail

Every packet: exact-head CI green on the existing `ci.yml` legs (`ubuntu-latest`, `windows-latest`, `macos-latest`),
Review Gates (`review-gates.yml`: Jev semantic review, Alibaba OpenCodeReview delegation) green, zero unresolved
threads, and a fresh-context security judge where marked. d1-local is advisory only.

#### WP1-00 Governance

- **Scope:** move the approved draft JSONs from `prep/unified-grains/` into `.specgrain/specs/` with `state: "GRAIN"`,
  record the founder go-ahead in `CURRENT.md`, update the open-grain pins. Correct `DONOR_REGISTRY.md` and
  `donor_registry.json` for Firecrawl (`REFERENCE_ONLY_SO_FAR` is stale, inventory section 3.7).
- **Definition of done:** no code, dependency, tool or authority change; the commands below pass.
- **Tests:** `node scripts/check-current-identity.mjs`; the `ci.yml` Governance job (which validates
  `.specgrain/canonical-evidence.json` and the spec set); `node -e` JSON parse of every changed JSON file.
- **CI:** `ubuntu-latest` (Governance job) plus the standard three legs.

#### WP1-01 Licence and dependency-direction gates

- **Scope:** a root `deny.toml` for the main workspace (licences, bans, sources) mirroring the four per-app files;
  allowlist `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `0BSD`; deny `AGPL-*`,
  `GPL-*`, `LGPL-*`, `SSPL-*`, `BUSL-*` and unknown licences in every `crates/*` unit; `MPL-2.0` allowed only by named
  exception. `scripts/check-npm-licenses.mjs` reads every `package-lock.json` under `apps/`, `packages/` and `tests/` and
  applies the same allowlist (test-only packages may add `PSF-2.0`). A `cargo metadata` test enforcing section 3.2. A
  text scan over `crates/`, `apps/`, `packages/` and `tests/` refusing `GNU AFFERO` and `SPDX-License-Identifier: AGPL`
  except in the files listed in `docs/orcel/notices/fd06-files.txt` (created here from the FD-06 record) and the notice
  files themselves.
- **Definition of done:** the gates run on every PR; current `main` passes; a fixture crate with an AGPL dependency and a
  fixture file with an AGPL header outside the allowlist both fail.
- **Tests:** `cargo deny check licenses bans sources` (root); `node --test scripts/check-npm-licenses.test.mjs`;
  `node --test scripts/check-agpl-markers.test.mjs`; `cargo test -p orceld --test dependency_direction`.
- **CI:** all three OS legs (licences are OS-independent, but `cfg` dependencies differ).

#### WP1-02 Contracts v1

- **Scope:** section 4 types in `orcel-contracts`; move `AuthorityMode`, `ExecutorClass`, `ExecutionState` with
  re-exports; `canonical_json` (with the SG-000093/SG-000018/SG-000040 exemptions of 4.0); golden fixtures; `schemars`
  dev-dependency and schema drift test; the new `FailureCode` variants and the HTTP mapping table as code
  (`FailureCode::http_status`), with a test that every variant is mapped.
- **Definition of done:** every type round-trips its golden fixture; unknown fields refused on inbound authority-bearing
  types; frozen spellings pinned; `orcel-policy` tests unchanged and green; no behaviour change.
- **Tests:** `cargo test -p orcel-contracts`; `cargo test -p orcel-policy` (unchanged).
- **CI:** all three.

#### WP1-03 Audit hash chain

- **Scope:** section 4.8 in `orcel-audit`; `orceld` records `request`, `decision`, `approval`, `dispatch`, `state`, `lease`,
  `emergency_stop` and `anchor` events; write-before-dispatch with refusal on failure; the Windows Event Log anchor
  written per user without source registration (section 4.8); `orcel audit verify` checking every Orcel anchor still in
  the Application log. If the anchor cannot be written, Full Control is refused (C-29); there is no indicator-only
  fallback.
- **Definition of done:** every dispatch in the existing test suites leaves a verifiable chain; editing, deleting or
  reordering one line is detected at that line; tail truncation is detected against the newest anchor; a forged
  conflicting anchor record is reported as a break; a simulated audit write failure refuses the dispatch; a simulated
  anchor write failure refuses Full Control; no raw SID, token, secret, argv, URL or page content in any event (asserted
  by a redaction scan over the test logs).
- **Tests:** `cargo test -p orcel-audit chain_`; `cargo test -p orceld audit_chain_`; `cargo test -p orceld audit_anchor_`
  (Windows: write, read-back, conflicting record, truncation); `cargo test -p orceld --test audit_anchor_standard_user`
  (Windows: the CI step creates a local standard account with `net user`, runs the test under it with a
  `CreateProcessWithLogonW` helper, asserts the write and read-back succeed and `ClearEventLogW` is refused, then deletes
  the account); the same test run once on the founder's PC as a standard user; redaction scan script
  `node scripts/check-audit-redaction.mjs`.
- **CI:** all three; Windows for the Event Log anchor. **Security judge:** yes.

#### WP1-04 orcel-jobs

- **Scope:** section 4.11 modules; state machine of 4.7 including restart handling; bounds; result store with global cap
  and expiry; job ownership.
- **Definition of done:** on restart, `not_started` jobs become `cancelled` and `dispatched` jobs `outcome_unknown`, none
  re-run; per-origin delay honoured within 10 ms of the configured value on all OSes; retries only for read-only batch
  units; per-job and global store caps enforced; no thread spins when idle.
- **Tests:** `cargo test -p orcel-jobs` (unit tests per module; state-machine property tests; throttle and backoff
  vectors re-derived from the Crawlee tests in 6.2; crash test killing the process between unit start and finish).
- **CI:** all three.

#### WP1-05 orcel-web

- **Scope:** v2 and v1 request types, refusal of every unsupported field by name, translation to `RequestEnvelope` and
  `WebCrawlRequest` with `Ids`, Document shaping, status mapping of 5.5.
- **Definition of done:** every row of 5.3 and 5.4 has a test; unknown top-level fields refused; v1 field names
  (`maxDepth`, `allowBackwardLinks`, `ignoreSitemap`, `sitemapOnly`, string `formats`, `parsePDF`) translate to the same
  output as their v2 equivalents; `orcel-web` depends on `orcel-contracts` only (dependency test).
- **Tests:** `cargo test -p orcel-web` with request fixtures written from the MIT SDK types.
- **CI:** all three.

#### WP1-06 orceld web and job dispatch

- **Scope:** pairs `web/scrape`, `web/map`, `web/crawl_start`, `web/batch_scrape_start`, `job/status`, `job/cancel`,
  `job/errors`, `job/list`. `WebCrawlRequest` to `CrawlSpec` translation. `FetchCrawlDriver` (4.11). Engines: `fetch` on
  Windows (existing SG-000040 WinHTTP transport, DNS pin and exact-peer check); `chromium` where the browser host can
  launch (Windows `live-browser-dev` and `live-browser-test` builds). macOS and Linux report every `web/*` entry
  `unsupported`. Approvals per 5.4 (one SOFT per scrape; one SOFT per job subject to FD-UP-5), binding the resolved-address
  set and `orcel_session_id`; `TARGET_STALE` on address drift; existing `browser_*` shapes and their approvals untouched.
- **Definition of done:** a refused or unsupported option never dispatches; a job approval cannot be replayed for a
  different spec, address set or session; cancel and emergency stop reach running units; the engine that ran is in every
  result and audit event; release builds report `chromium` as `unavailable` with the existing typed reason.
- **Tests:** `cargo test -p orceld web_` (policy, approvals, digest binding, address drift, cancel, unsupported, restart);
  `cargo test -p orceld fetch_crawl_` with deterministic resolver and transport adapters (the SG-000040 test pattern);
  fixture-origin tests through the existing test-only fixture pinning (SG-000108, `worker_host.rs` fixture lifetime) for
  the chromium engine.
- **CI:** Windows native required; Linux and macOS prove `unsupported`. **Security judge:** yes.

#### WP1-07 MCP tools, loopback REST and the guard amendment

- **Scope:** `tool_contract.ts` entries for the eight tools (all `local_only`, effect `network`, approval `SOFT`,
  `openWorldHint: true`); loopback REST routes for the W1 rows of 5.2 on the existing loopback server, reusing its bind,
  `Host`, `Origin` and body-bound checks; REST tokens, principals, ownership and per-principal bounds of 4.12; v1 aliases.
  **Guard amendment:** SG-000040's note says no MCP network tool is registered, and SG-000064 later admitted exactly
  `web_fetch` (and `web_search` followed). The Node guard tests that pin the network tool set are amended to admit
  exactly these eight names, recorded in the SG-000101 and SG-000102 specs as an explicit authority delta.
- **Definition of done:** the catalog, discovery, OAuth scope tables and runtime agree (extend `tool-contract.test.ts`,
  `surface.test.ts` and the network guard tests); no route outside the W1 rows answers anything but 404 or 501; the MCP
  token is refused on REST routes and a REST token on `/mcp`; the REST front holds no state beyond the token table and
  session bounds.
- **Tests:** `npm test` in `apps/orcel-mcp` (`loopback-http.test.ts` extended for routes, tokens, rotation, ownership,
  host and origin refusals, body bounds; guard tests); `cargo test -p orcel-lifecycle rest_client_`.
- **CI:** all three.

#### WP1-08 Fetch engine

- **Scope:** `apps/orcel-doc-parser` gains format `html` (sniffed, refused if not HTML); Rust port of Orcel's worker
  extraction with an Orcel tree sink on `html5ever`; `orceld` composes the Windows SG-000040 transport then the contained
  parser. No transport is added on macOS or Linux (WP2-12).
- **Definition of done:** Markdown output matches the worker's extraction on the shared fixtures within a documented
  normalisation; the parser runs with no network and no process creation under orcel-contain on all OSes; malformed and
  hostile HTML bounded in time and memory.
- **Tests:** `cargo test` in `apps/orcel-doc-parser` (`html_tests.rs`, fixtures shared with
  `apps/orcel-browser-worker/src/extract/extract.test.ts`); a 60-second fuzz run in CI.
- **CI:** all three (Document parser job); Windows for the engine composition test in `orceld`.

#### WP1-09 Firecrawl contract harness

- **Scope:** `tests/firecrawl-compat` runs the JS SDK 4.54.0 and the Python SDK 4.57.0 against a `live-browser-test`
  build of Orcel on the loopback with the test-only fixture origin (the existing TLS fixture of `worker_host.rs`, serving a
  pinned 60-page static site checked into `tests/firecrawl-compat/fixture-site/`); one test per W1 matrix row and per W1
  option row; parity report `tests/firecrawl-compat/report.json`.
- **Definition of done:** every W1 row passes on Windows with both engines; the SDKs surface Orcel refusals as their typed
  errors; the report is attached to the CI run; on Linux and macOS the harness asserts `UNSUPPORTED` for every web route.
- **Tests:** `npm test` in `tests/firecrawl-compat/js`; `python -I -m pytest tests/firecrawl-compat/py` in a hashed-lock
  virtualenv.
- **CI:** `windows-latest` (both SDK legs); `ubuntu-latest` and `macos-latest` (unsupported assertions).

#### WP1-10 Full Control dispatcher on Windows

- **Scope:** `crates/orceld/src/full_control_dispatch.rs`, the only path that dispatches an executor under a lease:
  indicator heartbeat check (C-28) -> epoch lock (C-30) -> load lease -> re-read the native identity -> check every
  binding (C-02) -> check `executor_enabled_now` -> require the shape's own approval (C-04) -> write and flush the dispatch
  audit event (C-05) -> check the stop directory (section 4.13) -> start or reuse the executor child under the section
  4.14 boundary, assign it to its Job Object, duplicate that handle to the indicator -> send the action -> release the
  lock. Lease expiry kills running executors; every job unit re-checks the lease. The `Admin` executor class is refused.
  **Process boundary for the existing SG-000095 path:** `orceld/src/uia.rs` -> `ComputerHostAdapter` ->
  `HostSession::spawn` -> the Go native host `apps/orcel-computer-host`. The native host is the DesktopInput executor
  child: while any lease is active it runs under token profile D (no user SID), in a Job Object with kill-on-close, one
  active process and every UI limit except `HANDLES`, with the handle duplicated to the indicator (section 4.14);
  process-starting executors use profile S on a separate desktop with every UI limit; when the lease ends, `orceld`
  terminates that host instance and Safe-mode observation restarts it with today's launch. The executor-token and ACL
  mechanism of section 4.14 is implemented here, subject to FD-UP-9. The STRONG grant prompt
  (`crates/orcel-lifecycle/src/full_control.rs`, `ApprovalPrompt::new_strong`) gains the C-27 residual text (C-25).
  `orcel-policy` gains
  `pub fn mode_selectable_on(proof: &LocalGrantProof, mode: AuthorityMode, os: OsFamily) -> Result<(), PolicyError>`,
  returning `LEASE_UNSUPPORTED_PLATFORM` for `FullUser`/`FullAdmin` when `os != OsFamily::Windows`; the existing
  `mode_selectable(proof, mode)` calls it with the compile-time OS, so its Windows behaviour is unchanged.
- **Definition of done:** no lease-gated executor is reachable except through the dispatcher (a call-site test); with no
  lease every Safe path is unchanged (golden pairs for `process_spawn`, the registry, the browser shapes and Safe-mode
  observation through the native host); every Full Control dispatch has an audit event with lease id, digest and epoch,
  written before start; a stop issued while a dispatch is between check and start waits for the lock and then kills the
  started process; the native host under a lease runs with the executor token in its Job Object; an executor child and
  its grandchild are denied every protected file and process (section 4.14 tests); dispatch is refused with
  `INDICATOR_UNAVAILABLE` when the indicator is absent or not visible; the grant prompt shows the residual text.
- **Tests:** `cargo test -p orceld full_control_dispatch_` (race test with a stop injected between check and start;
  expiry kill; per-unit re-check; admin refused; indicator absent or invisible; stop directory honoured);
  `cargo test -p orcel-policy` (SID and logon mismatch, epoch drift, policy drift, expiry, `mode_selectable_on`);
  `cargo test -p orceld executor_state_isolation_` (Windows, section 4.14 list);
  `cargo test -p orcel-provider-uia native_host_executor_launch_` (Windows: profile D restricting SIDs without the user
  SID, Job Object limits including every UI limit except `HANDLES`, handle duplicated with only
  `JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY`); `cargo test -p orceld executor_profile_s_` (Windows: no user or logon
  SID, separate window station and desktop, every UI limit, workspace grants to the executor SID);
  `cargo test -p orceld executor_cross_process_` (Windows: from profiles D and S, opening explorer and a second same-user
  process with `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD` and `PROCESS_DUP_HANDLE` is denied,
  and the measured logon-SID rights are recorded; `orcel-mcp` and `orcel-agent` unreadable from profile D);
  `cargo test -p orceld executor_indirect_spawn_` (Windows, profile S: `schtasks /create` and `ITaskService` with an
  interactive logon type, WMI `Win32_Process.Create`, BITS `SetNotifyCmdLine`, DCOM `ShellWindows` and
  `MMC20.Application`, each refused or yielding a restricted-token process); the existing Go native qualification suites run under profile D
  with each failing capability recorded; `node scripts/check-native-host-calls.mjs` (static guard of section 4.14 over
  `apps/orcel-computer-host`); `cargo test -p orcel-lifecycle grant_prompt_residual_text`; Windows native CI issuing a
  lease from real host values (existing pattern).
- **CI:** Windows native required; Linux and macOS prove `LEASE_UNSUPPORTED_PLATFORM`. **Security judge:** yes.

#### WP1-12 Protected Full Control indicator and out-of-band stop

- **Scope:** `apps/orcel-indicator` (Rust, Windows in Wave 1) implementing section 4.13 exactly: launched only by
  `orceld` on an inherited anonymous pipe; the always-on-top window "Orcel Full Control" shown while any lease is active
  (`orceld` checks the lease store every 1 s), displaying mode, expiry, the latest anchor `(seq, digest)` (informational)
  and the Stop button first; the four mitigation policies enabled before the window exists; Stop acting on hardware
  input only (`GetCurrentInputMessageSource`); close, minimise and hide requests treated as Stop; heartbeats only while
  all five visibility checks pass (including the input-desktop check); Job Object handles received from `orceld` with
  terminate and query rights only; out-of-band stop that terminates held Job Objects and writes a revoke request, never
  holding the authority key; session lock as a Stop in both the indicator and `orceld`; the hotkey shown as ready only
  when `RegisterHotKey` succeeded. `orceld` side: launch, peer checks, frames, the 2 s heartbeat rule, handle
  duplication, the stop directory, the session-lock stop.
  The indicator's title and class are added to `PROTECTED_WINDOW_MARKERS` and the native-host mirror (and the grant
  prompt's and emergency-stop surface's markers are confirmed present), so observation, capture and desktop input
  refuse them.
- **Definition of done:** the indicator appears within 2 s of a grant and disappears on revoke or expiry; killing,
  minimising, cloaking or moving the indicator off screen makes the next dispatch fail `INDICATOR_UNAVAILABLE`; Stop
  works with `orceld` running (StopAck within 1 s) and with `orceld` suspended (executors dead within 1 s, revoke request
  written, honoured by `orceld` before its next dispatch after resuming); a forged frame or a wrong parent is refused;
  with the hotkey already taken by another process, no "hotkey ready" text is shown; desktop input and observation
  targeting the indicator, the grant prompt and the stop surface are refused; an injected click (`SendInput`) on Stop
  is ignored while a hardware-equivalent test path is honoured; a `WM_CLOSE` or `SC_MINIMIZE` sent by another process
  stops Full Control; a hook DLL cannot be loaded into the indicator; switching to another desktop stops heartbeats;
  `LockWorkStation` (standing in for Win+L in CI) stops Full Control within 1 s with `orceld` running and suspended.
- **Tests:** `cargo test -p orcel-indicator` (frames, visibility gating including the input desktop, hotkey failure,
  revoke-request write, mitigation policies on at startup, injected-input filter, close and minimise as Stop);
  `cargo test -p orceld indicator_` (launch pins, peer checks, heartbeat expiry, handle rights, stop directory, session
  lock); `cargo test -p orcel-provider-uia protected_markers_`; Windows native tests: suspend `orceld`
  (`NtSuspendProcess`) and measure stop-to-death; minimise, cloak and send `WM_CLOSE` from a test process; inject a click
  with `SendInput` and assert no Stop; attempt `SetWindowsHookExW` with a test DLL into the indicator's thread and assert
  the DLL is not loaded; call `LockWorkStation` and measure stop-to-death; set `DisableLockWorkstation` = 1 under HKCU
  for the test user and assert the warning, `LockStatus { available: false }`, the capability report entry and that
  lock-to-stop is never shown as ready. The founder-present J-3 run uses real Win+L.
- **CI:** Windows native required. **Security judge:** yes.

#### WP1-11 Wave 1 journeys

- **Scope:** run J-1, J-2 and J-3 (section 10); update `README.md`'s capability table and `RELEASE_READINESS.md` with
  what is qualified and on which builds; grain closeouts.
- **Definition of done:** the gates of 10.2 that apply to Wave 1 pass; founder-present runs recorded where a real
  approval through a real client is required, otherwise stated as pending (F4 slice 4 precedent).
- **Tests:** `npm test` in `tests/firecrawl-compat/js` (J-1 scripted leg); `cargo test -p orceld --test j2_cancel_probe`;
  `cargo test -p orceld --test j3_desktop_input_stop`; `powershell -File scripts/ci-machine-sampler.ps1` for G-7;
  `orcel audit verify` on each run's log.
- **CI:** `windows-latest`; founder-present runs on the founder's Windows 11 PC.

### 8.3 Wave 2 packets

| Packet | Title | Prerequisites | Definition of done (summary) | Tests | CI |
| --- | --- | --- | --- | --- | --- |
| WP2-01 | Per-OS identity binding (macOS, Linux) and `orcel-full-control-lease/2` | WP1-10 | Leases on macOS and Linux bind uid plus audit session or logind session; v1 leases invalidated, not converted | identity readers on real runners; mismatch denial | macOS, Linux native |
| WP2-02 | `orcel-sidecar` host and sandbox profiles | WP1-02 | Section 4.9 implemented; launch from hashed handle; handle-list allowlist; capability-less AppContainer / Seatbelt / seccomp+Landlock+cgroup; listener scan where needed; kill paths | handshake, heartbeat loss, cancel, host death, socket refusal per OS | all three native |
| WP2-03 | macOS and Linux qualification of the core and Full Control executors, indicator on both | WP2-01, WP2-02, SG-000115 | Executors under lease on macOS 15 arm64 and Ubuntu 24.04 / Fedora 41 with C-25..C-30 | journey J-4 on each OS | macOS, Linux native; founder-present desktop runs |
| WP2-04 | Browser engine abstraction, capture contract, Chromium default | WP1-06 | `engine` trait; screenshot, PDF, multi-tab contract; engine reported per task; fallback reported, never silent | engine contract tests on Chromium | Windows; macOS and Linux after SG-000115 |
| WP2-05 | Obscura patched build and adapter | WP2-02, WP2-04, FD-UP-6 | Vendored sources; `cargo build --locked --offline`; V8 archives pre-fetched by SHA-256; build provenance attested; pipe CDP only; `obscura-net` egress removed or sandbox-denied; zero sockets; stealth and MCP compiled out | upstream tests in `third_party`; socket scan; egress-denied test | all three |
| WP2-06 | Measured Obscura corpus trial | WP2-05, WP2-07 | Corpus result per engine per site; Obscura marked qualified per capability only where it passes; Chromium fallback reported, never silent | `tests/browser-corpus` both engines | all three |
| WP2-07 | agent-browser parity port and corpus | WP2-04 | Snapshot refs identical across engines; hover, drag, scroll, double-click, tabs, frames | ported parity and e2e tests | Windows first |
| WP2-08 | Extraction metadata, ad blocking, adaptive selectors | WP2-04 | Microdata, OpenGraph, social; `blockAds`; optional adaptive selectors | extraction fixtures | all three |
| WP2-09 | REST/OpenAPI generated from the MCP catalog | WP1-07 | `/api/v1/*` from `tool_contract.ts`; OpenAPI 3.1.0 checked in; drift test | schema drift; route tests | all three |
| WP2-10 | TypeScript SDK `@orcel/sdk` | WP2-09 | Generated client; README examples run in CI against a test build; never defaults to a remote URL | SDK tests | all three |
| WP2-11 | Firecrawl W2 rows (screenshot, actions, parse, async scrape, watcher, queue status, cache) | WP2-04, WP2-07 | Rows 11 to 14 of 5.2 pass the harness; watcher checks Host, Origin and REST token | harness | all three |
| WP2-12 | macOS and Linux HTTPS transport for SG-000040 (new network authority) | WP1-08, FD-UP-12 | `rustls` + `rustls-platform-verifier` over a `TcpStream` connected to one address from the validated set; hostname kept for SNI and certificate identity; exact-peer check; same redirect, body and address rules as Windows; SG-000040 note amended for non-Windows | deterministic adapters; live probe to `https://example.com/` as on Windows; peer-mismatch tests | macOS, Linux native; security judge |

### 8.4 Wave 3 packets

| Packet | Title | Key constraint |
| --- | --- | --- |
| WP3-01 | Android ADB provider (port of phone-harness `src/phone_harness/android.py`, `transport.py`) in `orcel-provider-mobile` | adb is user-installed and pinned by hash; no phone-harness cloud or telemetry; MIT notice kept |
| WP3-02 | iPhone Mirroring on macOS (phone-harness `mirror.py`, `ios.py`, `ocr.py` behaviour, in `apps/orcel-native-host`) | macOS 15+ and iOS 18+; Accessibility and Screen Recording consent; no lock or Face ID bypass |
| WP3-03 | Remote screen view and control on the SG-000057 relay, WebRTC later | Requires SG-000105 Remote Full Control; no anonymous control; presence indicator and stop |
| WP3-04 | Fleet reporting adapter (`orcel-fleet-report`) from Fleet MIT `server/` and `orbit/` concepts | Read-only inventory; nothing from `ee/`; no stealth enrollment |
| WP3-05 | Mika as a paired remote device | Reaches Orcel through the relay and the authority; Mika's own MCP and sandbox not exposed |
| WP3-06 | Python SDK `packages/orcel-sdk-py` | Client library generated from the OpenAPI document; not shipped core |
| WP3-07 | Model-backed web rows (extract, json and summary formats, params preview) | BYOK or local model; schema-validated output; no hosted Firecrawl |

## 9. Platform floors

| Platform | Floor | Qualified on | CI runner | Notes |
| --- | --- | --- | --- | --- |
| Windows | Windows 10 version 1809 (build 17763) or later, or Windows 11, x64 (`README.md`) | Windows 11 on the founder's PC; `windows-latest` (Server 2025) | `windows-latest` | Lease identity (`TokenUser`, `TokenStatistics`), AppContainer and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` exist on the floor; Windows arm64 not claimed. Wave 1 web and Full Control are Windows-only |
| macOS | macOS 15.0 Sequoia, Apple Silicon (arm64) only (`MACOS_M0_READINESS.md` section 4) | macOS 15 and macOS 26 | `macos-latest` (arm64); a `macos-15` leg is added when a packet changes OS-specific code | Intel deferred; unsigned development builds only until FD-05; TCC grants are lost per rebuild |
| Linux | Ubuntu 24.04 LTS and Fedora 41, x86_64 (`ROADMAP.md` X5) | Same | `ubuntu-latest` plus Fedora 41 container for install tests | Kernel with Landlock ABI 3 or later (6.2+; both floors ship newer); cgroup v2; arm64 qualified later |
| Linux desktop | GNOME 46+ and KDE Plasma 6, Wayland and X11 sessions | Interactive runs (XP-10) | none hosted | Wayland input and capture go through portals and need per-session consent; X11 is the fallback |
| Android (W3) | Any device exposing adb over USB or a user-paired wireless debugging session | Founder's device | none hosted | Host side runs on all three desktop OSes |
| iPhone (W3) | iOS 18+ mirrored to macOS 15+ | Founder's devices | none hosted | No Windows or Linux iPhone claim |

## 10. Acceptance journeys and release gates

### 10.1 User journeys

| Journey | Wave | What a person does | Pass criteria |
| --- | --- | --- | --- |
| J-1 | W1 | Points the Firecrawl JS SDK, with an explicit `apiUrl`, at their local Orcel and scrapes, maps and crawls. Scripted leg: the pinned 60-page fixture site (`tests/firecrawl-compat/fixture-site/`) on the test-only fixture origin. Founder-present leg: `https://docs.python.org/3/library/` in a development build | Results returned through visible approvals; engine named; robots and the 250 ms politeness delay honoured (fixture server log); at most 50 pages read; `orcel audit verify` clean |
| J-2 | W1 | Asks an MCP client to crawl the fixture site, then cancels mid-way | Cancel probe (below) passes; partial results readable by the owner only |
| J-3 | W1 | Grants Full User on Windows with STRONG presence (the prompt states the C-27 residual), has an agent perform desktop input (SG-000095) in Notepad through the native host running as the executor child (token profile D), then presses Stop on the indicator; repeated with Win+L as the stop | Every dispatch audited with lease id, digest and epoch and anchored in the Event Log; Stop ends the running action within 1 s, including with `orceld` suspended (revoke request honoured on resume); Win+L stops it the same way; the next call fails `LEASE_INVALID`; input aimed at the indicator or grant prompt is refused; injected clicks on Stop are ignored and an injected `WM_CLOSE` stops; minimising the indicator blocks dispatch; any native-host capability that fails under profile D is reported `unsupported`, not hidden |
| J-3b | W1 if FD-UP-4 activates them, else W2 | J-3 with a shell build (SG-000096) and file edits (SG-000097) | Prerequisites: SG-000096 T02-T04 qualified (today `shell_session.rs` denies `ShellProcess` until T02-T04) and SG-000097 activated and qualified; same criteria plus C-26 isolation |
| J-4 | W2 | J-3 and J-3b on macOS 15 arm64 and Ubuntu 24.04 GNOME | Same criteria; OS consent prompts appear as the OS shows them |
| J-5 | W2 | Runs one browser task on Obscura and the same on Chromium | Same result or an explicit difference report; engine named; any fallback reported, never silent |
| J-6 | W2 | Calls the same intent through App, MCP and REST/SDK | Identical policy decisions and audit kinds; missing privilege reported precisely |
| J-7 | W3 | Drives an owned Android phone from Orcel on each desktop OS, and an owned iPhone via iPhone Mirroring on a Mac | Consent visible; actions audited; unsupported combinations report `unsupported` |
| J-8 | W3 | Views and controls their own desktop from a paired device over the self-hosted relay | No anonymous path; presence indicator; stop and revoke work |

**Cancel probe (J-2, G-6).** The fixture server records each request's arrival time with a monotonic clock shared with
the test harness. The harness issues the cancel, records `t_ack` when `web_job_cancel` returns, then polls
`web_job_status` every 50 ms. Pass: state `cancelled` at most 2 s after `t_ack`; the fixture log shows no request whose
arrival is later than `t_ack` plus the in-flight page's own completion (at most one request started before `t_ack`).

### 10.2 Release gates (measurable)

| Gate | Measure | Applies from |
| --- | --- | --- |
| G-1 Contract integrity | Golden fixtures and schema drift tests green; frozen spellings unchanged; every `FailureCode` mapped | W1 |
| G-2 Licence | Root and per-app `cargo deny` and the npm licence check green; zero AGPL/GPL/LGPL in `crates/*` dependency graphs; AGPL markers only in `fd06-files.txt` paths; NOTICE and licence files present for every ported file | W1 |
| G-3 Authority | 100% of Full Control dispatches in the test suites have a matching audit event (lease id, digest, epoch) written before start; Safe golden pairs unchanged; no executor reachable outside the dispatcher; no dispatch without the indicator; admin executor refused | W1 |
| G-4 Isolation | Zero listening sockets owned by Orcel children other than the documented loopback MCP/REST server, measured by a per-OS socket scan during the journeys; executor children denied every protected file (C-26) | W1 (Windows), W2 (all OSes, all sidecars) |
| G-5 Parity honesty | Every capability report entry and parity matrix row is backed by a passing test or reports `unsupported` / `blocked`; the harness report has no `failed` row for a claimed wave | W1 |
| G-6 Cancellation and stop | Cancel probe passes (2 s); indicator Stop to executor death at most 1 s with `orceld` running and with it suspended (Windows W1; all OSes W2) | W1 |
| G-7 Resource budget | During J-1's scripted 50-page fetch-engine crawl, the sum of private working sets of `orceld`, the MCP front, the indicator and the parser children peaks at **at most 300 MB**, sampled every 250 ms by `scripts/ci-machine-sampler.ps1`; idle `orceld` with an empty queue at most 60 MB. Engine processes excluded. A first run above either number blocks the gate; changing a number needs FD-UP-13 | W1 |
| G-8 Cross-platform | All three CI legs green; native journeys recorded for each claimed OS; nothing claimed for an OS without its journey | W2 |
| G-9 Release provenance | Existing release workflow gates (listed files only, SBOM, attestation); the live browser in release builds only after F4 slice 7 is decided; agents never approve the `release` environment | every release |
| G-10 Real consent | Journeys that need a person's approval through a real client are run by the founder or recorded as pending; scripted consent is labelled as such | every wave |
| G-11 Audit anchoring | Every journey's log verifies, and its newest anchor matches the Event Log record | W1 |

## 11. Founder decisions needed

1. **FD-UP-1 Firecrawl approach.** (a) Recommended: reimplement the Firecrawl v2 contract (with v1 aliases) in
   Apache-2.0 Orcel code, shapes taken from the MIT SDKs, contract-tested with those SDKs; existing FD-06 ports stay as
   they are. (b) Additionally allow an optional, separately distributed AGPL Firecrawl server sidecar, never bundled or
   default. (c) Pursue a copyright-holder-signed grant from Firecrawl before any further Firecrawl-derived code.
2. **FD-UP-2 Stealth and fingerprinting policy.** Whether Orcel may ever offer bot-detection evasion (Obscura `--stealth`,
   Scrapling stealth and `curl_cffi`, Crawlee fingerprints and impersonating clients, Firecrawl `proxy: "stealth"`,
   `mobile`, `location`). Until decided, all are BLOCKED and compiled out.
3. **FD-UP-3 "Vercel agent-use" identity.** Confirm whether it means `vercel-labs/agent-desktop` at
   `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad` (Apache-2.0, macOS AX / Windows UIA / Linux AT-SPI), another repository, or
   nothing. Until then no code is admitted and Track 1 keeps the vendored Cua path.
4. **FD-UP-4 Grain activations.** Approve activating, in this order: SG-000131 (contracts, audit chain, licence gates; new
   id), SG-000101 (Firecrawl-compatible scrape and fetch engine) and SG-000102 (jobs, crawl, map, batch), both reusing
   P20-reserved ids and roles out of the sequential order recorded in `docs/p20/sg000092_architecture_freeze.json`
   ("SG-000093 through SG-000107 remain absent until sequential activation"), and SG-000132 (Full Control dispatcher and
   indicator on Windows; new id). Alternatively allocate new ids (SG-000133, SG-000134) and keep SG-000101 and SG-000102
   for P20. Also: whether SG-000097 (full filesystem) is activated in Wave 1 and SG-000096 T02-T04 are prioritized so that
   J-3b can run in Wave 1 (recommended: no; J-3 on desktop input closes Wave 1, J-3b moves to Wave 2 unless both are
   qualified first).
5. **FD-UP-5 Job approval granularity in Safe mode.** This is an **explicit loosening** of SG-000040's one-shot fetch
   approval and of C-04's per-action rule, for the new `web/crawl_start`, `web/map` and `web/batch_scrape_start` shapes
   only. Recommended: one SOFT approval per job bound to the full spec digest (start URL, scope, filters, limits of 50
   pages, depth 5 and 10 minutes, engine), the start origin's resolved-address set (`TARGET_STALE` on drift), the
   principal and `orcel_session_id`; every page still governed by SG-000040/SG-000075 rules; existing `browser_*`
   approvals unchanged. Alternative: per-page approval (no loosening; a 50-page crawl raises 50 prompts).
6. **FD-UP-6 Carrying a patched Obscura.** Approve maintaining Orcel patches (pipe CDP transport, egress removed, stealth
   and MCP compiled out) on vendored Obscura source in `third_party/obscura`, built `--locked --offline` with V8
   archives verified by SHA-256 and attested provenance, as the only way Obscura ships; or limit Obscura to a CI-only
   corpus trial until upstream offers a pipe transport.
7. **FD-UP-7 Web tools in release builds.** Whether the fetch engine (no browser) may make `web_scrape`, `web_map` and
   `web_crawl_start` available in **Windows** release builds in Wave 1 (macOS and Linux follow WP2-12), while the
   chromium engine stays development-only until F4 slice 7 is decided. Recommended: yes for Windows, after J-1 and J-2
   pass.
8. **FD-UP-8 Custom request headers.** Whether Firecrawl `headers` may ever be honoured (they can carry credentials and
   cookies); refused until decided.
9. **FD-UP-9 Same-user isolation mechanism for executor children (C-26).** Recommended (section 4.14, buildable as
   written): on Windows, every Full Control executor child runs under a restricted token whose restricting SID list
   **excludes the user SID** and carries a per-install executor SID (`S-1-9-<random>`). Process-starting executors use
   profile S (no logon SID, a dedicated window station and desktop, every Job Object UI limit, explicit executor-SID
   grants on workspace roots and a private temp directory). The native computer host uses profile D (logon SID kept for
   the input desktop, every UI limit except `HANDLES`), with residual R-D1 (it can read same-user process memory)
   contained by a static guard on the pinned host. The state root carries an explicit deny ACE for the executor SID and
   an `OWNER RIGHTS` `READ_CONTROL`-only ACE, and `orceld` and the indicator put the same deny ACE on their own process
   objects. This keeps medium integrity for the native host, so input keeps working, which an AppContainer would
   break. AppContainer remains the boundary for donor sidecars. On macOS a Seatbelt deny of the state root and on Linux
   a Landlock rule set without it (Wave 2). Alternatives: an AppContainer executor (breaks desktop input), or a separate
   local account (needs administrator rights to create). Sub-questions: (a) accept that GUI programs started by shell
   executors are invisible (profile S desktop); (b) if WP1-10's measurement shows UI Automation observation failing
   broadly under profile D, choose between reduced capability under a lease (recommended) and a second, unrestricted,
   observe-only host instance with no input path. Whichever is chosen, C-27's desktop-input residual remains and is
   shown in the grant prompt.
10. **FD-UP-10 Approvals inside a trusted session.** The founder has asked for no repetitive approval dialogs inside a
    trusted session; today a lease is an additional gate and never replaces an approval (SG-000095, C-04). Recommended
    safe form, if wanted: a **lease-scoped standing approval** granted once with STRONG presence for a declared task
    scope (executor classes, roots or origins, and a time box no longer than the lease), **bound to both the lease and
    the requesting principal** (a different MCP or REST client cannot use it), shown on the indicator, still audited per
    dispatch with lease id, digest, epoch and principal, revoked by Stop or expiry, and never covering `Admin`, remote
    callers or out-of-scope targets. Alternative: keep per-action approvals unchanged.
11. **FD-UP-11 Crawl bounds.** Keep SG-000108 slice 7's limits (50 pages, depth 5, 10 minutes, 1,000 remembered URLs)
    for Firecrawl-compatible crawls (recommended for Wave 1), or raise them; raising needs its own security review.
12. **FD-UP-12 Network transport on macOS and Linux.** Approve WP2-12 as new network authority (rustls with the platform
    verifier, DNS pinning to the validated address set, exact-peer check) with an SG-000040 amendment and its own security
    judge, or keep web tools Windows-only.
13. **FD-UP-13 Resource budget.** Confirm G-7's numbers (300 MB peak across Orcel processes excluding the engine during a
    50-page crawl; 60 MB idle `orceld`), or set others before WP1-11 runs.

## 12. Draft grains and what this document does not do

Draft grain JSONs (state `DRAFT`, not activations) are in [`unified-grains/`](unified-grains/):

| File | Grain | Packets |
| --- | --- | --- |
| `SG-000131.draft.json` | Unified platform contracts v1, audit hash chain and anchor, licence gates (inert) | WP1-00 to WP1-03 |
| `SG-000101.draft.json` | Firecrawl-compatible scrape over MCP and loopback, Windows fetch engine, contract harness | WP1-05, WP1-06 (scrape), WP1-07, WP1-08, WP1-09 |
| `SG-000102.draft.json` | Embedded job queue; async crawl, map and batch scrape | WP1-04, WP1-06 (jobs), WP1-07, WP1-09 |
| `SG-000132.draft.json` | Full Control dispatcher, protected indicator and out-of-band stop on Windows | WP1-10, WP1-12 |

This document does not: activate any grain; import, copy or build any donor code; add any dependency; decide any
licence question; claim any capability as qualified; change README or release claims; or replace the canonical
SG-000093, SG-000095, SG-000108, SG-000010, SG-000040 or SG-000060 records, which remain authoritative where they differ
from this draft.

## 13. Review resolutions (revision 2)

| Finding | Resolution | Where |
| --- | --- | --- |
| R1 fetch transport Windows-only | Chosen: fetch engine is **Windows-only in Wave 1**, reusing the qualified WinHTTP SG-000040 transport; macOS/Linux report `unsupported`. Justification: a non-Windows transport is new network authority needing its own guard amendment and judge (S3), and section 7.2 keeps runtime crate deps at zero. Scoped packet WP2-12 (rustls + platform verifier, DNS pin, exact peer, SG-000040 amendment) and FD-UP-12 | 2.3, 4.6, 5.1, WP1-06, WP1-08, WP2-12, 7.3, 11 |
| R2 J-3 needs disabled ShellProcess | J-3 rewritten around DesktopInput (enabled for Full User, SG-000095); shell and filesystem moved to J-3b with SG-000096 T02-T04 qualification and SG-000097 activation as explicit prerequisites | 10.1, FD-UP-4 |
| R3 crawl unit granularity, no fetch driver | Decided: `crawl.rs` owns frontier/dedup/limits; one crawl or map = one `orcel-jobs` unit; per-URL units and dedup for batch only. `FetchCrawlDriver` added to WP1-06 | 4.11, WP1-06 |
| R4 orcel-web dependency on browser-host | `orcel-web` depends on `orcel-contracts` only and emits `WebCrawlRequest` (contracts); `orceld` translates to `CrawlSpec` | 3.1, 3.2, 4.11 |
| R5 naming, workspace_id, Ids | Pinned `capability/operation` pairs and tool names in catalog style; `workspace_id` from transport default; `Ids` defined | 4.0, 4.11 |
| R6 OUTCOME_UNKNOWN, PATH_* mapping | `OUTCOME_UNKNOWN` added as a `FailureCode`; `PATH_ESCAPE` 403, `PATH_RACE_DETECTED` 409; test that every variant is mapped | 4.10, 5.5, WP1-02 |
| R7 schema generator | `schemars` =1.2.3 as dev-dependency of `orcel-contracts`, drift test | 4.0, 7.2 |
| R8 canonical_json vs SG-000093 digests | SG-000093 lease ids and binding digest (and SG-000018/19/40 approval digests) exempt and unchanged | 4.0 |
| R9 LEASE_UNSUPPORTED_PLATFORM input | WP1-10 adds `mode_selectable_on(proof, mode, os: OsFamily)`; `mode_selectable` delegates with compile-time OS | 4.2, WP1-10 |
| R10 FD prerequisites | FD-UP-1/5/7 (and 9, 11) added to packet prerequisites | 8.1 |
| R11 missing tests/CI | WP1-00, WP1-09, WP1-11 now name commands and runners | 8.2 |
| R12 G-7, J-1 site, cancel measurement | G-7 committed numbers (300 MB peak, 60 MB idle) with sampler and FD-UP-13; J-1 pinned fixture site plus named public site for founder leg; cancel probe defined | 10.1, 10.2, 11 |
| R13 AGPL claim vs FD-06, scan scope | C-15/C-16 reworded to "no new AGPL"; `fd06-files.txt` allowlist; scan covers crates/apps/packages/tests | 1.4, WP1-01, SG-000101 draft |
| R14 html5ever MSRV | Doc-parser workspace declares `rust-version = "1.88"` (at least 1.85); recorded | 3.1, 7.1, 7.2 |
| R15 AuditKind relation | Lease events carry `AuthorityAuditEvent` verbatim; dispatch is a new `AuditEventKind`; `AuditKind` unchanged | 4.8 |
| S1 same-user agent | C-25 (STRONG grant/renew, protected markers for grant/indicator/stop, input refusal tests), C-26 (executor children denied the state root, per-OS test), C-27 residual stated, FD-UP-9 mechanism | 1.2, WP1-10, WP1-12, 11 |
| S2 executor "may replace approval" | Removed; `lease_gate` additionally gates, never replaces; founder wish recorded as FD-UP-10 with lease-scoped standing approval as recommended safe form | 1.1 C-04, 4.5, 11 |
| S3 release fetch transport and guard | Wave 1 fetch Windows-only on the existing transport; WP2-12 is a separate packet with SG-000040 amendment; WP1-07 carries the explicit Node guard amendment for the eight MCP web tools | WP1-07, WP2-12, FD-UP-7, FD-UP-12 |
| S4 indicator and hung orceld | C-28; WP1-12 protected indicator; dispatcher refuses with `INDICATOR_UNAVAILABLE`; out-of-band stop kills Job Objects and revokes when `orceld` hangs | 1.2, 4.10, WP1-10, WP1-12 |
| S5 atomicity, expiry, admin | C-30: epoch lock held from check to process start, stop takes it; expiry kills; per-unit re-check; `Admin` refused in Wave 1; race test | 1.2, WP1-10 |
| S6 audit anchoring and claims | C-29; anchor to Event Log and indicator; argv/URL/query digested; refuse dispatch on write failure; truncation claim corrected | 1.2, 4.8, WP1-03, G-11 |
| S7 REST token and SDK default | Separate prefixed REST tokens with rotation and per-client principals; job ownership; pending-approval cap; config guard and docs for `api.firecrawl.dev`; W2 WebSocket checks Origin and token | 4.12, WP1-07, WP2-11 |
| S8 crawl approval | Resolved-address set in the digest, `TARGET_STALE` on drift, fetch crawl driver specified, FD-UP-5 framed as explicit loosening of C-04/SG-000040 | 4.11, 5.4, FD-UP-5 |
| S9 crawl bounds | Kept 50 pages / depth 5 / 10 minutes (FD-UP-11 to change); global 200 MiB store cap; pending-approval timeout cancels | 4.11, 5.4, 11 |
| S10 restart | Approvals and jobs bind `orcel_session_id`; on restart `not_started` cancelled, `dispatched` `outcome_unknown` | 4.3, 4.4, 4.7 |
| S11 sidecar launch | Launch from hashed handle; handle-list allowlist; capability-less AppContainer or continuous socket scan; version never decides policy; nonce is liveness only | 1.3 C-10/C-11, 4.9 |
| S12 Obscura build and egress | Vendored sources, `--locked --offline`, V8 archives by SHA-256, provenance; `obscura-net` egress removed at compile time or sandbox-denied; Fetch interception not relied on alone | 1.3 C-13, 6.3, 7.3, WP2-05, FD-UP-6 |
| S13 "fallback automatic" | Replaced everywhere by "reported, never silent" | C-08, 5.3, WP2-04, WP2-06, J-5 |

### 13.1 Revision 3 (re-reviews of `e9cc14d4`)

| Finding | Resolution | Where |
| --- | --- | --- |
| RR1 indicator protocol | New section 4.13: `orceld` alone launches the indicator (pinned, hashed handle, one inherited anonymous pipe pair, normal user token, outside executor Job Objects, relaunch at most every 10 s); peer authentication by pipe possession plus image-path, creation-time and parent checks on both sides, and self-applied deny ACEs; closed frame vocabularies; 1 s visibility-gated heartbeat, 2 s expiry; Job Object handles duplicated `orceld` to indicator with `JOB_OBJECT_TERMINATE` and `JOB_OBJECT_QUERY` only; Stop via `StopRequest`/`StopAck`, and when `orceld` hangs the indicator terminates held Job Objects and writes an unauthenticated revoke request in the state root's `stop` directory that `orceld` honours inside the epoch lock before any dispatch. Justified: the indicator never holds the authority key; a revoke request can only remove authority; executors cannot write the directory | 4.13, C-28, WP1-12 |
| RR2 DesktopInput process boundary | New section 4.14: `orceld/src/uia.rs` -> `ComputerHostAdapter` -> `HostSession::spawn` -> Go host `apps/orcel-computer-host` is the DesktopInput executor child; under a lease it runs with the executor token in a Job Object, handle duplicated to the indicator (token and UI limits superseded by 13.2). AppContainer rejected for it (UIPI blocks low-integrity input). FD-UP-9 stays the founder call, with the restricted-token-plus-executor-SID mechanism and exact ACLs stated buildably | 4.14, WP1-10, FD-UP-9 |
| RR3 WP1-12 prerequisite | WP1-03 added | 8.1, SG-000132 draft |
| SN1 residual in the grant prompt | C-25: the STRONG grant and renewal prompt states the C-27 residual; WP1-10 adds the text and a test | C-25, C-27, WP1-10, J-3 |
| SN2 anchor verify and registration | `orcel audit verify` checks every Orcel anchor still in the Application log; conflicting records are a break; beyond-tail record means truncation. No source registration (it needs admin): unregistered `RegisterEventSourceW` per user, proven by a standard-account CI test and a founder-PC run; if the write is denied, Full Control is refused; indicator-only fallback removed | C-29, 4.8, WP1-03 |
| SN3 heartbeat visibility | Heartbeats only while topmost, visible, not minimised, not cloaked and on a monitor; tests minimise and cloak | C-28, 4.13, WP1-12 |
| SN4 hotkey failure | `HotkeyStatus { registered: false }`; never shown as ready; Stop button primary and first | 4.13, WP1-12 |
| SN5 add-rest approval and device cap | `add-rest` and `rotate-rest` need a SOFT approval through the protected local broker; device-wide cap of 2 pending web approval prompts | 4.11, 4.12, SG-000101 and SG-000102 drafts |
| SN6 standing approval principal | FD-UP-10's standing approval binds the lease and the requesting principal, and audits the principal | FD-UP-10, SG-000132 draft |
| Grain consistency | All four drafts re-checked against the spec and updated to revision 3 (indicator protocol, executor boundary, anchor rule, add-rest approval, caps, prerequisites) | `unified-grains/*.draft.json` |

### 13.2 Revision 4 (security re-check of `5d1651cd`)

| Finding | Resolution | Where |
| --- | --- | --- |
| B1 user SID in the restricting list | Removed from every executor token. Profile S (process-starting executors): restricting SIDs executor, Everyone, Users, Authenticated Users, RESTRICTED (no user or logon SID), so other same-user processes are unopenable; workspace roots and a private temp directory granted explicitly to the executor SID (Chromium-style). Profile D (native host): user SID removed, logon SID kept for the input desktop and `DESKTOP_JOURNALPLAYBACK`; default DACLs give it read and execute only (stated: `PROCESS_VM_READ` included, residual R-D1, contained by a static guard on the pinned host), never write, thread, handle or terminate rights. Tests open explorer and another same-user process with `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD` and expect denial. Native host consequence: `SendInput` needs no target handle, window actions need window handles (allowed), UIA mostly needs none but COM security and legacy common-control proxies are unproven, so WP1-10 measures with the existing Go qualification suites and reports failures `unsupported`; FD-UP-9 sub-question (b). J-3 updated accordingly | 4.14, C-26, WP1-10, J-3, FD-UP-9 |
| B2 desktop-level attacks | Profile S runs on a dedicated window station and desktop with every `JOB_OBJECT_UILIMIT_*` flag, so it cannot message, hook, close or hide the indicator or switch desktops. The native host takes every UI limit except `HANDLES` (it must act on other processes' windows; it has no clipboard call, so the clipboard limits apply). The indicator enables extension-point, Microsoft-signed-only, image-load and dynamic-code mitigation policies (works for the unsigned build because it loads only system DLLs; CI asserts it), adds the input-desktop check to visibility, acts on hardware input only (`IMO_INJECTED` ignored), treats close, minimise and hide as Stop, and resists repositioning. Residual stated: the native host can send input and messages to the indicator at the same integrity; mitigated by the injected-input filter and fail-safe handling, and a stop no user-mode code can block or fake is added: session lock (Ctrl+Alt+Del then Lock, or Win+L) via `WTSRegisterSessionNotification` in both `orceld` and the indicator | 4.13, 4.14, C-28, WP1-12, J-3 |

### 13.3 Revision 5 (nits from the re-check of `c19e7b94`)

| Nit | Resolution | Where |
| --- | --- | --- |
| N1 indirect spawn from profile S | Negative tests added: `schtasks /create` and `ITaskService` with an interactive logon type, WMI `Win32_Process.Create`, BITS `SetNotifyCmdLine`, DCOM `ShellWindows` and `MMC20.Application`; each must be refused or yield a process that still carries the restricted token, or the packet fails | 4.14 tests, WP1-10, SG-000132 draft |
| N2 R-D1 coverage of other Orcel processes | The executor-SID deny ACE also covers `orcel-mcp` (applied by `orceld` to its identified launching parent, since Node has no native ACL call) and `orcel-agent` (self-applied through `ctypes`); profile D tests assert both are unreadable | 4.14, WP1-10, SG-000132 draft |
| N3 locking disabled by policy | The indicator reads `DisableLockWorkstation` (HKCU and HKLM policy keys), warns, sends `LockStatus { available: false }`, never shows lock-to-stop as ready; `orceld` reports and audits it | 4.13, WP1-12, SG-000132 draft |
| N4 low-level hooks by other same-user processes | Stated as a residual in section 4.13, covered by the session-lock path (the secure attention sequence bypasses low-level hooks), and uncovered where locking is disabled, which the indicator states | 4.13 |
