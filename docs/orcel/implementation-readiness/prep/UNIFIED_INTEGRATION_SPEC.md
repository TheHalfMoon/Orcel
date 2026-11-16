# Orcel unified platform: integration specification (EGM draft)

**Status: DRAFT SPECIFICATION, DOCS ONLY.** This document activates no grain, imports no donor code, adds no
dependency, tool, listener or authority, and changes no canonical state. Every packet below needs its own
activated grain, exact-head qualified PR, review gates and, where it touches authority, a fresh-context
security judge. Draft grain JSONs live in [`unified-grains/`](unified-grains/), not in `.specgrain/specs/`.

- **Base:** branch `plan/donor-inventory` at `c72d33fa`, on `origin/main` `4dd5cfc93b524e3e99eed9097c3e81917676bee8`.
- **Inputs read in full:** the founder blueprint and source pins from PR #785 (`UNIFIED_PLATFORM_BLUEPRINT_2026-11-16.md`,
  `UNIFIED_SOURCE_PINS_2026-11-16.json`); [`DONOR_INVENTORY.md`](DONOR_INVENTORY.md) and
  [`capability_inventory.json`](capability_inventory.json) (96 records); `docs/security/SG-000093_FULL_CONTROL_AUTHORITY_MODEL.md`;
  `docs/security/SG-000108_ENGINE_ATTACHMENT_DECISION.md` and `SG-000108_CRAWL.md`; the SG-000010 notes
  (`SG-000010_NO_SHELL.md`, `_ZERO_NETWORK.md`, `_BOUNDED_PROCESS_SPAWN_NOTE.md`) and `SG-000060_PROTECTED_EXECUTABLE_REGISTRY_NOTE.md`;
  `docs/canonical/CURRENT.md`; the P20 freeze `docs/p20/sg000092_architecture_freeze.json`; and the code in
  `crates/orcel-contracts`, `crates/orcel-policy`, `crates/orcel-browser-host`, `crates/orceld`,
  `apps/orcel-browser-worker`, `apps/orcel-doc-parser`, `apps/orcel-mcp` and `apps/orcel-contain`.
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

## 1. Binding design constraints

Three independent Goldfish reviews found the blueprint not implementable as written. Their conclusions are
adopted here as constraints. A packet that cannot meet one stops and asks; it does not reinterpret it.

### 1.1 Authority

- **C-01. One permission-mode model.** SG-000093 is the only mode model: `Safe` (sole default), `Full User`,
  `Full Admin`, `Persistent Admin` (unavailable until SG-000099) and `Remote Full Control` (unavailable until
  SG-000105). The blueprint's "Observe / Workspace / Full Control / Headless" names are not modes. They map
  onto SG-000093 as: Observe and Workspace are `Safe` plus existing per-action approvals; local Full Control is
  `Full User` (or `Full Admin` with an `AdminLease`); remote Full Control is `Remote Full Control`; headless
  jobs are jobs that run under whichever mode their dispatch was admitted in, never a mode of their own.
- **C-02. Leases bind exactly** the OS user identity, the interactive logon session, the device, the Orcel
  session, the authority profile, the policy revision, the authority epoch, issue time and bounded expiry
  (60 s to 12 h, `crates/orcel-policy/src/full_control.rs`). Any mismatch fails closed. Emergency revoke
  advances the epoch, so every earlier lease fails before the next mutation dispatches.
- **C-03. Only the authenticated local user control path mints authority** (`LocalGrantProof`). No agent, MCP
  caller, donor runtime, relay or remote principal can mint, widen, renew, persist or convert a lease
  (`UntrustedGrantOrigin`).
- **C-04. Full Control is a new executor class consuming leases, dispatched only by `orceld`.** It is not a
  relaxation of Safe paths. It MUST NOT loosen the SG-000010 no-shell, zero-network and bounded-spawn rules,
  the SG-000060 protected executable registry, or the SG-000108 per-action SOFT approvals in `Safe` mode. A
  test in every Full Control packet proves that with no lease the Safe path is byte-for-byte unchanged.
- **C-05. Every Full Control dispatch writes an audit event** carrying the opaque lease id, the SHA-256 binding
  digest and the authority epoch (`AuthorityAuditEvent` today), and never the raw SID, raw device or session
  values, token handles or credential material.
- **C-06. The "gateway" is `orceld`.** Anything in front of it (`apps/orcel-mcp` transports, the loopback REST
  routes, the relay uplink, the desktop app) is a stateless front that holds no authority, decides no scope,
  approval or staleness, and only forwards a `RequestEnvelope` over a private pipe.
- **C-07. Agent runtimes are untrusted callers above the authority layer.** `apps/orcel-agent` (SG-000129,
  Python, DeerFlow-derived), external MCP clients, SDK users and any donor agent loop reach Orcel only as MCP
  or API callers. Discovery filtering is never authorization (`apps/orcel-mcp/src/tool_contract.ts`).
- **C-08. Broader-authority fallback is never automatic** (`broader_fallback_allowed() == false`). A lease
  failure after dispatch does not imply retry.

### 1.2 Isolation

- **C-09. Every donor-derived runtime runs as a supervised child of a Rust host crate.** Windows: Job Object
  (kill on close, process limit, memory and CPU limits) plus AppContainer where the sidecar needs no network.
  macOS: Seatbelt profile through `sandbox-exec`, owned by `orceld` running as a per-user launchd agent.
  Linux: cgroup v2 limits, seccomp, Landlock ABI 3 or later, `PR_SET_PDEATHSIG` and `PR_SET_NO_NEW_PRIVS`.
  `apps/orcel-contain` already installs these boundaries for one-shot helpers and is the reference.
- **C-10. Host-built argv, scrubbed environment.** The host builds the complete argv and an empty-by-default
  environment. The child adds nothing (`ignoreDefaultArgs: true` precedent, SG-000108 decision 1).
- **C-11. Private stdio or anonymous-pipe IPC only, no listening sockets.** Donor MCP servers, HTTP listeners
  and CDP ports are disabled or patched out. The SG-000074 frame format (`u32` little-endian length plus JSON,
  `crates/orcel-browser-host/src/proto.rs`) is the base of the sidecar contract (section 4.9).
- **C-12. Obscura speaks CDP over a pipe.** Orcel's argv rules forbid `--remote-debugging-port` and
  `--remote-debugging-address` (`crates/orcel-browser-host/src/argv.rs`); Chromium already runs over
  `--remote-debugging-pipe`. At the pinned SHA, Obscura's CDP server is TCP plus WebSocket only
  (`crates/obscura-cdp/src/server.rs` binds a `std::net::TcpListener`; `obscura serve --port`, default 9222).
  A pipe transport is therefore a required patch before Obscura can ship (WP2-05).
- **C-13. Web-intelligence sidecars have no ambient network.** All page and subresource traffic goes through a
  host-side broker (CDP `Fetch` interception fulfilled by the host's governed fetch, as SG-000075 governs
  Chromium navigation today). A forced proxy is an alternative only with its own security decision.
- **C-14. Port, don't ship runtimes.** Prefer porting algorithms into existing Rust and TypeScript crates over
  shipping new runtimes. Python and Go are not in the shipped core unless a later founder decision says so.
  Python may run in CI as a contract-test client only (Firecrawl Python SDK, section 7).

### 1.3 Licensing

- **C-15. No AGPL code in kernel crates.** Firecrawl's AGPL-3.0 code (`apps/api`, `apps/local`,
  `apps/go-html-to-md-service`, `apps/playwright-service-ts`, `apps/nuq-postgres`, `apps/test-site`,
  `apps/test-suite`) never enters `crates/*`. The Firecrawl API contract is reimplemented in Apache-2.0 code,
  with request and response shapes derived from the MIT SDKs (`apps/js-sdk`, `apps/python-sdk`), not from the
  AGPL `apps/api/openapi.json`, which MUST NOT be vendored.
- **C-16. Existing FD-06 ports stay as they are.** `crawl_scope.rs`, `map_rank.rs`, `change_tracking.rs` and
  `apps/orcel-doc-parser` rely on the FD-06 founder attestation and the notice
  `docs/orcel/notices/firecrawl-AGPL-3.0.txt`. This spec neither widens nor removes that reliance; it records
  that no copyright-holder-signed grant is in the repository (`DONOR_INVENTORY.md` section 1). `SG-000108_CRAWL.md`
  records `crawl.rs` itself as a native rebuild with no copied line.
- **C-17. An AGPL Firecrawl server could only ever be an optional, separately distributed sidecar**, never a
  default, never bundled, never in a kernel crate. Choosing it is FD-UP-1.
- **C-18. Fleet:** a reporting adapter only, from MIT parts; nothing from `ee/`. **UU Remote:** no source;
  remote desktop is built on the existing relay (SG-000052 to SG-000058, SG-000057 self-host) and WebRTC later.
- **C-19. Stealth and fingerprinting are BLOCKED** (Obscura `--stealth`, Scrapling stealth and `curl_cffi`,
  Crawlee fingerprints and impersonating clients, Firecrawl `proxy: "stealth"`) pending FD-UP-2.
- **C-20. Per-crate and per-package licence checks run in CI** (WP1-01).

### 1.4 Scope and sequencing

- **C-21. Founder goals are all retained; only their order changes.** Wave 1, Wave 2 and Wave 3 are as listed in
  section 8. Nothing in a later wave is dropped.
- **C-22. Acceptance is by user journeys** (section 10), not donor checklists.
- **C-23. A claim needs a test.** Capability discovery reports `unsupported` explicitly; no tool returns a
  simulated success. Parity rows without a passing test stay `not_started`.
- **C-24. Existing work is extended, not replaced.** No donor tree replaces the repository root; the trusted
  runtime grows through tested adapters.

## 2. Architecture

### 2.1 Layers and trust boundaries

```text
 UNTRUSTED CALLERS (C-07)
 +--------------------------------------------------------------------------------------------+
 | Desktop app (WPF today; Tauri SG-000119) | orcel CLI | MCP clients | SDKs (TS W2, Py W3)    |
 | apps/orcel-agent (Python, DeerFlow-derived) | donor agent loops, if any, as callers only     |
 +--------------------------------------------------------------------------------------------+
            | MCP stdio | MCP Streamable HTTP 127.0.0.1 + bearer | REST 127.0.0.1 + bearer | relay
            v
 STATELESS FRONTS, NO AUTHORITY (C-06)
 +--------------------------------------------------------------------------------------------+
 | apps/orcel-mcp: tool_contract.ts catalog -> MCP tools; loopback REST /v1,/v2 Firecrawl       |
 | routes (W1, hand-mapped) and /api/v1 OpenAPI routes (W2, generated from the catalog);        |
 | relay_device uplink (SG-000055) adds a RemoteContext; it never adds authority                |
 +--------------------------------------------------------------------------------------------+
            | private stdio pipe: one RemoteRequestEnvelope per line (orcel-contracts)
            v
 orceld: THE GATEWAY AND SOLE AUTHORITY
 +--------------------------------------------------------------------------------------------+
 | request decode -> capability discovery -> policy (orcel-policy) -> mode check              |
 |   Safe: SG-000010 / SG-000060 / SG-000108 rules + per-action SOFT/STRONG (orcel-approval)    |
 |   Full User / Full Admin: lease check (C-02) -> Full Control dispatcher (WP1-10)             |
 | job queue (orcel-jobs, W1) | audit hash chain (orcel-audit, W1) | mutation journal           |
 | emergency stop: epoch advance -> cancel in-flight jobs -> kill sidecars                      |
 +--------------------------------------------------------------------------------------------+
     | in-process providers                      | supervised children (C-09..C-13)
     v                                           v
 +------------------------------+   +-------------------------------------------------------+
 | orcel-provider-fs / -git /   |   | orcel-browser-host -> apps/orcel-browser-worker        |
 | -process / -network /        |   |   -> Chromium (--remote-debugging-pipe)   [today]      |
 | -clipboard / -uia            |   |   -> Obscura (pipe patch, broker fetch)   [W2 trial]   |
 | orcel-web (pure mapping, W1) |   | orcel-contain -> apps/orcel-doc-parser (pdf/docx/xlsx, |
 +------------------------------+   |   html for the fetch engine W1)                       |
                                    | apps/orcel-native-host (macOS/Linux GUI), Go host (Win) |
                                    | orcel-sidecar host (W2) -> mobile, fleet adapters (W3) |
                                    +-------------------------------------------------------+
                                                       |
                                                       v
                                           OS (Windows / macOS / Linux)
```

### 2.2 Two request walk-throughs

**Firecrawl-compatible scrape (Wave 1, Safe mode).** The Firecrawl JS SDK, configured with
`apiUrl: "http://127.0.0.1:<port>"` and `apiKey: <loopback token>`, posts `/v2/scrape`. The loopback front checks
`Host`, `Origin` and the bearer token as it does for `/mcp` today, translates the body with the `orcel-web`
schema into `RequestEnvelope { capability: "web", operation: "scrape" }` and forwards it. `orceld` checks the
capability report (engine available on this OS and build), runs policy, raises one SOFT approval bound to the
request digest (URL, engine, formats), dispatches to the engine (`fetch` through `orcel-provider-network` plus the
contained parser, or `chromium` through the browser host's `extract_page`), audits, and returns the result.
The front shapes it as Firecrawl's `{ "success": true, "data": Document }`.

**Full Control action (Wave 1, Windows, Full User).** The user grants Full User from the local control path; the
lease is stored by `full_control_store.rs`. An MCP caller asks for a shell session (SG-000096). `orceld` loads the
lease, re-reads the native identity (`current_windows_identity`), checks every binding (C-02), confirms
`executor_enabled_now(FullUser, ShellProcess)`, writes the dispatch audit event (C-05) and only then starts the
process. Emergency stop advances the epoch: the next check fails, in-flight jobs move to `cancelled` (if the
executor confirms the stop) or `outcome_unknown` (if it cannot), and the sidecar host kills the child trees.

### 2.3 What is deliberately absent

- No second authorization channel: no donor MCP server, HTTP listener, CDP port or admin feature is reachable.
- No founder-hosted service, SaaS database, paid API or required relay (blueprint decision 6).
- No webhook egress from jobs in Wave 1 (Firecrawl `webhook` is refused, section 5.3).

## 3. Crates and packages

### 3.1 Inventory

"Wave" is when the unit is created or first changed by this plan. Licence is the unit's own licence; donor notices
travel with ported files (section 6.1).

| Unit | Path | State | Wave | Licence | Depends on (Orcel units) | Role in this plan |
| --- | --- | --- | --- | --- | --- | --- |
| orcel-contracts | `crates/orcel-contracts` | exists | W1 | Apache-2.0 | none (serde, serde_json) | Leaf. Gains contract modules of section 4 |
| orcel-platform | `crates/orcel-platform` | exists | W2 | Apache-2.0 | none | Per-OS identity readers for macOS and Linux (W2) |
| orcel-policy | `crates/orcel-policy` | exists | W1 | Apache-2.0 | contracts, platform, approval, providers | Lease issue and check stay here; wire types move to contracts |
| orcel-approval | `crates/orcel-approval` | exists | none | Apache-2.0 | contracts, platform | Unchanged SOFT/STRONG approvals |
| orcel-audit | `crates/orcel-audit` | exists | W1 | Apache-2.0 | contracts, platform | Gains the hash chain (section 4.8) |
| orcel-journal | `crates/orcel-journal` | exists | W1 | Apache-2.0 | none (fs4) | Storage primitive reused by orcel-jobs |
| orcel-jobs | `crates/orcel-jobs` | **new** | W1 | Apache-2.0 | contracts, journal | Embedded durable queue, retry, throttle, checkpoint |
| orcel-web | `crates/orcel-web` | **new** | W1 | Apache-2.0 | contracts, browser-host (types only) | Firecrawl-compatible schemas and translation, pure |
| orcel-browser-host | `crates/orcel-browser-host` | exists | W1, W2 | Apache-2.0 | contracts | Crawl, map, extraction (W1 reuse); engine contract and Obscura adapter (W2) |
| orcel-provider-network | `crates/orcel-provider-network` | exists | W1 | Apache-2.0 | contracts | `web_fetch` governed fetch reused by the fetch engine |
| orcel-sidecar | `crates/orcel-sidecar` | **new** | W2 | Apache-2.0 | contracts, platform | Generic supervised-child host and sandbox profiles |
| orcel-provider-mobile | `crates/orcel-provider-mobile` | **new** | W3 | Apache-2.0 (+ MIT notice, phone-harness) | contracts, sidecar | Android ADB provider |
| orcel-fleet-report | `crates/orcel-fleet-report` | **new** | W3 | Apache-2.0 | contracts | Read-only inventory reporting adapter |
| orceld | `crates/orceld` | exists | W1 to W3 | Apache-2.0 | all kernel crates | Dispatch for web and job capabilities; Full Control dispatcher |
| orcel-mcp | `apps/orcel-mcp` | exists | W1, W2 | Apache-2.0 | orceld over a pipe only | Catalog entries, loopback REST routes, OpenAPI generation (W2) |
| orcel-browser-worker | `apps/orcel-browser-worker` | exists | W2 | Apache-2.0 (+ MIT notice, browser-use) | browser host over a pipe only | Engine-neutral snapshot refs and actions (agent-browser port) |
| orcel-doc-parser | `apps/orcel-doc-parser` | exists | W1 | Apache-2.0 (+ FD-06 notice) | provider-process (test) | New `html` format for the fetch engine |
| orcel-contain | `apps/orcel-contain` | exists | W2 | Apache-2.0 | provider-process | Boundary reference for orcel-sidecar |
| orcel-native-host | `apps/orcel-native-host` | exists | W2, W3 | Apache-2.0 (+ vendored Cua notices) | platform | macOS/Linux GUI; iPhone Mirroring (W3) |
| orcel-relay | `apps/orcel-relay` | exists | W3 | Apache-2.0 | none in-process | Remote screen signalling on the SG-000057 relay |
| firecrawl-compat | `tests/firecrawl-compat` | **new** | W1 | Apache-2.0 (+ MIT notice for adapted SDK tests) | none (black-box over loopback) | Contract harness; never shipped |
| browser-corpus | `tests/browser-corpus` | **new** | W2 | Apache-2.0 (+ Apache notice, agent-browser) | none (black-box) | Dual-engine qualification corpus; never shipped |
| @orcel/sdk | `packages/orcel-sdk-ts` | **new** | W2 | Apache-2.0 | none (HTTP client) | TS SDK generated from the OpenAPI document |
| orcel-sdk (Python) | `packages/orcel-sdk-py` | **new** | W3 | Apache-2.0 | none (HTTP client) | Python SDK; a client library, not shipped core (C-14) |
| obscura (patched) | `third_party/obscura` (separate workspace) | **new** | W2 | Apache-2.0 + vendored MIT/OFL | none | Pinned source plus the pipe-transport patch; built in CI |

### 3.2 Dependency direction

```text
 orcel-contracts  <-- every kernel crate (leaf; serde only; no IO; no platform code)
 orcel-platform   <-- policy, approval, audit, sidecar, providers, orceld
 orcel-journal    <-- orcel-jobs, orceld
 orcel-jobs       <-- orceld                  (never <- providers or browser-host)
 orcel-web        <-- orceld                  (pure: no IO, no network, no process)
 browser-host     <-- orcel-web (types), orceld
 orcel-sidecar    <-- provider-mobile, fleet-report, browser-host (W2), orceld
 orceld           <-- nothing in-process; apps reach it only over a pipe
```

Rules, enforced by a `cargo metadata` test added in WP1-01:

1. No kernel crate (`crates/*`) depends on any `apps/*`, `tests/*`, `packages/*` or `third_party/*` unit.
2. `orcel-contracts` has no dependency beyond `serde` and `serde_json`, and no `cfg(target_os)` code.
3. `orcel-web` and `orcel-jobs` have no network, process or platform dependency.
4. Separate workspaces stay separate (`apps/orcel-contain`, `apps/orcel-doc-parser`, `apps/orcel-native-host`,
   `third_party/obscura`), so tokio and V8 never enter `orceld`'s lockfile (AD-16 precedent).
5. A crate's licence set (its own plus its resolved dependencies) passes the allowlist of WP1-01.

## 4. Contracts v1

All types live in `crates/orcel-contracts/src/` as new modules: `identity.rs`, `lease.rs`, `session.rs`,
`tool.rs`, `capability.rs`, `job.rs`, `event.rs`, `sidecar.rs`, `error.rs`. They are wire types only: no
issuance, no checking and no secret material. Issuance and checking stay in `orcel-policy`.

### 4.0 Versioning and conventions

- Every top-level wire object carries `"contract": "orcel.<name>/<major>"`, starting at `/1`. A major bump is a
  breaking change and needs its own grain; additive optional fields keep the major.
- **Inbound authority-bearing objects** (leases, grants, remote context, sidecar control frames) use
  `#[serde(deny_unknown_fields)]`, as `FullControlLease` and `RemoteContext` do today. Outbound reports may gain
  optional fields.
- Enums are `snake_case` on the wire, except `FailureCode`, which keeps its frozen `SCREAMING_SNAKE_CASE`.
- Time is `u64` milliseconds since the Unix epoch (`*_ms`). Digests are lowercase hex SHA-256 (`*_sha256` or
  `*_digest`). Identifiers are opaque strings of at most 256 bytes (`MAX_AUTHORITY_FIELD_BYTES`).
- `INTERNAL_PROTOCOL_VERSION` stays `1`; contracts carry their own majors. A golden JSON fixture per type lives in
  `crates/orcel-contracts/tests/fixtures/*.json`, and JSON Schema (draft 2020-12) files are generated into
  `docs/orcel/contracts/schema/` by a test that fails when they drift.
- Canonical JSON for digests: UTF-8, object keys sorted by code point, no insignificant whitespace, integers
  without exponent, strings with minimal escaping (RFC 8785 style). One function, `canonical_json`, in
  `orcel-contracts`, is the only producer.

### 4.1 Principal and device

```rust
pub enum PrincipalKind { LocalUser, McpClient, RemotePrincipal, AgentRuntime, Sidecar }

pub struct Principal {
    pub contract: String,            // "orcel.principal/1"
    pub kind: PrincipalKind,
    pub principal_id: String,        // opaque; for LocalUser the SHA-256 of the OS identity binding
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

Only `LocalUser` can appear as the issuing principal of a lease (C-03). `AgentRuntime` and `Sidecar` principals
are recorded in audit for attribution and are never authority.

### 4.2 Per-OS identity binding

```rust
#[serde(tag = "os", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsIdentityBinding {
    Windows { user_sid: String, logon_session_luid: u64 },          // TokenUser + TokenStatistics.AuthenticationId (today)
    Macos   { uid: u32, audit_session_id: u32, console_user: bool }, // getuid + getaudit_addr ai_asid (W2)
    Linux   { uid: u32, login_session_id: String, seat: Option<String> }, // sd_pid_get_session / logind (W2)
}
```

- Wave 1 implements `Windows` only and keeps `FullControlLease`'s existing fields (`windows_user_sid`,
  `logon_session_id`) byte-for-byte, so `orcel-full-control-lease/1` leases stay valid. Wave 2 introduces
  `orcel-full-control-lease/2` with `os_identity: OsIdentityBinding` and a migration that invalidates, never
  converts, v1 leases (a user re-grants).
- Each reader returns the binding from the running process's own kernel credentials, never from an environment
  variable or an argument. macOS and Linux readers are WP2-01; until then `mode_selectable` refuses `Full User`
  on those OSes with `LEASE_UNSUPPORTED_PLATFORM`.

### 4.3 Lease and grant

```rust
pub struct LeaseView {                       // wire projection; no secret; never accepted as proof
    pub contract: String,                    // "orcel.lease-view/1"
    pub lease_id: String,                    // domain-separated SHA-256 (SG-000093)
    pub mode: AuthorityMode,                 // safe | full_user | full_admin | persistent_admin | remote_full_control
    pub binding_digest: String,              // SHA-256 over the exact bindings (C-02)
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
}

pub struct DispatchAuthority {               // attached by orceld to every dispatch and audit event
    pub mode: AuthorityMode,
    pub lease: Option<LeaseRef>,             // Some for every Full Control dispatch (C-05)
    pub grant: Option<GrantRef>,             // Some for every approved Safe dispatch
}
pub struct LeaseRef { pub lease_id: String, pub binding_digest: String, pub authority_epoch: u64 }
```

`AuthorityMode`, `ExecutorClass` and `ExecutionState` move from `orcel-policy` to `orcel-contracts` with identical
serde spellings and are re-exported from `orcel-policy` so no caller changes. `FullControlLease` and `AdminLease`
stay in `orcel-policy` (they are issued there and their ids are keyed by `LocalGrantProof`).

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

A lease binds `orcel_session_id`, so a restart invalidates every lease (C-02). `client_session_id` is never
authority.

### 4.5 Tool registry entry

The TypeScript catalog in `apps/orcel-mcp/src/tool_contract.ts` stays authoritative for MCP. Wave 1 adds a Rust
mirror so `orceld` and the generated OpenAPI agree mechanically:

```rust
pub struct ToolEntry {
    pub contract: String,                    // "orcel.tool/1"
    pub name: String,                        // e.g. "web_scrape"
    pub capability: String,                  // "web"
    pub operation: String,                   // "scrape"
    pub effect: EffectClass,                 // read | preview | write | destructive | execute | network | desktop_* | clipboard
    pub approval: ApprovalClass,             // in Safe mode
    pub executor: Option<ExecutorClass>,     // the Full Control class that may replace the approval, if any
    pub remote: RemoteExposure,              // local_only | scopes(["orcel.web.read", ...])
    pub profiles: Vec<String>,               // discovery only
    pub platforms: Vec<OsFamily>,            // where an implementation exists
    pub input_schema: String,                // path of the JSON Schema
    pub output_bound: String,
    pub since: String,                       // grain id
}
```

A test in `apps/orcel-mcp` compares the TS catalog with `docs/orcel/contracts/tools.json` generated from the Rust
mirror; any difference fails CI.

### 4.6 Capability discovery

```rust
pub struct CapabilityReport {
    pub contract: String,                    // "orcel.capability-report/1"
    pub device: Device,
    pub build: BuildKind,                    // release | live_browser_dev | live_browser_test
    pub entries: Vec<CapabilityEntry>,
}
pub struct CapabilityEntry {
    pub capability: String,                  // "web.scrape"
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

`orcel capabilities` (CLI), the `capabilities` MCP tool and `GET /api/v1/capabilities` (W2) return the same
report. Every tool call that hits a non-`Available` entry fails with the matching `FailureCode` (section 4.10),
never a degraded success.

### 4.7 Job state machine

Jobs reuse the frozen SG-000093 vocabulary. No new state is added.

```rust
pub struct Job {
    pub contract: String,                    // "orcel.job/1"
    pub job_id: String,                      // 128-bit random, base32
    pub kind: JobKind,                       // web_crawl | web_batch_scrape | web_scrape (async) | ...
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
| `not_started` | `cancelled` | Caller cancel, approval denied or expired, emergency stop |
| `not_started` | `dispatched` | First unit of work handed to an executor |
| `dispatched` | `completed` | Every unit finished; `outcome` set (`Partial` if some units failed) |
| `dispatched` | `cancelled` | Cancel or stop, and every executor confirmed it stopped |
| `dispatched` | `outcome_unknown` | An executor died, a stop could not be confirmed, or `orceld` restarted mid-unit |

Terminal states are `completed`, `cancelled` and `outcome_unknown`. `outcome_unknown` is never retried
automatically (C-08); the caller may submit a new job. Unit-level retries (section 4.11, orcel-jobs) happen inside
`dispatched` and are idempotent reads only; a mutating unit is never retried.

### 4.8 Event audit chain

`orcel-audit` today appends JSON lines with no chain. Wave 1 adds a hash chain without changing what is
redacted.

```rust
pub struct AuditEvent {
    pub contract: String,                    // "orcel.audit-event/1"
    pub seq: u64,                            // 0-based, gapless per log file
    pub prev_digest: String,                 // digest of seq-1; 64 zeros for seq 0
    pub at_ms: u64,
    pub kind: AuditEventKind,                // request | decision | approval | dispatch | state | lease | emergency_stop | sidecar
    pub request_id: Option<String>,
    pub job_id: Option<String>,
    pub capability: Option<String>, pub operation: Option<String>,
    pub authority: Option<DispatchAuthority>,// lease id + binding digest + epoch for every Full Control dispatch (C-05)
    pub state: Option<ExecutionState>,
    pub detail: serde_json::Value,           // bounded, redacted: no SID, token, secret, page content
    pub digest: String,                      // SHA-256(canonical_json(self without "digest"))
}
```

- Rotation starts a new file whose `seq 0` `prev_digest` is the last digest of the previous file, recorded in a
  `rotation` event.
- `orcel audit verify [--from <file>]` recomputes the chain and reports the first break. A break is evidence, not
  a repair: nothing is rewritten.
- The chain detects truncation or edits by anything without the ability to rewrite the whole log. It does not
  defend against a same-user writer who rewrites everything; that is stated in the grain as accepted.

### 4.9 Sidecar IPC: handshake, heartbeat, kill

Generalizes SG-000074 (`proto.rs`): anonymous pipes, `u32` little-endian length plus JSON, closed vocabularies,
unknown frames rejected without action.

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

| Phase | Rule |
| --- | --- |
| Launch | Host resolves the binary by pinned absolute path, checks it is not group- or world-writable, hashes it and compares with the pin (orcel-contain step 1); empty environment plus an explicit allowlist; complete argv |
| Handshake | First frame both ways is `Hello` within 5 s; generation and `session_nonce` must match; anything else kills the child |
| Listener check | After `Hello`, the host verifies the child owns no listening socket (Windows `GetExtendedTcpTable`/`GetExtendedUdpTable` by PID; Linux seccomp denies `bind`/`listen` on non-`AF_UNIX`; macOS Seatbelt denies `network-bind`) |
| Heartbeat | Host sends `Heartbeat` every 2 s; three missed `HeartbeatAck` kill the child and mark its units `outcome_unknown` |
| Cancel | `Cancel` then 2 s grace; no `Response` or `Error` means kill |
| Shutdown | `Shutdown` then `Bye` within `deadline_ms` (at most 5 s), else kill |
| Kill | Windows `TerminateJobObject`; macOS and Linux `SIGKILL` to the process group plus `PR_SET_PDEATHSIG` / parent-death sentinel; cgroup `cgroup.kill` on Linux where delegated |
| Host death | Child sees end of file on stdin and exits; kill-on-close job, PDEATHSIG and sentinel cover a crashed host |

### 4.10 Errors

`FailureCode` keeps every existing variant and wire spelling. Wave 1 adds, at the end, each with a frozen-spelling
test like `remote_session_inactive_has_the_frozen_wire_spelling`:

| New code | Meaning | REST / Firecrawl HTTP |
| --- | --- | --- |
| `LEASE_REQUIRED` | A Full Control executor was asked for without an active lease | 403 |
| `LEASE_INVALID` | A lease exists but a binding, the epoch, the policy revision or expiry does not match | 403 |
| `LEASE_UNSUPPORTED_PLATFORM` | No identity binding on this OS yet | 501 |
| `UNSUPPORTED` | Capability entry is `unsupported` | 501 |
| `POLICY_BLOCKED` | Capability entry is `blocked` (stealth, cloud-only, EE) | 403 |
| `JOB_NOT_FOUND` | Unknown or expired job id | 404 |
| `QUEUE_FULL` | Queue bound reached | 429 |
| `RATE_LIMITED` | Per-origin politeness budget exhausted for a synchronous call | 429 |

Existing codes map as: `INVALID_REQUEST` 400; `CAPABILITY_DENIED`, `WORKSPACE_DENIED`, `APPROVAL_DENIED`,
`APPROVAL_REQUIRED` 403; `APPROVAL_UNAVAILABLE`, `PROVIDER_UNAVAILABLE` 503; `TARGET_STALE` 409; `PROCESS_TIMEOUT` 408;
`OUTPUT_LIMIT` 413; `POSTCONDITION_FAILED`, `INTERNAL_ERROR`, `PROCESS_TERMINATION_UNVERIFIED` 500;
`REMOTE_SESSION_INACTIVE` 403. A missing or wrong loopback bearer token is 401 before any envelope exists.
Firecrawl-shaped bodies are `{ "success": false, "error": <message>, "code": <FailureCode> }`.

### 4.11 Web contracts (`orcel-web`) and the job queue (`orcel-jobs`)

`orcel-web` holds Apache-2.0 Rust types for the Firecrawl-compatible subset of section 5, derived field by field
from the MIT SDK types (`apps/js-sdk/firecrawl/src/v2/types.ts`, `apps/python-sdk/firecrawl/v2/types.py`), plus
pure translations:

```rust
pub struct ScrapeRequestV2 { pub url: String, pub formats: Vec<FormatV2>, pub only_main_content: Option<bool>,
    pub include_tags: Vec<String>, pub exclude_tags: Vec<String>, pub wait_for: Option<u64>,
    pub timeout: Option<u64>, pub max_age: Option<u64>, pub parsers: Vec<ParserV2>,
    pub orcel: Option<OrcelScrapeExt> }                       // { engine: Option<"fetch"|"chromium"|"obscura"> }
pub enum FormatV2 { Markdown, Html, RawHtml, Links, Screenshot { full_page: bool }, ChangeTracking { modes: Vec<String> },
    Unsupported(String) }                                      // parsed so the refusal can name it
pub fn to_envelope(req: &ScrapeRequestV2, ids: &Ids) -> Result<RequestEnvelope, WebRefusal>;
pub fn crawl_spec(req: &CrawlRequestV2) -> Result<orcel_browser_host::crawl::CrawlSpec, WebRefusal>;
pub fn document_v2(result: &ScrapeResult) -> serde_json::Value; // Firecrawl Document shape
```

`orcel-jobs` (pure plus files under the private state root, no tokio, no server database):

| Module | Behaviour | Source of the idea (section 6.2) |
| --- | --- | --- |
| `queue.rs` | Durable FIFO per job with in-progress leases on units, reclaim after timeout, uniqueness by normalized-URL key | Crawlee `request-queue.ts`, `request-dedup-cache.ts` |
| `throttle.rs` | Per-origin minimum delay and token bucket; honours `Retry-After`; robots `Crawl-delay` when robots is on | Crawlee `throttling-request-manager.ts`, Scrapling `spiders/throttle.py` |
| `retry.rs` | Exponential backoff with jitter, max 3 attempts, read-only units only; 4xx other than 408 and 429 not retried | Crawlee `basic-crawler.ts`, `request-timeout.ts` |
| `concurrency.rs` | Concurrency 1 to 4, stepped down on memory pressure and engine failures; no CPU spinning | Crawlee `autoscaling/autoscaled-pool.ts`, `snapshotter.ts`, `system-status.ts` |
| `checkpoint.rs` | Append-only progress log so a restarted `orceld` resumes `dispatched` units as `outcome_unknown` units, never silently | Scrapling `spiders/checkpoint.py` |
| `store.rs` | Result pages written once per unit, bounded per job (default 50 MiB), expiring after 24 h, readable with a `next` cursor | Crawlee `dataset.ts`, `key-value-store.ts` |

Bounds that hold regardless of mode: at most 8 jobs queued, 2 running, 1,000 URLs remembered and depth 5 per
crawl (the existing `crawl.rs` limits), 100 URLs per batch.

## 5. Firecrawl parity matrix

### 5.1 Upstream contract facts (verified 2026-11-16)

- **Pins.** The inventory pin is `firecrawl/firecrawl@42f4d669954649ce33466a2a50e8215c7f1f4d1c`; PR #785 pinned
  `25a92fc3175babbd75fd50a0e8122aaa44b068ad`. The route tables `apps/api/src/routes/v1.ts` and `v2.ts` were read at
  both SHAs and are identical, so this matrix holds for either. Orcel's existing ports were taken at `f84845c8`.
- **Versions.** The upstream server exposes **v2** (current; `apps/api/openapi.json`, `info.version` `v2`, server
  `https://api.firecrawl.dev/v2`) and **v1** (legacy; `apps/api/v1-openapi.json`). Both OpenAPI files are in the
  AGPL `apps/api` tree and are read as reference only (C-15).
- **SDKs used as contract clients.** `@mendable/firecrawl-js` **4.54.0** (`apps/js-sdk/firecrawl/package.json`, MIT,
  Copyright (c) 2024 Sideguide Technologies Inc.): the default `Firecrawl` client speaks v2, a v1 client remains.
  It reads `apiUrl` (falling back to `FIRECRAWL_API_URL`, then `https://api.firecrawl.dev`) and sends the API key as
  a bearer token, which matches Orcel's loopback bearer. `firecrawl-py` **4.57.0** (`apps/python-sdk/firecrawl/__init__.py`,
  MIT) has `v1` and `v2` clients.
- **Upstream route counts at the pin:** v2 70 routes, v1 33 route lines of which 6 are commented out
  (`/crawlWebsitePreview`, `/checkJobStatus/:jobId`, `/keyAuth`, the v0 `/search`, `/health/liveness`,
  `/health/readiness`).
- **Parity target.** Orcel implements the **v2** contract for scrape, map, crawl and batch scrape (plus job status,
  cancel, errors and listing) in Wave 1, with **v1 aliases** for `POST /v1/scrape`, `/v1/map`, `/v1/crawl` and the v1
  crawl status, cancel and errors routes. Everything else is a later wave, `unsupported` (501), or out of scope (404).

### 5.2 Endpoint matrix

Status vocabulary: `existing-lib` (tested Orcel library code, not exposed), `new` (to build in the stated wave),
`unsupported` (answers 501 `UNSUPPORTED` until its wave), `blocked` (403 `POLICY_BLOCKED`, cloud-only or policy), `n/a`
(hosted SaaS concern; 404). MCP tools are `local_only` in Wave 1 (C-06; remote exposure is a later decision).

| # | Upstream route (v2; v1 alias) | Orcel MCP tool | Orcel backing | Wave | Status today | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `POST /v2/scrape`; `POST /v1/scrape` | `web_scrape` | fetch engine (WP1-08) or `BrowserWorker::extract_page` | W1 | new | Synchronous; one SOFT approval per request in Safe |
| 2 | `POST /v2/map`; `POST /v1/map` | `web_map` | `crawl.rs` map mode + `map_rank.rs` | W1 | existing-lib | `search` ranks via WI-02; `sitemap` include/skip/only |
| 3 | `POST /v2/crawl`; `POST /v1/crawl` | `web_crawl_start` | orcel-jobs + `crawl.rs`/`crawl_scope.rs` | W1 | existing-lib (crawl), new (async) | Returns `{ success, id, url }`; `url` is the loopback status URL |
| 4 | `GET /v2/crawl/{id}`; v1 alias | `web_job_status` | orcel-jobs store | W1 | new | Status mapping in 5.5; `next` cursor for pages |
| 5 | `DELETE /v2/crawl/{id}`; v1 alias | `web_job_cancel` | orcel-jobs | W1 | new | `{ status: "cancelled" }` only after executors confirm |
| 6 | `GET /v2/crawl/{id}/errors`; v1 alias | `web_job_errors` | `CrawlReport.skipped`, unit failures | W1 | existing-lib (report) | `robotsBlocked` from robots refusals |
| 7 | `GET /v2/crawl/ongoing`, `/v2/crawl/active` | `web_job_list` | orcel-jobs | W1 | new | Only this device's jobs |
| 8 | `POST /v2/batch/scrape` | `web_batch_scrape_start` | orcel-jobs + scrape | W1 | new | At most 100 URLs; one SOFT approval binds the URL list digest |
| 9 | `GET`/`DELETE /v2/batch/scrape/{id}`, `/errors` | `web_job_status`, `_cancel`, `_errors` | orcel-jobs | W1 | new | Same job API as crawl |
| 10 | `POST /v2/search`; `POST /v1/search` | `web_search` (exists) | `crates/orceld/src/search.rs` (BYOK, off by default) | W1 | existing (MCP) | Results only; `scrapeOptions` refused until W2 |
| 11 | `GET /v2/scrape/{jobId}` | `web_job_status` | orcel-jobs | W2 | unsupported | Async scrape result retrieval |
| 12 | `POST /v2/parse`, `GET /v2/parse/formats`, `POST /v2/parse/upload-url`, `PUT /v2/parse/upload/{uploadId}` | `document_parse` | `apps/orcel-doc-parser` under orcel-contain | W2 | existing-lib (parser) | Upload lands in a private staging dir; bounded |
| 13 | WebSocket crawl watcher (`crawl-status-ws`) | none | loopback WS over the job store | W2 | unsupported | SDK `watcher` |
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
`excludeTags`, `maxAge`, `minAge`, `headers`, `waitFor`, `mobile`, `skipTlsVerification`, `timeout`, `parsers`,
`actions`, `location`, `removeBase64Images`, `blockAds`, `proxy`, `storeInCache`, `lockdown`, `checkPromptInjection`,
`redactPII`, `profile`, `threatProtection`, `auditMetadata`, `zeroDataRetention`, `alexandria`, `maxCredits`,
`domainTools`, `toolDetail`. Upstream `formats` accepts strings or `{ type }` objects.

| Field | Orcel W1 | Later | Rule |
| --- | --- | --- | --- |
| `url` | yes | | Public HTTPS on port 443 only (SG-000075 rules; `web_fetch` rules for the fetch engine) |
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
| `actions` | no (501) | W2 | Each action maps to an existing SOFT-approved browser shape; none is approval-free in Safe |
| `blockAds` | no (ignored false) | W2 | Scrapling ad-domain list (BSD-3) as navigation blocklist data |
| `headers` | refused (400) | decision | Custom request headers can carry credentials; needs a policy decision |
| `skipTlsVerification` | refused (400) | never | Contradicts SG-000075 |
| `proxy: "stealth"`, `mobile`, `location` | refused (403 `POLICY_BLOCKED`) | FD-UP-2 | Fingerprinting and geo-spoofing |
| `proxy: "basic"` / `"auto"` | accepted as no proxy | | Local egress only |
| `storeInCache`, `zeroDataRetention` | accepted as no-ops | | Nothing leaves the device; nothing is cached in W1 |
| `profile`, `lockdown`, `checkPromptInjection`, `redactPII`, `threatProtection`, `auditMetadata`, `alexandria`, `maxCredits`, `domainTools`, `toolDetail`, `onlyCleanContent`, `minAge`, `removeBase64Images` | refused (400, named) | re-evaluated per wave | Hosted or model features |
| `orcel.engine` (extension) | yes | | `fetch` (default where the browser is unavailable), `chromium`; `obscura` W2. The result always names the engine that ran |

### 5.4 Map and crawl options

| Upstream field | Orcel W1 | Rule |
| --- | --- | --- |
| map `url`, `search`, `limit`, `includeSubdomains: false`, `ignoreQueryParameters` | yes | Same-origin only (`crawl.rs`); `includeSubdomains: true` refused (one admitted destination) |
| map `sitemap` (`include`, `skip`, `only`); v1 `ignoreSitemap`, `sitemapOnly` | yes | Existing sitemap reading (#317) |
| map `timeout` | yes | Capped by the crawl deadline |
| map `location`, `ignoreCache`, `threatProtection`, `auditMetadata` | refused / no-op | As 5.3 |
| crawl `url`, `includePaths`, `excludePaths`, `limit` (at most 1,000), `maxDiscoveryDepth` (at most 5); v1 `maxDepth` | yes | Existing `CrawlSpec` limits; filters narrow, the origin is the boundary |
| crawl `sitemap`, `ignoreQueryParameters`, `regexOnFullURL` | yes | WI-01 regex patterns exist |
| crawl `delay`, `maxConcurrency` | yes | orcel-jobs throttle; `maxConcurrency` capped at 4 |
| crawl `scrapeOptions` | yes, subset of 5.3 | |
| crawl `allowExternalLinks`, `allowSubdomains`, `crawlEntireDomain`; v1 `allowBackwardLinks` | `false` only | Wider scope needs a new admitted-destination rule |
| crawl `ignoreRobotsTxt: true`, `robotsUserAgent` | refused | Robots obedience is on (blueprint "rate/robots compliance") |
| crawl `webhook` | refused | No job egress in W1 |
| crawl `prompt` | 501 | Model, W3 |
| crawl `zeroDataRetention` | no-op | |

### 5.5 Status and response mapping

| Orcel job | Firecrawl `status` | `success` |
| --- | --- | --- |
| `not_started`, `dispatched` | `scraping` | true |
| `completed` + `Succeeded` or `Partial` | `completed` | true (`Partial` adds `warning`) |
| `completed` + `Failed` | `failed` | false, with `error` and `code` |
| `cancelled` | `cancelled` | true |
| `outcome_unknown` | `failed` | false, `code: "OUTCOME_UNKNOWN"` (never retried) |

`creditsUsed` is always `0`; `expiresAt` is the job store expiry; `total` and `completed` come from `JobProgress`. The
Document shape follows the SDK `Document` type (`markdown`, `html`, `rawHtml`, `links`, `screenshot`, `metadata`,
`changeTracking`, `warning`), plus `metadata.orcelEngine` naming the engine that ran.

### 5.6 Licence statement for this surface

The Firecrawl-compatible surface is new Apache-2.0 code in `crates/orcel-web`, `crates/orcel-jobs`, `crates/orceld`
and `apps/orcel-mcp`. It copies no line from AGPL Firecrawl files. Field names and route shapes are interface facts
taken from the MIT SDK types. `tests/firecrawl-compat` may adapt MIT SDK e2e tests
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
| `PATCH` | Upstream source carried with an Orcel patch, built in its own workspace | Upstream licence, NOTICE and a `PATCHES.md` listing every change |
| `REFERENCE` | Read for design only | none |

All rows below are at these SHAs: Crawlee `7bec9ad5631f8e529ae067494f6841dba3c12683` (branch `master`), Scrapling
`bb223f2f5fc8f743772751a5ce283ef7851ca6be`, Firecrawl `42f4d669954649ce33466a2a50e8215c7f1f4d1c`, Obscura
`0d9a2f764ffdb097269da048002c593865e83a9e`, agent-browser `53384771fbafc261ba67608ac806dd5aa70b84f0`, Browser Use
`4b5b1b0aa0ab45a1d6a2a31984d37d3e748c0134`. Every path was checked present in the upstream tree at that SHA on 2026-11-16.

### 6.2 Wave 1

| Upstream (repo: path) | Licence | Method | Orcel destination | Packet |
| --- | --- | --- | --- | --- |
| crawlee: `packages/core/src/storages/request-queue.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/queue.rs` | WP1-04 |
| crawlee: `packages/core/src/storages/request-dedup-cache.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/queue.rs` (unique key) | WP1-04 |
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
| orcel (own): `crates/orcel-browser-host/src/{crawl,crawl_scope,map_rank,change_tracking,robots}.rs` | Apache-2.0 (+ FD-06 notice where recorded) | reuse in place | called by `orceld` web dispatch | WP1-06 |

Full Control on Windows (WP1-10) and the contracts (WP1-02, WP1-03) import no donor file.

### 6.3 Wave 2

| Upstream (repo: path) | Licence | Method | Orcel destination | Packet |
| --- | --- | --- | --- | --- |
| obscura: whole tree at the pin (526 files), with `vendor/taffy` MIT, `vendor/cosmic-text` MIT OR Apache-2.0, `vendor/wreq-util` Apache-2.0, Noto Color Emoji OFL-1.1 | Apache-2.0 | PATCH | `third_party/obscura/` (separate workspace) | WP2-05 |
| obscura: `crates/obscura-cdp/src/server.rs`, `dispatch.rs`, `lib.rs` | Apache-2.0 | PATCH (add a pipe transport on fds 3/4 or Windows handles, Chromium `--remote-debugging-pipe` framing, NUL-delimited JSON; remove the TCP listener from the Orcel build) | `third_party/obscura/crates/obscura-cdp` | WP2-05 |
| obscura: `crates/obscura-cli/src/main.rs` | Apache-2.0 | PATCH (pipe mode flag; `serve` and `--stealth` compiled out with a cargo feature) | `third_party/obscura/crates/obscura-cli` | WP2-05 |
| obscura: `crates/obscura-net/src/wreq_client.rs`, `blocklist.rs`, `crates/obscura/tests/stealth_transport.rs` | Apache-2.0 | excluded (feature off) | none (C-19) | WP2-05 |
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
| Declared MSRV | 1.82 | root `Cargo.toml` `rust-version` |
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
| html5ever | =0.40.1 (MSRV 1.85) | MIT OR Apache-2.0 | `apps/orcel-doc-parser` workspace only | HTML parsing for the fetch engine, with an Orcel-owned minimal tree sink (no `markup5ever_rcdom`) |
| @mendable/firecrawl-js | 4.54.0 (exact, matching the pin) | MIT | `tests/firecrawl-compat` devDependency | Contract client |
| firecrawl-py | 4.57.0 (exact, matching the pin) | MIT | CI-only virtualenv, hashes in a lock file | Contract client (C-14) |
| Python (CI only) | 3.12.x from `actions/setup-python` | PSF | CI | Runs the Python contract leg |

No new dependency enters any `crates/*` unit in Wave 1: `orcel-jobs` and `orcel-web` use only `serde`, `serde_json`,
`sha2` and `fs4`, already in the workspace. Versions marked "checked" were read with `cargo info` on 2026-11-16; the
packet re-checks each version is at least 14 days old and records its SHA-256 in the lock file.

### 7.3 Planned for Wave 2 (re-verified when the packet starts)

| Item | Version | Notes |
| --- | --- | --- |
| Obscura | source at `0d9a2f764ffdb097269da048002c593865e83a9e` plus Orcel patches; trial may compare against release `v0.2.7` (tag commit `0ecc41770da5c5300227dd83a15bfa1e5100d5d4`, published 2026-11-13) | Built in CI; its V8 dependency fetches prebuilt static libraries at build time, which the packet must pin by hash or build from source |
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
| WP1-03 | Audit hash chain and `orcel audit verify` | WP1-02 | SG-000131 | all three |
| WP1-04 | `orcel-jobs` embedded queue | WP1-02 | SG-000102 | all three |
| WP1-05 | `orcel-web` Firecrawl-compatible schemas and translation (pure) | WP1-02 | SG-000101 | all three |
| WP1-06 | `orceld` web and job dispatch | WP1-03, WP1-04, WP1-05 | SG-000101 (scrape), SG-000102 (jobs) | Windows (chromium engine); all three (fetch) |
| WP1-07 | MCP tools and loopback Firecrawl REST routes | WP1-06 | SG-000101, SG-000102 | all three |
| WP1-08 | Fetch engine: HTML to Markdown in the contained parser | WP1-05 | SG-000101 | all three |
| WP1-09 | Firecrawl contract harness (JS and Python SDKs) | WP1-07, WP1-08 | SG-000101, SG-000102 | all three; Windows for the chromium leg |
| WP1-10 | Full Control dispatcher on Windows | WP1-02, WP1-03 | SG-000132 | Windows |
| WP1-11 | Wave 1 journeys J-1, J-2, J-3 and readiness update | all of the above | closeouts | Windows, plus founder-present runs |

### 8.2 Wave 1 packets in detail

Every packet: exact-head CI green on `ubuntu-latest`, `windows-latest` and `macos-latest` (existing `ci.yml` legs),
Review Gates (Jev semantic review, Alibaba OpenCodeReview delegation) green, zero unresolved threads, and a
fresh-context security judge where marked. d1-local is advisory only.

#### WP1-00 Governance

- **Scope:** move the approved draft JSONs from `prep/unified-grains/` into `.specgrain/specs/` with
  `state: "GRAIN"`, record the founder go-ahead in `CURRENT.md`, update the open-grain pins. Correct
  `DONOR_REGISTRY.md` and `donor_registry.json` for Firecrawl (`REFERENCE_ONLY_SO_FAR` is stale, inventory section 3.7).
- **Definition of done:** governance CI green; no code, dependency, tool or authority change.
- **Tests:** existing governance checks; `node scripts/check-current-identity.mjs`.

#### WP1-01 Licence and dependency-direction gates

- **Scope:** a root `deny.toml` for the main workspace (licences, bans, sources) mirroring the four per-app files;
  allowlist `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `0BSD`; deny `AGPL-*`,
  `GPL-*`, `LGPL-*`, `SSPL-*`, `BUSL-*` and unknown licences in every `crates/*` unit; `MPL-2.0` allowed only by named
  exception. `scripts/check-npm-licenses.mjs` reads every `package-lock.json` under `apps/`, `packages/` and `tests/`
  and applies the same allowlist (test-only packages may add `PSF-2.0` for Python tooling). A `cargo metadata` test
  enforcing section 3.2's rules. A text scan refusing the strings `GNU AFFERO` and `SPDX-License-Identifier: AGPL` under
  `crates/` except in the FD-06 files already listed in `docs/orcel/notices/`.
- **Definition of done:** the gates run on every PR; current `main` passes; a fixture crate with an AGPL dependency fails.
- **Tests:** `cargo deny check licenses bans sources` (root); `node --test scripts/check-npm-licenses.test.mjs`;
  `cargo test -p orceld --test dependency_direction`.
- **CI:** all three OS legs (licences are OS-independent, but `cfg` dependencies differ).

#### WP1-02 Contracts v1

- **Scope:** section 4 types in `orcel-contracts`; move `AuthorityMode`, `ExecutorClass`, `ExecutionState` with
  re-exports; `canonical_json`; golden fixtures; JSON Schema generation test; the eight new `FailureCode` variants.
- **Definition of done:** every type round-trips its golden fixture; unknown fields refused on inbound
  authority-bearing types; frozen spellings pinned; `orcel-policy` tests unchanged and green; no behaviour change.
- **Tests:** `cargo test -p orcel-contracts` (round-trip, unknown-field refusal, frozen spellings, canonical JSON
  vectors including key order and Unicode escapes); `cargo test -p orcel-policy` (unchanged).
- **CI:** all three.

#### WP1-03 Audit hash chain

- **Scope:** section 4.8 in `orcel-audit`; `orceld` records `request`, `decision`, `approval`, `dispatch`, `state`, `lease`
  and `emergency_stop` events; `orcel audit verify`.
- **Definition of done:** every dispatch in the existing test suites leaves a verifiable chain; editing, deleting or
  reordering one line is detected at that line; rotation keeps continuity; no raw SID, token, secret or page content in
  any event (asserted by a redaction scan over the test logs).
- **Tests:** `cargo test -p orcel-audit chain_`; `cargo test -p orceld audit_chain_`; redaction scan.
- **CI:** all three. **Security judge:** yes (audit is evidence for C-05).

#### WP1-04 orcel-jobs

- **Scope:** section 4.11 modules; state machine of 4.7; bounds; checkpoint and resume; result store with expiry.
- **Definition of done:** a job survives an `orceld` restart with `dispatched` units reported `outcome_unknown`, never
  re-run silently; per-origin delay honoured within 10 ms of the configured value on all OSes; retries only for
  read-only units and only for retryable failures; store bound and expiry enforced; no thread spins when idle.
- **Tests:** unit tests per module; property tests for the state machine (no transition outside the table);
  throttle and backoff vectors re-derived from the Crawlee tests listed in 6.2; crash-resume test that kills the
  process between unit start and finish.
- **CI:** all three.

#### WP1-05 orcel-web

- **Scope:** v2 and v1 request types, refusal of every unsupported field by name, translation to `RequestEnvelope` and
  `CrawlSpec`, Document shaping, status mapping of 5.5.
- **Definition of done:** every row of 5.3 and 5.4 has a test; unknown top-level fields refused (upstream also uses
  strict schemas); v1 field names (`maxDepth`, `allowBackwardLinks`, `ignoreSitemap`, `sitemapOnly`, string `formats`,
  `parsePDF`) translate to the same envelope as their v2 equivalents.
- **Tests:** `cargo test -p orcel-web` with request fixtures written from the MIT SDK types.
- **CI:** all three.

#### WP1-06 orceld web and job dispatch

- **Scope:** capabilities `web.scrape`, `web.map`, `web.crawl`, `web.batch_scrape`, `job.status`, `job.cancel`,
  `job.errors`, `job.list`. Engines: `fetch` everywhere; `chromium` where the browser host can launch (today Windows
  `live-browser-dev` builds; macOS and Linux after SG-000115). Capability report entries for each engine and OS.
  Safe mode: one SOFT approval per scrape bound to (URL, engine, formats) digest; one SOFT approval per crawl or batch
  bound to the full spec digest (FD-UP-5 confirms this granularity); every page navigation still governed by SG-000075;
  existing `browser_*` shapes and their approvals untouched.
- **Definition of done:** a refused or unsupported option never dispatches; a job approval cannot be replayed for a
  different spec; cancel and emergency stop reach running units; the engine that ran is in every result and audit event;
  release builds report `chromium` as `unavailable` with the existing typed reason.
- **Tests:** `cargo test -p orceld web_` (policy, approvals, digest binding, cancel, unsupported); fixture-origin tests
  using the existing test-only fixture pinning (SG-000108) for the chromium engine on Windows; the fetch engine against
  a local TLS fixture admitted only in test builds.
- **CI:** all three; Windows native for chromium. **Security judge:** yes.

#### WP1-07 MCP tools and loopback REST

- **Scope:** `tool_contract.ts` entries `web_scrape`, `web_map`, `web_crawl_start`, `web_batch_scrape_start`,
  `web_job_status`, `web_job_cancel`, `web_job_errors`, `web_job_list` (all `local_only`, effect `network`, approval
  `SOFT`, `openWorldHint: true`); loopback REST routes for the W1 rows of 5.2 on the existing loopback server, reusing
  its bind, `Host`, `Origin`, bearer and body-bound checks; v1 aliases.
- **Definition of done:** the catalog, discovery, OAuth scope tables and runtime agree (extend `tool-contract.test.ts`
  and `surface.test.ts`); no route outside the W1 rows answers anything but 404 or 501; the REST front holds no state
  beyond the MCP session table.
- **Tests:** `npm test` in `apps/orcel-mcp` (`loopback-http.test.ts` extended for the new routes, token, host and origin
  refusals, body bounds).
- **CI:** all three.

#### WP1-08 Fetch engine

- **Scope:** `apps/orcel-doc-parser` gains format `html` (sniffed, refused if not HTML); Rust port of Orcel's worker
  extraction (main content, headings, lists, links, code, tables) with an Orcel tree sink on `html5ever`; `orceld`
  composes `web_fetch` (1 MiB, public HTTPS, SG-000040 guard) then the contained parser.
- **Definition of done:** Markdown output matches the worker's extraction on the existing extraction fixtures within a
  documented normalisation; the parser runs with no network and no process creation under orcel-contain on all OSes;
  malformed and hostile HTML bounded in time and memory.
- **Tests:** `cargo test` in `apps/orcel-doc-parser` (`html_tests.rs`, shared fixtures with
  `apps/orcel-browser-worker/src/extract/extract.test.ts`); fuzz corpus run in CI for 60 s.
- **CI:** all three (Document parser job).

#### WP1-09 Firecrawl contract harness

- **Scope:** `tests/firecrawl-compat` runs the JS SDK 4.54.0 and the Python SDK 4.57.0 against a test build of Orcel on
  the loopback with a fixture origin; one test per W1 matrix row and per W1 option row; a parity report
  `tests/firecrawl-compat/report.json` listing each row as `passed`, `failed` or `unsupported`.
- **Definition of done:** every W1 row passes on all three OSes with the fetch engine and on Windows with chromium; the
  SDKs' own error handling surfaces Orcel refusals as their typed errors; the report is attached to the CI run.
- **CI:** all three; Windows for the chromium leg.

#### WP1-10 Full Control dispatcher on Windows

- **Scope:** `crates/orceld/src/full_control_dispatch.rs`, the only path that dispatches an executor under a lease:
  load lease, re-read the native identity, check every binding (C-02), check `executor_enabled_now`, write the
  dispatch audit event (C-05), dispatch, record the state. Migrate the existing DesktopInput path (SG-000095) onto it;
  SG-000096 shell sessions and SG-000097 filesystem (when activated) consume it. Emergency stop: epoch advance, cancel
  in-flight jobs, kill sidecars, report states.
- **Definition of done:** no executor under a lease is reachable except through the dispatcher (a test enumerates
  dispatch call sites); with no lease every Safe path is unchanged (C-04: golden request/response pairs for
  `process_spawn`, the registry and the browser shapes); every Full Control dispatch has an audit event with lease id,
  digest and epoch; stop reaches a running dispatch within 1 s on the Windows runner.
- **Tests:** `cargo test -p orceld full_control_dispatch_`; `cargo test -p orcel-policy` (SID and logon mismatch,
  epoch drift, policy drift, expiry); Windows native CI issuing a lease from real host values (existing pattern).
- **CI:** Windows native required; Linux and macOS prove `LEASE_UNSUPPORTED_PLATFORM`. **Security judge:** yes.

#### WP1-11 Wave 1 journeys

- **Scope:** run J-1, J-2 and J-3 (section 10); update `README.md`'s capability table and `RELEASE_READINESS.md` with
  what is qualified and on which builds; grain closeouts.
- **Definition of done:** the gates of section 10.2 that apply to Wave 1 pass; founder-present runs recorded where a
  real approval through a real client is required, otherwise stated as pending (F4 slice 4 precedent).

### 8.3 Wave 2 packets

| Packet | Title | Prerequisites | Definition of done (summary) | Tests | CI |
| --- | --- | --- | --- | --- | --- |
| WP2-01 | Per-OS identity binding (macOS, Linux) and `orcel-full-control-lease/2` | WP1-10 | Leases on macOS and Linux bind uid plus audit session or logind session; v1 leases invalidated, not converted | identity readers on real runners; mismatch denial | macOS, Linux native |
| WP2-02 | `orcel-sidecar` host and sandbox profiles | WP1-02 | Section 4.9 implemented; Job Object / Seatbelt / cgroup+seccomp+Landlock profiles; listener check; kill paths | handshake, heartbeat loss, cancel, host death, listener refusal per OS | all three native |
| WP2-03 | macOS and Linux qualification of the core and Full Control executors | WP2-01, WP2-02, SG-000115 | Shell, filesystem and desktop executors under lease on macOS 15 arm64 and Ubuntu 24.04 / Fedora 41 | journey J-4 on each OS | macOS, Linux native; founder-present desktop runs |
| WP2-04 | Browser engine abstraction, capture contract, Chromium default | WP1-06 | `engine` trait; screenshot, PDF, multi-tab contract; engine reported per task | engine contract tests on Chromium | Windows; macOS and Linux after SG-000115 |
| WP2-05 | Obscura patched build and adapter (pipe CDP, broker fetch, no stealth, no MCP) | WP2-02, WP2-04, FD-UP-6 | Obscura launches only via pipe under orcel-sidecar; zero listening sockets; every request fulfilled by the host broker | upstream tests in `third_party`; listener scan; broker-only traffic test | all three |
| WP2-06 | Measured Obscura corpus trial | WP2-05, WP2-07 | Corpus result per engine per site; Obscura marked qualified per capability only where it passes; Chromium fallback automatic and reported | `tests/browser-corpus` both engines | all three |
| WP2-07 | agent-browser parity port and corpus | WP2-04 | Snapshot refs identical across engines; hover, drag, scroll, double-click, tabs, frames | ported parity and e2e tests | Windows first |
| WP2-08 | Extraction metadata, ad blocking, adaptive selectors | WP2-04 | Microdata, OpenGraph, social; `blockAds`; optional adaptive selectors | extraction fixtures | all three |
| WP2-09 | REST/OpenAPI generated from the MCP catalog | WP1-07 | `/api/v1/*` from `tool_contract.ts`; OpenAPI 3.1.0 checked in; drift test | schema drift; route tests | all three |
| WP2-10 | TypeScript SDK `@orcel/sdk` | WP2-09 | Generated client; README examples run in CI against a test build | SDK tests | all three |
| WP2-11 | Firecrawl W2 rows (screenshot, actions, parse, async scrape, watcher, queue status, cache) | WP2-04, WP2-07 | Rows 11 to 14 of 5.2 pass the harness | harness | all three |

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
| Windows | Windows 10 version 1809 (build 17763) or later, or Windows 11, x64 (`README.md`) | Windows 11 on the founder's PC; `windows-latest` (Server 2025) | `windows-latest` | Full Control lease identity (`TokenUser`, `TokenStatistics`) is available on the floor; Windows arm64 is not claimed |
| macOS | macOS 15.0 Sequoia, Apple Silicon (arm64) only (`MACOS_M0_READINESS.md` section 4) | macOS 15 and macOS 26 | `macos-latest` (arm64); a `macos-15` leg is added when a packet changes OS-specific code | Intel deferred; unsigned development builds only until FD-05; TCC grants are lost per rebuild |
| Linux | Ubuntu 24.04 LTS and Fedora 41, x86_64 (`ROADMAP.md` X5) | Same | `ubuntu-latest` plus Fedora 41 container for install tests | Kernel with Landlock ABI 3 or later (6.2+; both floors ship newer); cgroup v2; arm64 qualified later |
| Linux desktop | GNOME 46+ and KDE Plasma 6, Wayland and X11 sessions | Interactive runs (XP-10) | none hosted | Wayland input and capture go through portals and need per-session consent; X11 is the fallback |
| Android (W3) | Any device exposing adb over USB or a user-paired wireless debugging session | Founder's device | none hosted | Host side runs on all three desktop OSes |
| iPhone (W3) | iOS 18+ mirrored to macOS 15+ | Founder's devices | none hosted | No Windows or Linux iPhone claim |

## 10. Acceptance journeys and release gates

### 10.1 User journeys

| Journey | Wave | What a person does | Pass criteria |
| --- | --- | --- | --- |
| J-1 | W1 | Points the Firecrawl JS SDK at their local Orcel and scrapes, maps and crawls a public documentation site | Results returned through App-visible approvals; engine named; robots and politeness honoured; `orcel audit verify` clean |
| J-2 | W1 | Asks an MCP client to crawl a site, then cancels mid-way | Job reaches `cancelled` within 2 s; no page fetched after the cancel is acknowledged; partial results readable |
| J-3 | W1 | Grants Full User on Windows, has an agent run a shell build and edit files, then presses emergency stop | Every dispatch audited with lease id, digest and epoch; stop ends the running process within 1 s; the next call fails `LEASE_INVALID` |
| J-4 | W2 | J-3 on macOS 15 arm64 and Ubuntu 24.04 GNOME | Same criteria; OS consent prompts appear as the OS shows them |
| J-5 | W2 | Runs one browser task on Obscura and the same on Chromium | Same result or an explicit difference report; engine named; Chromium fallback reported |
| J-6 | W2 | Calls the same intent through App, MCP and REST/SDK | Identical policy decisions and audit kinds; missing privilege reported precisely |
| J-7 | W3 | Drives an owned Android phone from Orcel on each desktop OS, and an owned iPhone via iPhone Mirroring on a Mac | Consent visible; actions audited; unsupported combinations report `unsupported` |
| J-8 | W3 | Views and controls their own desktop from a paired device over the self-hosted relay | No anonymous path; presence indicator; stop and revoke work |

### 10.2 Release gates (measurable)

| Gate | Measure | Applies from |
| --- | --- | --- |
| G-1 Contract integrity | Golden fixtures and schema drift tests green; frozen spellings unchanged | W1 |
| G-2 Licence | Root and per-app `cargo deny` and the npm licence check green; zero AGPL/GPL/LGPL in `crates/*` dependency graphs; NOTICE and licence files present for every ported file | W1 |
| G-3 Authority | 100% of Full Control dispatches in the test suites have a matching audit event with lease id, digest and epoch; Safe golden pairs unchanged; no executor reachable outside the dispatcher | W1 |
| G-4 Isolation | Zero listening sockets owned by Orcel children other than the documented loopback MCP/REST server, measured by a per-OS socket scan during the journeys | W1 (browser), W2 (all sidecars) |
| G-5 Parity honesty | Every capability report entry and parity matrix row is backed by a passing test or reports `unsupported` / `blocked`; the harness report has no `failed` row for a claimed wave | W1 |
| G-6 Cancellation and stop | Cancel to `cancelled` within 2 s; emergency stop to process death within 1 s (Windows W1; all OSes W2) | W1 |
| G-7 Resource budget | Idle `orceld` with the queue empty stays within the SG-000127 memory budget; a 100-page crawl stays under 400 MB resident across Orcel processes, excluding the browser engine (proposed threshold, to be confirmed by the first measured run) | W1 |
| G-8 Cross-platform | All three CI legs green; native journeys recorded for each claimed OS; nothing claimed for an OS without its journey | W2 |
| G-9 Release provenance | Existing release workflow gates (listed files only, SBOM, attestation); the live browser in release builds only after F4 slice 7 is decided; agents never approve the `release` environment | every release |
| G-10 Real consent | Journeys that need a person's approval through a real client are run by the founder or recorded as pending; scripted consent is labelled as such | every wave |

## 11. Founder decisions needed

1. **FD-UP-1 Firecrawl approach.** (a) Recommended: reimplement the Firecrawl v2 contract (with v1 aliases) in
   Apache-2.0 Orcel code, shapes taken from the MIT SDKs, contract-tested with those SDKs; existing FD-06 ports stay
   as they are. (b) Additionally allow an optional, separately distributed AGPL Firecrawl server sidecar, never bundled
   or default. (c) Pursue a copyright-holder-signed grant from Firecrawl before any further Firecrawl-derived code.
2. **FD-UP-2 Stealth and fingerprinting policy.** Whether Orcel may ever offer bot-detection evasion (Obscura `--stealth`,
   Scrapling stealth and `curl_cffi`, Crawlee fingerprints and impersonating clients, Firecrawl `proxy: "stealth"`,
   `mobile`, `location`). Until decided, all are BLOCKED and compiled out.
3. **FD-UP-3 "Vercel agent-use" identity.** Confirm whether it means `vercel-labs/agent-desktop` at
   `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad` (Apache-2.0, macOS AX / Windows UIA / Linux AT-SPI), another repository,
   or nothing. Until then no code is admitted and Track 1 keeps the vendored Cua path.
4. **FD-UP-4 Grain activations.** Approve activating, in this order: SG-000131 (contracts, audit chain, licence gates;
   new id), SG-000101 (Firecrawl-compatible scrape and fetch engine) and SG-000102 (jobs, crawl, map, batch), both reusing
   P20-reserved ids and roles out of the sequential order recorded in `docs/p20/sg000092_architecture_freeze.json`
   ("SG-000093 through SG-000107 remain absent until sequential activation"), and SG-000132 (Full Control dispatcher on
   Windows; new id). Alternatively allocate new ids (SG-000133, SG-000134) and keep SG-000101 and SG-000102 for P20.
   Also: whether SG-000097 (full filesystem) is activated in Wave 1 to consume the dispatcher, and confirmation that
   SG-000096 continues as the shell-session consumer.
5. **FD-UP-5 Job approval granularity in Safe mode.** Confirm one SOFT approval per crawl or batch job bound to the
   full spec digest (start URL, scope, filters, limits, engine), with every page still governed by SG-000075, as a new
   action shape that leaves existing `browser_*` approvals unchanged; or require per-page approval.
6. **FD-UP-6 Carrying a patched Obscura.** Approve maintaining an Orcel patch (pipe CDP transport, stealth and MCP
   compiled out) on pinned Obscura source in `third_party/obscura`, and building V8 artefacts reproducibly, as the only
   way Obscura ships; or limit Obscura to a CI-only corpus trial until upstream offers a pipe transport.
7. **FD-UP-7 Web tools in release builds.** Whether the fetch engine (no browser) may make `web_scrape`, `web_map` and
   `web_crawl_start` available in release builds on all three OSes in Wave 1, while the chromium engine stays
   development-only until F4 slice 7 is decided.
8. **FD-UP-8 Custom request headers.** Whether Firecrawl `headers` may ever be honoured (they can carry credentials and
   cookies); refused until decided.

## 12. Draft grains and what this document does not do

Draft grain JSONs (state `DRAFT`, not activations) are in [`unified-grains/`](unified-grains/):

| File | Grain | Packets |
| --- | --- | --- |
| `SG-000131.draft.json` | Unified platform contracts v1, audit hash chain and licence gates (inert) | WP1-00 to WP1-03 |
| `SG-000101.draft.json` | Firecrawl-compatible scrape over MCP and loopback, fetch engine, contract harness | WP1-05, WP1-06 (scrape), WP1-07, WP1-08, WP1-09 |
| `SG-000102.draft.json` | Embedded job queue; async crawl, map and batch scrape | WP1-04, WP1-06 (jobs), WP1-07, WP1-09 |
| `SG-000132.draft.json` | Full Control dispatcher on Windows | WP1-10 |

This document does not: activate any grain; import, copy or build any donor code; add any dependency; decide any
licence question; claim any capability as qualified; change README or release claims; or replace the canonical
SG-000093, SG-000108, SG-000010 or SG-000060 records, which remain authoritative where they differ from this draft.
