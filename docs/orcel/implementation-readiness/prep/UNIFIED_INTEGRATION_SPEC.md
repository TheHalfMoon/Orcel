# Orcel unified platform: integration specification (EGM draft)

**Status: DRAFT SPECIFICATION, DOCS ONLY (revision 8, founder decisions encoded).** This document activates no grain,
imports no donor code, adds no dependency, tool, listener or authority, and changes no canonical state. Every packet
below needs its own activated grain, exact-head qualified PR, review gates and, where it touches authority, a
fresh-context security judge. Activation-ready grain JSONs live in [`unified-grains/`](unified-grains/), not in
`.specgrain/specs/`; the activation PR is the next step (WP1-00).

- **Revision 6 (2026-11-17)** encodes the founder's answers to FD-UP-1 to FD-UP-13 as DECIDED (section 11) and
  restructures the plan around them: copy-first Firecrawl parity with an isolated AGPL component, a policy gate for
  sensitive web features, credential headers, configurable crawl budgets, final grain ids (SG-000131, SG-000132,
  SG-000133, SG-000134, plus SG-000097 activated and SG-000096 continued), a parallel macOS/Linux track, the patched
  Obscura build authorized now, and a new Full Control architecture (sections 4.13 to 4.15) that keeps comprehensive
  computer use working on the user's desktop while Orcel's authority lives outside the user session.
- **Revision 7** applies the security review of `4e0f3606` (pipe anti-squatting, service-owned Job Objects, audit records as session-asserted claims, the grant window after a service-observed unlock, and two disclosure nits); section 13.5 maps them.
- **Revision 8** applies the two nits of the review of `d6f2b3ba` (`READ_CONTROL` for the client owner check; grant intent plus a service-rendered confirmation, with the residual stated in C-27 (f)); section 13.6.
- Revisions 2 to 5 resolved two rounds of fresh-context review; their tables are kept in section 13 as history. Where
  revision 6 replaces a design they record (notably the restricted-token executor profiles S and D of revision 4),
  the current text governs and section 13.4 says so.
- **Base:** branch `plan/donor-inventory` (`c72d33fa`); `origin/main` is now `1f0b2d4658f0420aaedb5d1e14fb2a1a2de83095`.
- **Inputs:** the founder blueprint and pins from PR #785; [`DONOR_INVENTORY.md`](DONOR_INVENTORY.md) and
  [`capability_inventory.json`](capability_inventory.json); the SG-000010, SG-000019, SG-000040, SG-000060, SG-000064,
  SG-000093 and SG-000108 records; `docs/canonical/CURRENT.md`; `docs/p20/sg000092_architecture_freeze.json`; the code
  in `crates/orcel-contracts`, `orcel-policy`, `orcel-lifecycle`, `orcel-provider-network`, `orcel-provider-uia`,
  `orcel-browser-host`, `orceld`, `apps/orcel-browser-worker`, `apps/orcel-doc-parser`, `apps/orcel-mcp`,
  `apps/orcel-contain` and `apps/orcel-computer-host`; and the founder attestation
  [`docs/orcel/grants/2026-11-17-founder-attestation.md`](../../grants/2026-11-17-founder-attestation.md).
- **Upstream facts** were read on 2026-11-16 and 2026-11-17 with `gh api` at the exact SHAs named. No donor was cloned,
  built or run.
- **Vocabulary.** MUST and MUST NOT bind the packets. `C-nn` constraint, `WPw-nn` work packet (`WPX-nn` parallel
  cross-platform track, `WPB-nn` parallel browser-engine track), `J-n` journey, `G-n` gate, `FD-UP-n` founder decision.

## Contents

1. Binding design constraints
2. Architecture
3. Crates and packages
4. Contracts and designs
5. Firecrawl parity matrix
6. Donor file to destination mapping
7. Dependency versions
8. Packets and order
9. Platform floors
10. Acceptance journeys and release gates
11. Founder decisions (DECIDED 2026-11-17)
12. Grain drafts and what this document does not do
13. Review and decision history

## 1. Binding design constraints

### 1.1 Authority

- **C-01. One permission-mode model.** SG-000093 is the only mode model: `Safe` (sole default), `Full User`,
  `Full Admin`, `Persistent Admin` (SG-000099) and `Remote Full Control` (SG-000105). The blueprint's names map onto it:
  Observe and Workspace are `Safe` plus per-action approvals; local Full Control is `Full User` (or `Full Admin` with an
  `AdminLease` and an OS elevation); remote Full Control is `Remote Full Control`; headless jobs run under whichever mode
  admitted them.
- **C-02. Leases bind exactly** the OS user identity, the interactive logon session, the device, the Orcel session,
  the authority profile, the policy revision, the authority epoch, issue time and bounded expiry (60 s to 12 h). Any
  mismatch fails closed. Emergency stop advances the epoch.
- **C-03. Only the local user, proven present, mints authority.** Leases, renewals and standing approvals are issued by
  the Orcel authority service (section 4.13) after a STRONG presence proof (Windows Hello signature over a service
  challenge; macOS LocalAuthentication; Linux polkit). No agent, MCP or REST caller, donor runtime, relay or remote
  principal can mint, widen, renew, persist or convert authority, and the keys that sign it are outside the user session.
- **C-04. Approvals.** A lease alone never replaces a per-action approval. Repeated actions inside a trusted session are
  covered only by an explicit **standing approval** (section 4.15, FD-UP-10 decided): bound to the identified client,
  the declared task, the scope and an expiry, granted with STRONG presence, audited per dispatch, ended by stop. Full
  Control never loosens the SG-000010, SG-000060, SG-000040 or SG-000108 rules that apply in `Safe` mode; every Full
  Control packet proves that with no lease the Safe path is byte-for-byte unchanged.
- **C-05. Every Full Control dispatch is authorized and audited by the authority service first**, with the opaque lease
  id, binding digest, authority epoch, client principal and (if used) standing approval id, and never raw SIDs, tokens
  or credentials. No authorization record means no dispatch.
- **C-06. The gateway is `orceld`; the authority is the authority service.** Fronts (`apps/orcel-mcp`, loopback REST,
  relay uplink, desktop app) hold no authority. `orceld` decides policy, approvals and dispatch for the user session;
  every Full Control dispatch additionally needs the service's authorization.
- **C-07. Agent runtimes are untrusted callers** (`apps/orcel-agent`, MCP clients, SDK users, donor agent loops).
- **C-08. Fallback is never silent.** Broader-authority fallback never happens automatically; engine fallback (Obscura
  to Chromium/Playwright) is reported in the result and audit and never crosses an approval or capability boundary.

### 1.2 Full Control: comprehensive by design, authority out of reach (FD-UP-9 decided)

- **C-25. Full Control gives comprehensive computer use.** Under a Full User lease the agent can use every shell
  (PowerShell 5.1 and 7, cmd, Git Bash, WSL bash on Windows; zsh and bash on macOS; bash and zsh on Linux), the
  filesystem across the drives and roots the user authorizes, application launch and management, windows, mouse and
  keyboard, browser automation, processes, git and long-running automation, and remote use when separately authorized
  (SG-000105). Executors run **on the user's desktop with the user's normal token**, so GUI applications they start are
  visible and usable, and UI Automation works as it does for the user.
- **C-26. Orcel's authority is held outside the user session.** The authority key, lease store, authority epoch,
  standing approvals, the Full Control audit chain and its Event Log anchor live in the authority service, which runs
  under its own service identity with state the user session cannot read or write. An agent with Full Control acts
  with the user's rights and therefore cannot reach them. This replaces the revision 4 and 5 restricted-token profiles.
- **C-27. Stated OS limits (unavoidable).** Under Full Control the agent has the user's own rights in the user's
  session, so: (a) anything it does through the OS outside Orcel's process trees (scheduled tasks, WMI, DCOM, startup
  items, other programs it drives) can persist after stop, and Orcel cannot undo effects already made; (b) it can read
  whatever the user can read, including other programs' data; (c) it can kill or obscure user-session Orcel processes,
  including the indicator, and imitate its heartbeat, so the heartbeat proves nothing against a same-user agent; (d) a
  Windows Hello PIN can be observed by code running in the session, including code an agent persisted during an earlier
  session (a), so a later grant's PIN entry is not private; biometric Hello is recommended and the grant prompt says so;
  (e) during a lease the agent can talk to the authority service as if it were `orceld`, so what an `Authorize` request
  says it will run is a claim by the session: the Full Control audit is tamper-evident, out-of-session storage of
  session-asserted claims plus the facts the service observes itself (caller SID, logon session, process id and image,
  time, Job Object), not proof of what ran; (f) any process with the user's rights can record a grant intent (with any
  scope) and call `LockWorkStation`, so after the user's next unlock a grant confirmation can appear that the user did
  not ask for, and such a process can draw windows that cover or imitate it; the user must read the scope in the
  service's own "Orcel Authority" confirmation and approve only what they asked for, and Windows Hello still needs the
  user's own gesture. Every intent, confirmation answer and grant is in the Event Log (4101, 4102), the intent expires
  after 5 minutes, and only one is pending per session. Orcel's guarantees are therefore: no self-grant, self-renewal or
  self-escalation; tamper-evident, out-of-session audit of every request Orcel's authority admitted; stop and expiry
  that end Orcel authority and kill every process tree in a service-owned Job Object; grants and renewals only while no
  Full Control lease is active and only after a service-observed unlock; and honest disclosure in the grant prompt of
  (a) to (f).
- **C-28. Stop cannot be blocked from the user session.** The service ends Full Control on: the indicator's Stop
  button, the `orcel` CLI, lease expiry, session lock (Ctrl+Alt+Del then Lock, or Win+L; the service receives the session
  change itself), sign-out and service-side heartbeat loss. Stop advances the epoch and terminates every Orcel executor
  Job Object, which the service holds open.
- **C-29. Audit is anchored outside the session.** The service writes the Full Control audit chain to its own
  protected directory and anchors it in the Windows Event Log under a source it registered at install. `orceld`'s own
  Safe-mode chain (WP1-03) is anchored the same way, or per user without registration where the service is absent.
- **C-30. Authorization is atomic.** The service checks the lease, epoch, standing approval and principal, appends the
  audit record, registers the Job Object and returns the decision under one lock; stop takes the same lock.

### 1.3 Isolation of donor runtimes

- **C-09. Every donor-derived runtime runs as a supervised child of a Rust host** with Job Object (Windows),
  Seatbelt (macOS), or cgroup v2, seccomp and Landlock (Linux), as `apps/orcel-contain` does today.
- **C-10. Host-built argv, scrubbed environment, launch from the hashed handle.**
- **C-11. Private stdio or anonymous-pipe IPC only; no listening sockets**; inherited handles limited by
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` or `close_range`; donor MCP servers, HTTP listeners and CDP ports disabled.
- **C-12. Obscura speaks CDP over a pipe** through the Orcel patch authorized by FD-UP-6 (section 6.3, WPB-02).
- **C-13. Web sidecars and the Firecrawl component have no ambient network**: pages arrive through Orcel's governed
  fetch or the browser host; the component only transforms bytes.
- **C-14. Port or copy into existing runtimes; ship no new language runtime in the core.** Python and Go stay outside
  the shipped core (the existing Go native host and Python agent are separate programs). The Firecrawl extract logic
  copied in Wave 2 runs on the already-pinned Node runtime inside the isolated component.

### 1.4 Licensing (FD-UP-1 decided)

- **C-15. Founder attestation recorded separately.** The founder confirms full permission to copy and adapt authorized
  donor code, including Firecrawl, Browser Use and authorized private repositories
  (`docs/orcel/grants/2026-11-17-founder-attestation.md`). It is recorded beside, not instead of, the upstream licence
  terms in `DONOR_INVENTORY.md`.
- **C-16. The core stays independently licensed.** `crates/*` and the Apache-2.0 apps contain Orcel's own code, the
  already-recorded FD-06 files (`crawl_scope.rs`, `map_rank.rs`, `change_tracking.rs`, `apps/orcel-doc-parser`), and
  permissively licensed ports with their notices.
- **C-17. Copy-first Firecrawl code lives in an isolated AGPL component.** `apps/orcel-firecrawl` is a separate cargo
  workspace and a separately packaged program, licensed AGPL-3.0 as upstream, with the upstream LICENSE, NOTICE,
  `PROVENANCE.json`, `PATCHES.md` and a corresponding-source offer (the public repository at the release tag plus a
  source archive attached to each release). Orcel talks to it only over a JSON-over-stdio protocol under orcel-contain
  (section 4.17). No kernel crate links it.
- **C-18. Fleet:** reporting adapter only, from MIT parts; nothing from `ee/`. **UU Remote:** no source; remote desktop
  is built on the SG-000057 relay and WebRTC later.
- **C-19. Sensitive web features are opt-in, not blocked** (FD-UP-2 decided, section 4.16).
- **C-20. Licence and provenance gates run in CI per crate, package and component** (WP1-01).

### 1.5 Web policy (FD-UP-2, 5, 8, 11 decided)

- **C-31. Sensitive web features are configurable, OFF by default, per-client permission, audited, and never bypass
  security.** Privacy and compatibility features may be on by default; fingerprint, TLS-impersonation, proxy, geo and
  device-emulation features are off by default and need a per-client permission granted from the local control path.
  CAPTCHA solving, login or paywall bypass, access-control evasion and ignoring a site's robots rules are never offered.
- **C-32. Custom request headers are supported** with credentials held in the OS secret store, per-client permission,
  destination scoping (dropped on any cross-origin redirect) and redaction in logs and audit.
- **C-33. One approval per crawl or batch job**, bound to the client principal, the declared task, the destination
  scope and the parameters; every page is still checked against the destination scope and its resolved addresses.
- **C-34. Crawl budgets are user-configurable** with sensible defaults; the only fixed limits are resource protection.

### 1.6 Scope and sequencing

- **C-21. All founder goals retained; only ordered.** **C-22. Acceptance by user journeys.** **C-23. A claim needs a
  test; capability discovery reports `unsupported` explicitly.** **C-24. Existing work is extended, not replaced.**

## 2. Architecture

```text
 UNTRUSTED CALLERS: desktop app | orcel CLI | MCP clients | SDKs | apps/orcel-agent
        | MCP stdio | MCP loopback + MCP token | REST loopback + per-client REST token | relay
        v
 STATELESS FRONTS (no authority): apps/orcel-mcp (catalog, MCP tools, Firecrawl v1/v2 REST)
        | private pipe, RemoteRequestEnvelope
        v
 orceld (user session): policy -> approvals -> capability report -> job queue -> dispatch -> Safe audit chain
        |                                    \
        | Full Control: Authorize RPC         \ supervised children (contained, no ambient network)
        v                                      v
 ORCEL AUTHORITY SERVICE (own identity,      orcel-contain -> apps/orcel-doc-parser
 state unreachable from the session):        orcel-contain -> apps/orcel-firecrawl (AGPL component)
   keys, leases, epoch, standing approvals,  browser host -> worker -> Chromium (pipe) | Obscura (pipe, WPB)
   Full Control audit chain + Event Log,
   creates and owns executor Job Objects,     EXECUTORS ON THE USER DESKTOP (user token, each in a
   receives lock/logoff, enforces expiry      service-owned Job Object): shells, files, apps,
        ^                                     input, browser automation, git, long-running jobs
        | Stop (direct pipe)
 Full Control indicator (user session, disclosure + Stop button)
```

**Scrape walk-through (Safe mode).** A Firecrawl SDK with an explicit `apiUrl` and a REST token posts `/v2/scrape`.
The front checks host, origin and token, maps the body with `orcel-web` to `web/scrape`, and forwards it. `orceld`
checks the capability report, policy and per-client permissions (headers, sensitive features), raises one SOFT
approval bound to the request digest (URL, engine, formats, resolved addresses, client, session), fetches through the
governed transport, transforms through the contained Firecrawl component, audits and returns a Firecrawl `Document`.

**Full Control walk-through (Windows).** The user grants Full User for a declared task; the service checks that no
lease is active, challenges, verifies the Windows Hello signature, issues the lease and a standing approval for the
task scope. An MCP client asks for a PowerShell session. `orceld` calls the service's `Authorize`; the service checks
lease, epoch, standing approval, client and scope, appends the audit record, creates a Job Object it owns (granting
`orceld` only `JOB_OBJECT_ASSIGN_PROCESS`), and returns the decision; `orceld` starts PowerShell suspended, assigns it to
that Job Object and resumes it on the user's desktop.
Win+L, the indicator's Stop, the CLI or expiry make the service advance the epoch and terminate every held Job Object.

## 3. Crates and packages

| Unit | Path | State | Wave | Licence | Depends on | Role |
| --- | --- | --- | --- | --- | --- | --- |
| orcel-contracts | `crates/orcel-contracts` | exists | W1 | Apache-2.0 | serde, serde_json (+ schemars dev) | Leaf; section 4 contracts |
| orcel-policy | `crates/orcel-policy` | exists | W1 | Apache-2.0 | contracts, platform, approval, providers | Mode model, lease checks (verification moves to the service client) |
| orcel-approval | `crates/orcel-approval` | exists | W1 | Apache-2.0 | contracts, platform | Approvals bind `orcel_session_id` and client |
| orcel-audit | `crates/orcel-audit` | exists | W1 | Apache-2.0 | contracts, platform | Hash chain and Event Log anchor (shared by orceld and the service) |
| orcel-journal | `crates/orcel-journal` | exists | W1 | Apache-2.0 | fs4 | Storage primitive |
| orcel-jobs | `crates/orcel-jobs` | **new** | W1 | Apache-2.0 | contracts, journal | Embedded queue, throttle, budgets, store |
| orcel-web | `crates/orcel-web` | **new** | W1 | Apache-2.0 | contracts | Firecrawl v1/v2 schemas, refusals, translation |
| orcel-authority | `crates/orcel-authority` | **new** | W1 | Apache-2.0 | contracts, policy, audit, platform | Service core: leases, standing approvals, authorize, stop, audit; client used by orceld |
| orcel-browser-host | `crates/orcel-browser-host` | exists | W1, B | Apache-2.0 | contracts | Crawl, map, extraction; engine contract and Obscura adapter (track B) |
| orcel-provider-network | `crates/orcel-provider-network` | exists | W1, X | Apache-2.0 | contracts | Windows WinHTTP transport; macOS/Linux transport (WP1-13); credential headers |
| orcel-provider-uia | `crates/orcel-provider-uia` | exists | W1 | Apache-2.0 | contracts, platform | Protected markers for grant prompt and indicator |
| orcel-lifecycle | `crates/orcel-lifecycle` | exists | W1 | Apache-2.0 | approval, platform, policy, tunnel | `orcel authority install`, grant/stop, REST client and budget commands |
| orceld | `crates/orceld` | exists | W1 | Apache-2.0 | kernel crates | Web and job dispatch, Full Control dispatcher (service client), executors |
| orcel-authority-service | `apps/orcel-authority-service` | **new** | W1 (Windows), X | Apache-2.0 | orcel-authority | Windows service (`NT SERVICE\OrcelAuthority`); macOS LaunchDaemon and Linux systemd unit in track X |
| orcel-indicator | `apps/orcel-indicator` | **new** | W1 | Apache-2.0 | service pipe, orceld pipe | Disclosure and Stop |
| orcel-firecrawl | `apps/orcel-firecrawl` (own workspace) | **new** | W1 (native), W2 (extract) | **AGPL-3.0** (upstream) | none in-process | Isolated copy-first Firecrawl component |
| orcel-mcp | `apps/orcel-mcp` | exists | W1, W2 | Apache-2.0 | orceld over a pipe | Catalog, MCP tools, REST routes, OpenAPI (W2) |
| orcel-doc-parser | `apps/orcel-doc-parser` | exists | W2 | Apache-2.0 (+ FD-06 notice) | provider-process (test) | `/v2/parse` documents |
| orcel-browser-worker | `apps/orcel-browser-worker` | exists | B | Apache-2.0 (+ MIT notice) | browser host pipe | Engine-neutral refs and actions |
| orcel-sidecar | `crates/orcel-sidecar` | **new** | B, W3 | Apache-2.0 | contracts, platform | Generic supervised-child host (section 4.9) |
| obscura (patched) | `third_party/obscura` (own workspace) | **new** | B | Apache-2.0 + vendored notices | none | Pipe CDP; sensitive features gated |
| firecrawl-compat | `tests/firecrawl-compat` | **new** | W1 | Apache-2.0 (+ MIT notice) | black box | SDK contract harness, never shipped |
| browser-corpus | `tests/browser-corpus` | **new** | B | Apache-2.0 (+ notice) | black box | Dual-engine corpus |
| @orcel/sdk, orcel-sdk-py | `packages/orcel-sdk-ts`, `packages/orcel-sdk-py` | **new** | W2, W3 | Apache-2.0 | HTTP | SDKs |
| mobile, fleet adapters | `crates/orcel-provider-mobile`, `crates/orcel-fleet-report` | **new** | W3 | Apache-2.0 (+ notices) | contracts, sidecar | Android ADB; Fleet reporting |

**Dependency rules** (enforced by `crates/orceld/tests/dependency_direction.rs`, WP1-01): no `crates/*` unit depends on
`apps/*`, `tests/*`, `packages/*` or `third_party/*`; `orcel-contracts` depends only on serde and serde_json at runtime;
`orcel-web` only on `orcel-contracts`; `orcel-jobs` only on `orcel-contracts` and `orcel-journal`; separate workspaces
(`apps/orcel-contain`, `apps/orcel-doc-parser`, `apps/orcel-native-host`, `apps/orcel-firecrawl`, `third_party/obscura`)
stay separate; no Apache unit links an AGPL unit.

## 4. Contracts and designs

### 4.0 Versioning, naming and conventions

- Top-level wire objects carry `"contract": "orcel.<name>/<major>"`; additive optional fields keep the major.
- Inbound authority-bearing objects use `deny_unknown_fields`. Enums are `snake_case`, except `FailureCode`
  (`SCREAMING_SNAKE_CASE`, frozen). Times are `u64` ms; digests lowercase hex SHA-256; ids at most 256 bytes.
- Golden fixtures in `crates/orcel-contracts/tests/fixtures/`; JSON Schema (2020-12) generated into
  `docs/orcel/contracts/schema/` by `schemars` =1.2.3 as a dev-dependency, with a drift test.
- `orcel_contracts::canonical_json` (RFC 8785 style) produces every new digest. SG-000093 lease ids and binding digests
  and SG-000018/019/040 approval digests keep their existing encodings.
- Naming: envelope pairs `web/scrape`, `web/map`, `web/crawl_start`, `web/batch_scrape_start`, `web/search`,
  `job/status`, `job/cancel`, `job/errors`, `job/list`, and later `web/extract`, `web/parse`; MCP tools `web_scrape`,
  `web_map`, `web_crawl_start`, `web_batch_scrape_start`, `web_job_status`, `web_job_cancel`, `web_job_errors`,
  `web_job_list` (plus the existing `web_search`). Web calls use the transport's configured default `workspace_id`.

### 4.1 to 4.4 Principal, device, identity binding, lease, grant, session

```rust
pub enum PrincipalKind { LocalUser, McpClient, RestClient, RemotePrincipal, AgentRuntime, Sidecar }
pub struct Principal { contract: String, kind: PrincipalKind, principal_id: String,
                       client_profile_id: Option<String>, display: String }
pub struct Device { contract: String, device_id: String, os: OsFamily, os_build: String, arch: Arch, device_epoch: u64 }
#[serde(tag = "os", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsIdentityBinding {
    Windows { user_sid: String, logon_session_luid: u64 },
    Macos   { uid: u32, audit_session_id: u32, console_user: bool },
    Linux   { uid: u32, login_session_id: String, seat: Option<String> },
}
pub struct LeaseView { contract: String, lease_id: String, mode: AuthorityMode, binding_digest: String,
                       authority_epoch: u64, issued_at_ms: u64, expires_at_ms: u64,
                       executors: Vec<ExecutorClass>, state: LeaseState }      // projection, never proof
pub struct GrantRef { contract: String, approval_class: ApprovalClass, action_digest: String,
                      nonce_id: String, orcel_session_id: String, principal_id: String }
pub struct LeaseRef { lease_id: String, binding_digest: String, authority_epoch: u64 }
pub struct DispatchAuthority { mode: AuthorityMode, lease: Option<LeaseRef>, grant: Option<GrantRef>,
                               standing: Option<String>, authorization_id: Option<String> }
pub struct Session { contract: String, orcel_session_id: String, client_session_id: String, principal: Principal,
                     transport: Transport, tool_surface_profile: String, remote: Option<RemoteContext>, started_at_ms: u64 }
```

`AuthorityMode`, `ExecutorClass` and `ExecutionState` move to `orcel-contracts` with identical spellings and are
re-exported by `orcel-policy`. Approvals and leases bind `orcel_session_id`, so a restart invalidates them.

### 4.5 Tool registry entry

```rust
pub struct ToolEntry { contract: String, name: String, capability: String, operation: String, effect: EffectClass,
                       approval: ApprovalClass, lease_gate: Option<ExecutorClass>, standing_approvable: bool,
                       remote: RemoteExposure, profiles: Vec<String>, platforms: Vec<OsFamily>,
                       input_schema: String, output_bound: String, since: String }
```

`lease_gate` additionally gates a call; `standing_approvable` says whether a standing approval (section 4.15) may cover
it. A test compares the TypeScript catalog with the generated `docs/orcel/contracts/tools.json`.

### 4.6 Capability discovery

`CapabilityReport { device, build, entries: [ { capability, engine, status } ] }` with `status` one of `available`,
`unavailable { reason }`, `unsupported { reason }`, `blocked { policy }` and, new in revision 6,
`permission_required { permission }` for opt-in features a client has not been granted. The same report backs
`orcel capabilities`, the `capabilities` MCP tool and `GET /api/v1/capabilities`.

### 4.7 Job state machine

`Job { job_id, kind, owner (principal_id), task (declared, bounded, escaped), scope_digest, spec_digest, state,
outcome, authority, progress, budget, created_at_ms, updated_at_ms, expires_at_ms }`, with `state` in exactly
`not_started | dispatched | completed | cancelled | outcome_unknown`.

| From | To | Trigger |
| --- | --- | --- |
| (new) | `not_started` | Admitted; approval pending or granted |
| `not_started` | `cancelled` | Cancel, approval denied or expired, stop, or `orceld` restart |
| `not_started` | `dispatched` | First unit handed to an executor |
| `dispatched` | `completed` | All units finished; `outcome` `succeeded`, `partial` or `failed { code }` |
| `dispatched` | `cancelled` | Cancel, stop or lease expiry, confirmed by every executor |
| `dispatched` | `outcome_unknown` | Executor died, stop unconfirmed, or `orceld` restarted |

On restart, `not_started` jobs become `cancelled` and `dispatched` jobs `outcome_unknown`; nothing resumes; nothing in
`outcome_unknown` is retried.

### 4.8 Audit chain and anchors

`AuditEvent { contract, seq, prev_digest, at_ms, kind, request_id, job_id, principal_id, capability, operation,
authority, state, asserted_by_session, caller_pid, caller_image, detail, digest }`, where `asserted_by_session` is true
for every field the user session supplied (in the service's Full Control log: the action, capability, principal and
task as claimed by the caller) and `caller_pid` and `caller_image` are what the service observed on the pipe (C-27 e); `kind` in `request | decision | approval | dispatch | state | lease | standing |
emergency_stop | sidecar | rotation | anchor`. Lease lifecycle keeps `AuthorityAuditEvent` verbatim in `detail`;
`AuditKind` gains no variant. Argv, URLs, query strings and header values are recorded only as SHA-256 digests.

- **Write before dispatch.** A dispatch's record is flushed first; a failed write refuses the dispatch.
- **Anchors** every 32 events and on `lease`, `standing`, `emergency_stop` and shutdown: `(file id, seq, digest)` written
  to the Windows Application log, event id 4100, as insertion strings `orcel-anchor/1|<log>|<file id>|<seq>|<digest>`.
  The authority service registers the `Orcel` event source at install (it is installed with administrator consent).
  Where the service is not installed, `orceld` writes through an unregistered `RegisterEventSourceW(NULL, L"Orcel")`
  handle, which a standard user can use; WP1-03 proves that under a temporary standard account on the runner.
- **Verify.** `orcel audit verify` recomputes each chain and checks every Orcel anchor still in the log: a conflicting
  record is a break; a record beyond the chain's end means truncation. Only anchors still present (the log rolls over)
  are checked, and the oldest is reported. No durable anchor means no Full Control.

### 4.9 Sidecar IPC

As revision 5: `u32` little-endian length plus JSON over anonymous pipes; closed `HostToSidecar` (`hello`, `heartbeat`,
`request`, `cancel`, `shutdown`) and `SidecarToHost` (`hello`, `heartbeat_ack`, `response`, `progress`, `error`, `bye`)
vocabularies; 64 KiB control frames, declared data bound (at most 8 MiB); pinned path, hash check, launch from the hashed
handle, empty environment, handle allowlist; capability-less AppContainer or Seatbelt or seccomp/Landlock; listener
scan where sockets cannot be denied; 2 s heartbeat with three misses killing; 2 s cancel grace; 5 s shutdown;
`TerminateJobObject` or process-group kill; version strings never decide policy; the nonce proves liveness only.

### 4.10 Errors

New `FailureCode` variants, each with a frozen-spelling test: `LEASE_REQUIRED` (403), `LEASE_INVALID` (403),
`LEASE_UNSUPPORTED_PLATFORM` (501), `AUTHORITY_UNAVAILABLE` (503, the service is not installed or not answering),
`INDICATOR_UNAVAILABLE` (503), `UNSUPPORTED` (501), `POLICY_BLOCKED` (403), `PERMISSION_REQUIRED` (403, an opt-in feature
not granted to this client), `JOB_NOT_FOUND` (404), `QUEUE_FULL` (429), `RATE_LIMITED` (429), `OUTCOME_UNKNOWN` (500).
Existing codes: `INVALID_REQUEST` 400; `CAPABILITY_DENIED`, `WORKSPACE_DENIED`, `APPROVAL_DENIED`, `APPROVAL_REQUIRED`,
`PATH_ESCAPE`, `REMOTE_SESSION_INACTIVE` 403; `TARGET_STALE`, `PATH_RACE_DETECTED` 409; `APPROVAL_UNAVAILABLE`,
`PROVIDER_UNAVAILABLE` 503; `PROCESS_TIMEOUT` 408; `OUTPUT_LIMIT` 413; `POSTCONDITION_FAILED`, `INTERNAL_ERROR`,
`PROCESS_TERMINATION_UNVERIFIED` 500. `FailureCode::http_status` maps every variant (enumeration test).

### 4.11 Web requests, crawl execution, jobs and budgets

```rust
pub struct WebCrawlRequest {                 // "orcel.web-crawl/1", in orcel-contracts::web
    pub start_url: String, pub scope: WebScope, pub include_paths: Vec<String>, pub exclude_paths: Vec<String>,
    pub max_pages: u32, pub max_depth: u32, pub deadline_s: u32,   // validated against the user's budget (below)
    pub sitemap: SitemapMode, pub search: Option<String>, pub extract: Option<ExtractRequest>,
    pub engine: Engine, pub delay_ms: u32, pub headers: Vec<HeaderSpec>, pub privacy: PrivacyProfileRef,
    pub task: String,                        // declared task, at most 512 bytes, escaped for prompts
}
pub struct WebScope { pub origins: Vec<String> }   // W1: exactly one origin; W2: declared origin set (subdomains)
pub struct Ids { pub request_id: String, pub client_session_id: String, pub workspace_id: String, pub principal_id: String }
```

- `orcel-web` (depends on `orcel-contracts` only) parses Firecrawl bodies into these; `orceld`
  (`crates/orceld/src/web_dispatch.rs`) translates into `orcel_browser_host::crawl::CrawlSpec`.
- **Unit granularity.** `crawl.rs` owns frontier, dedup, scope and limits through `CrawlDriver`; one crawl or map job is
  one `orcel-jobs` unit. Per-URL units and dedup apply to batch scrape only. Drivers: `WorkerCrawl` (chromium, exists)
  and `FetchCrawlDriver` (`crates/orceld/src/fetch_crawl.rs`: governed transport plus the Firecrawl component).
- **Budgets (FD-UP-11 decided).** Defaults: 50 pages, depth 5, 10 minutes, 1,000 remembered URLs per crawl; 50 URLs per
  batch; delay 250 ms. The user changes them with `orcel config web-budgets` (local control path only; no MCP or REST
  route), stored in `%USERPROFILE%\.orcel\config\web-budgets.json`. `crawl.rs`'s constants become defaults behind a
  `CrawlLimits` value validated against **resource-protection ceilings** that are not product caps: result store at most
  20 MiB per job and 2 GiB in total by default (configurable up to free-disk minus 1 GiB), at most 2 running jobs and 4
  concurrent fetches device-wide (configurable to 8), memory ceiling per contained transform (orcel-contain limit), and
  the delay never below 100 ms per origin.
- **Approvals (FD-UP-5 decided).** One SOFT approval per crawl, map or batch job, bound to the client principal, the
  declared task, the destination scope (origins plus the resolved-address set of each), the parameters (budget,
  filters, formats, engine, headers by name, privacy profile) and `orcel_session_id`. Every page is checked against the
  scope and revalidates addresses (`TARGET_STALE` on drift). Pending prompts: 1 per client, 2 device-wide; an unanswered
  prompt cancels the job.
- **`orcel-jobs` modules:** `queue.rs`, `throttle.rs` (per-origin delay, token bucket, `Retry-After`, `Crawl-delay`),
  `retry.rs` (3 attempts, read-only batch units only), `concurrency.rs`, `checkpoint.rs` (reporting only), `store.rs`
  (caps and 24 h expiry), `budget.rs` (defaults, user config, ceilings), `owner.rs` (principal ownership).

### 4.12 Loopback REST access and credential headers

- **REST tokens:** `orcel_rest_<26 base32>` per client, hashed at rest, created and rotated with a SOFT approval through
  the protected local broker (`orcel client add-rest`, `rotate-rest`), removed without one (`remove-rest`); MCP token
  refused on REST and vice versa; jobs owned by the creating principal; generated client configs always set `apiUrl`
  (the SDKs otherwise default to `https://api.firecrawl.dev`). Wave 2 WebSocket checks host, origin and token.
- **Per-client permissions** (`orcel client grant <name> <permission>`, local control path, SOFT approval, audited):
  `web.headers.custom`, `web.headers.credential:<secret-name>`, `web.privacy.sensitive:<feature>`.
- **Headers (FD-UP-8 decided).** `HeaderSpec { name, value: Literal(String) | Secret(String) }`.
  - Credential values are never passed inline: `orcel secret add-header <name> --destination <origin>[,...]` stores the
    value in the OS secret store (`crates/orceld/src/secret_store.rs`: DPAPI on Windows, Keychain on macOS, Secret
    Service on Linux) bound to its destination origins; a request names it as `secret:<name>`.
  - Literal headers are allowed only for clients with `web.headers.custom`, and names that are credential-like
    (`Authorization`, `Cookie`, `Proxy-Authorization`, `X-Api-Key` and a configurable list) must use secrets.
  - Hop-by-hop and framing headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `TE`, `Upgrade`,
    `Expect`) are refused.
  - Headers are sent only to the destination origins of the secret and of the approved scope, and are **dropped on any
    redirect that leaves the origin**; the approval shows header names and secret names, never values.
  - Logs, audit and errors carry header names and value digests only. SG-000040's "no caller headers" rule is amended
    by SG-000133 for exactly these shapes.

### 4.13 Orcel authority service (Full Control, FD-UP-9 decided)

**Windows (Wave 1).** `apps/orcel-authority-service` runs as the virtual account `NT SERVICE\OrcelAuthority`
(`SERVICE_SID_TYPE_UNRESTRICTED`, automatic delayed start, no interactive rights, no network access configured). It is
installed once with administrator consent by the installer or `orcel authority install` (elevated through UAC).
- **State:** `%ProgramData%\Orcel\authority\` with a protected DACL: `NT SERVICE\OrcelAuthority` full control, `SYSTEM`
  full control, `BUILTIN\Administrators` full control (an administrator owns the machine), no access for users. It holds
  the lease store, epoch, standing approvals, enrolled presence keys, the Full Control audit chain and its anchors.
- **Keys:** the lease-signing key is a non-exportable key in the Microsoft Platform Crypto Provider (TPM) when present,
  otherwise the Microsoft Software Key Storage Provider, in the service account's key store. The user session never
  holds a signing key; `orceld` holds only `LeaseView`s and per-dispatch authorization ids.
- **Interface and anti-squatting:** named pipe `\\.\pipe\orcel-authority`, created by the service at start with
  `FILE_FLAG_FIRST_PIPE_INSTANCE` (if the name already exists, the service refuses to run, logs an Event Log error and
  Full Control is unavailable: a denial of service, never a spoof) and `PIPE_REJECT_REMOTE_CLIENTS`. Its DACL grants
  the service SID full control and `NT AUTHORITY\INTERACTIVE` exactly `FILE_READ_DATA | FILE_WRITE_DATA |
  SYNCHRONIZE | READ_CONTROL` (`READ_CONTROL` lets clients read the owner for the check below and cannot create pipe
  instances); it never grants `GENERIC_WRITE` or `FILE_APPEND_DATA`, whose bit is `FILE_CREATE_PIPE_INSTANCE`, so no
  user process can add a rogue instance. The service starts automatically (not delayed) to shorten the window before
  it owns the name. **Every client** (`orceld`, the indicator, `orcel authority enroll`, the CLI) verifies, before sending
  anything, that `GetNamedPipeServerProcessId` equals the service's PID from `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)`
  and that the pipe's owner SID (`GetSecurityInfo` on the handle) is the virtual service SID of
  `NT SERVICE\OrcelAuthority` (`LookupAccountNameW`); otherwise it disconnects and reports `AUTHORITY_UNAVAILABLE`.
  For every request the service records the caller's token user SID and logon session (`ImpersonateNamedPipeClient`,
  `GetTokenInformation`), process id (`GetNamedPipeClientProcessId`) and image path. Requests: `GrantBegin`,
  `GrantComplete`, `StandingBegin`, `StandingComplete`, `Authorize`, `Stop`, `Status`, `Heartbeat`. A caller can act only
  on leases bound to its own SID and logon session.
- **Presence (STRONG) and the grant window:** at first use, the user enrolls a Windows Hello key credential ("Orcel
  Authority", `KeyCredentialManager.RequestCreateAsync`, created by `orcel authority enroll` in the user session); the
  service stores its public key. Windows Hello's prompt does not show Orcel's scope, so:
  1. **intent first:** `orcel full-control grant` sends `GrantBegin` with the requested scope, client and task; the service
     records it as the session's single pending **grant intent** (event 4102 in the Event Log) and expires it after
     5 minutes. Without a recorded intent, an unlock opens nothing, so the user's routine unlocks (including after a
     lock any process caused with `LockWorkStation`) never produce a grant prompt by themselves;
  2. a **grant window** of 120 s opens only on the first service-observed `WTS_SESSION_UNLOCK` for that session after the
     intent (the user authenticated through the secure attention sequence), while no Full Control lease is active; the
     CLI tells the user to press Win+L and unlock;
  3. the requested scope defaults to the narrowest form (desktop input only, no roots, no shells, 30 minutes); every
     widening (roots, shells, apps, longer expiry) is an explicit choice in the intent;
  4. **service-rendered confirmation:** when the window opens, the service calls `WTSSendMessageW` for that session with
     the title "Orcel Authority" and the requested scope, client, task and expiry, buttons Yes and No, a 60 s timeout, and
     waits for the answer. The message box is created by the system on the service's behalf, not by a user-session
     process; WP1-10 verifies that `SendInput` and `PostMessageW` from a medium-integrity user process cannot answer it
     (User Interface Privilege Isolation). Only Yes continues; No or timeout clears the intent (event 4102 records the
     result). If WP1-10's verification fails, this step still shows the scope but is recorded as not input-protected,
     and the residual in C-27 (f) carries the whole weight;
  5. the service issues a 32-byte challenge bound to the intent's digest; the user session calls
     `KeyCredential.RequestSignAsync` (Windows Hello); the service verifies the signature;
  6. the service writes the **granted scope** (executors, roots, client, task, expiry, lease id) to the Event Log as
     event id 4101 under its registered source, and the indicator shows the scope as the service reports it, so the
     user can check what was granted outside any agent-controlled window.
  Grants and renewals are refused while any Full Control lease is active. The prompt recommends biometric Hello
  because a PIN can be observed by persisted code (C-27 d). **Remote Full Control (SG-000105) must not ship before this
  grant window, narrow default and Event Log scope record are implemented and qualified.**
- **Job Objects are created and owned by the service.** For each executor (and each in-process Full Control provider
  worker, section 4.14), `orceld` asks the service in `Authorize`; the service creates a Job Object named
  `Global\Orcel-Job-<128-bit random>` (failing on `ERROR_ALREADY_EXISTS`) with limits
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no `JOB_OBJECT_LIMIT_BREAKAWAY_OK` and no `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`,
  owner the service SID, and a DACL granting the requesting session's logon SID only `JOB_OBJECT_ASSIGN_PROCESS`. The
  service keeps its handle. `orceld` opens the name with `JOB_OBJECT_ASSIGN_PROCESS`, checks that the owner is the
  service SID, creates the executor suspended, assigns it, then resumes it (assignment before resume). `orceld` cannot
  change limits, terminate the job or let a child break away; processes started by the job's members stay in it.
- **Authorize (atomic, C-30):** under the epoch lock, check lease (bindings, epoch, expiry, policy revision), the
  client principal, the standing approval (scope, task, expiry) or the action's own approval reference; append the audit
  record (with `asserted_by_session: true` for everything the request claims, and the observed caller SID, logon
  session, PID and image); create the Job Object as above; return `{ authorization_id, epoch, job_name }`. The indicator
  heartbeat is checked too, but it is disclosure only and proves nothing against a same-user agent (C-27 c).
- **Stop (C-28):** `Stop` from any process in the same logon session (it only removes authority); the service also
  handles `SERVICE_CONTROL_SESSIONCHANGE` (`WTS_SESSION_LOCK`, `WTS_SESSION_LOGOFF`, `WTS_CONSOLE_DISCONNECT`,
  `WTS_REMOTE_DISCONNECT`), expiry timers and heartbeat loss. Stop advances the epoch, terminates every held Job Object,
  writes `emergency_stop`, and tells `orceld` and the indicator.
- **Admin:** the service never elevates anything. `Full Admin` actions still need an `AdminLease` and an OS UAC
  elevation (SG-000098); the Admin executor is refused until SG-000098.
- **Without the service:** Safe mode and every non-Full-Control feature work; Full Control answers
  `AUTHORITY_UNAVAILABLE` and the capability report says why. The existing SG-000095 desktop-input path moves behind
  the service (it does not keep a weaker per-user path).

**macOS and Linux (track X).** macOS: a LaunchDaemon `com.orcel.authority` running as a dedicated `_orcel` user created
at install, state in `/Library/Application Support/Orcel/authority` (owner `_orcel`, mode 0700), an XPC Mach service
identifying callers by audit token (uid, audit session), presence by a Secure Enclave key in the user's keychain
created with `.userPresence` and signed through LocalAuthentication, and process groups instead of Job Objects. Lock
detection on macOS comes from a per-user LaunchAgent and is therefore best effort; expiry is enforced by the daemon.
Linux: a systemd system service with `User=orcel-authority`, state 0700, key sealed with `systemd-creds` (TPM2 when
present), a Unix socket with `SO_PEERCRED`, presence through a polkit action (`org.orcel.authority.grant`,
`auth_self`), cgroup v2 scopes instead of Job Objects, and logind's `Lock`/`LockedHint` on the system bus for stop.

### 4.14 Executors, indicator and stop (Windows, Wave 1)

| Executor class | What runs | Grain | Token and desktop | Kill |
| --- | --- | --- | --- | --- |
| DesktopInput, window actions, UIA observation | Native host `apps/orcel-computer-host` (Go), via `orceld/src/uia.rs` -> `ComputerHostAdapter` -> `HostSession::spawn` | SG-000095 (closed), migrated by SG-000132 | User token, user desktop | Service-owned Job Object |
| ShellProcess: PowerShell 5.1/7, cmd, Git Bash, WSL bash; interactive PTY (ConPTY) | One process tree per session | SG-000096 (continued) | User token, user desktop | Service-owned Job Object; for WSL bash it holds only the tracked wsl.exe tree, and stop also kills the session's Linux process group (started under setsid) and verifies it gone, otherwise `outcome_unknown` (SG-000096 scope and A10) |
| Filesystem across authorized drives and roots; process inspection and termination | **Full Control provider worker** `orceld fc-worker` (the same binary in a separate process, one per lease, serving the filesystem and process providers over a private pipe), not in-process in `orceld` | SG-000097 (activated) | User token | Service-owned Job Object; Stop kills in-flight operations |
| App launch and close | App process trees | SG-000097 | User token, user desktop | Service-owned Job Object per launch |
| Git beyond workspaces | The git provider inside the same `fc-worker` | SG-000097 scope | User token | Service-owned Job Object |
| Long-running automation | `orcel-jobs` units, each executor in a service-owned job | SG-000134 | As above | Service-owned Job Object |
| Browser automation of the user's browsers and profiles | Browser host | SG-000100 (Wave 2) | User token | Service-owned Job Object |
| Remote control | Relay | SG-000105 (Wave 3; blocked on the grant-window work of 4.13) | n/a | n/a |

No Full Control operation runs inside the long-lived `orceld` process itself; Safe-mode providers stay in-process as
today. Processes an agent starts through the OS outside these jobs (scheduled tasks, WMI, DCOM) are not in them and
survive stop (C-27 a).

- **Authorized roots** are declared at grant (drives or folders) and are part of the lease's scope; the filesystem
  provider refuses paths outside them and always refuses `%ProgramData%\Orcel\authority` (unreadable anyway) and the
  user-session Orcel state root for writes.
- **Indicator** (`apps/orcel-indicator`, launched by `orceld` on an inherited pipe as in revision 5, plus a direct pipe to
  the service): shows mode, client, task, roots, expiry and the latest service anchor; Stop button first; hotkey shown
  only if `RegisterHotKey` succeeded; "Lock your PC (Win+L) to stop" unless `DisableLockWorkstation` is set (then a
  warning, `LockStatus { available: false }`, recorded by the service); acts on hardware input only
  (`GetCurrentInputMessageSource`); treats close, minimise and hide as Stop; enables the extension-point, signature,
  image-load and dynamic-code mitigation policies; sends a heartbeat to the service every 1 s only while topmost, visible,
  not cloaked, on a monitor and on the input desktop. The service refuses `Authorize` after 5 s without a heartbeat.
- **What the indicator is.** It is disclosure and a convenient Stop. An agent with the user's rights can kill or
  imitate it and forge its heartbeat, so the heartbeat proves nothing against a same-user agent (C-27 c); enforcement
  does not depend on it: expiry, session lock, sign-out and the CLI stop are handled by the service. It verifies the
  service pipe as every client does (4.13) before sending Stop.
- **Tests (WP1-10, WP1-12):** see section 8.2.

### 4.15 Standing approvals (FD-UP-10 decided)

```rust
pub struct StandingApproval {                // "orcel.standing-approval/1", issued only by the service
    pub id: String, pub lease_id: String, pub principal_id: String, pub task: String,
    pub executors: Vec<ExecutorClass>,       // never Admin
    pub roots: Vec<String>, pub origins: Vec<String>, pub commands: Option<Vec<String>>,  // declared scope
    pub issued_at_ms: u64, pub expires_at_ms: u64,   // at most the lease's expiry
}
```

Granted with STRONG presence for one identified client and one declared task; shown on the indicator; every dispatch it
covers is authorized and audited individually with its id; ended by stop, lease end or expiry; never covers `Admin`,
remote callers, out-of-scope targets or another client. Without one, each action keeps its own approval.

Amended 2026-11-17, recorded in SG-000135 (`.specgrain/specs/SG-000135.json`), pending founder confirmation of the
derived standing-approval coverage: for the remote `browser_full` capability profile only, a browser lease or browser
standing approval issued by the owner may cover
the remote caller that is the identified client named in it, through the Secure MCP Tunnel, within its origins,
profiles, sessions, action families and expiry. Every other remote caller, executor and profile keeps the rule above.
The founder's words (chat directive, 2026-11-17): "The current Orcel remote MCP profile does not expose browser
actions. Implement an explicitly authorized remote browser capability profile. Do not merely copy BrowserOS's MCP
server and claim that ChatGPT can already control it. Prove an actual end-to-end browser task over local MCP, then
validate the ChatGPT tunnel integration where the client supports it." and "Full Access grants eliminate repeated
approvals for routine actions already authorized by the owner." The founder's architecture decision of the same day
describes the tunnel forwarding "to Orcel's local, authenticated and owner-lease-authorized MCP service". The remote
standing-approval coverage is derived from these words, not quoted from them, and shares the same pending founder
confirmation as remote coverage: until it is given, only a lease issued by the authority service covers a remote
caller; the alternative is an interim-store browser lease gated by the existing SG-000055 STRONG remote-session lease.

### 4.16 Sensitive web features (FD-UP-2 decided)

| Class | Features | Default | Gate |
| --- | --- | --- | --- |
| Privacy and compatibility | Ad and tracker blocking (Scrapling ad-domain list), Global Privacy Control header, cookie isolation per job, `Accept-Language` matching the OS, a truthful Orcel user agent naming the engine | On | None beyond the job approval |
| Sensitive, opt-in | User-agent override, device and mobile emulation, locale and timezone override, geolocation override, user-supplied proxy, fingerprint randomisation, TLS fingerprint impersonation (Obscura's stealth stack, built behind a cargo feature and enabled at run time only by policy) | Off | Per-client `web.privacy.sensitive:<feature>` granted from the local control path, shown in each job approval, audited per use |
| Never | CAPTCHA solving, login, paywall or access-control bypass, ignoring robots rules, ignoring a site's rate limits, credential stuffing | n/a | Not implemented |

Firecrawl's `proxy: "stealth"`, `mobile` and `location` map to the sensitive class: allowed when the client holds the
permission and the engine supports it, otherwise `PERMISSION_REQUIRED` or `UNSUPPORTED`.

### 4.17 Firecrawl component protocol (`apps/orcel-firecrawl`)

- **Launch:** through `crates/orcel-provider-process/src/contained.rs` (`run_contained`), exactly as the document
  parser: pinned path and SHA-256, no network, no process creation, read-only private input copy, CPU, memory and time
  limits, one JSON request on stdin, one JSON result on stdout.
- **Requests (W1):** `transform_html { html, url, only_main_content, include_tags, exclude_tags, formats }` returns
  `{ markdown, html, links, metadata }`; `filter_links { links, base_url, scope }`; `parse_sitemap { xml }`;
  `post_process_markdown { markdown }`. W2 adds `extract { content, schema, prompt }` (the copied extract pipeline, model
  calls answered by `orceld` over the same pipe from the user's configured provider).
- **Never:** HTTP, file access outside the private copy, telemetry, cloud hand-off (`apps/local/src/cloud.rs`,
  `login.rs` are not copied).

## 5. Firecrawl parity matrix

### 5.1 Upstream facts

Pins: inventory `firecrawl/firecrawl@42f4d669954649ce33466a2a50e8215c7f1f4d1c`; PR #785 `25a92fc3`; route tables
identical at both. Server versions: v2 (`apps/api/openapi.json`) and v1 (`apps/api/v1-openapi.json`). SDKs:
`@mendable/firecrawl-js` 4.54.0 (MIT) and `firecrawl-py` 4.57.0 (MIT). Route counts: v2 70; v1 33 lines, 6 commented
out. **Target (FD-UP-1 decided): full open-source feature parity for scrape, crawl, map, search, extract, batch,
document processing, structured outputs and change tracking**, v2 native and v1 where practical, no Firecrawl Cloud
dependency. Windows first; macOS and Linux follow WP1-13 on the parallel track.

### 5.2 Endpoint matrix

| # | Route (v2; v1 alias) | Orcel tool | Backing | Wave | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | `POST /v2/scrape`; `/v1/scrape` | `web_scrape` | governed fetch + Firecrawl component, or chromium extract | W1 | One SOFT approval per request |
| 2 | `POST /v2/map`; `/v1/map` | `web_map` | `crawl.rs` map + `map_rank.rs` + component `filter_links`/`parse_sitemap` | W1 | |
| 3 | `POST /v2/crawl`; `/v1/crawl` | `web_crawl_start` | orcel-jobs + `crawl.rs` via drivers | W1 | One approval per job (C-33) |
| 4-7 | `GET`/`DELETE /v2/crawl/{id}`, `/errors`, `/ongoing`, `/active`; v1 aliases | `web_job_*` | orcel-jobs | W1 | Owner only |
| 8-9 | `POST /v2/batch/scrape`, status, cancel, errors | `web_batch_scrape_start`, `web_job_*` | orcel-jobs | W1 | |
| 10 | `POST /v2/search`; `/v1/search` | `web_search` | `crates/orceld/src/search.rs` (BYOK providers) | W1 results; W2 `scrapeOptions` | |
| 11 | `GET /v2/scrape/{jobId}` | `web_job_status` | orcel-jobs | W2 | |
| 12 | `/v2/parse`, `/parse/formats`, `/parse/upload-url`, `PUT /parse/upload/{id}` | `document_parse` | `apps/orcel-doc-parser` | W2 | Upload to private staging |
| 13 | WebSocket crawl watcher | none | loopback WS | W2 | Host, origin, token checked |
| 14 | `/v2/team/queue-status`, `/v2/concurrency-check` | `web_job_list` | orcel-jobs counts | W2 | |
| 15 | `POST /v2/extract`, `GET /v2/extract/{id}`; v1 aliases | `web_extract` | component `extract` (copied pipeline) + user's model provider | W2 | Structured outputs validated against the schema |
| 16 | `POST /v2/crawl/params-preview` | none | component + model | W2 | |
| 17 | `/v1/llmstxt`, `/v1/deep-research` | none | component + model | W3 | |
| 18 | `/v2/monitor*` | none | local change-tracking scheduler over orcel-jobs | W2 | Monitor source is cloud-only; local equivalent, no parity claim for hosted features |
| 19 | `/v2/agent*`, `/v1/fireclaw` | none | `apps/orcel-agent` is separate | n/a | Cloud-only |
| 20 | `/v2/scrape/{jobId}/interact`, `/v2/interact*`, `/v2/browser` | Orcel `browser_*` tools | browser host | n/a | Cloud-only; local browser tools are the equivalent |
| 21 | team usage and billing routes | none | none | n/a | No billing |
| 22 | keyless, slack, support, feedback, siem, threat-protection, research, developer, gov | none | none | n/a | Hosted SaaS |

### 5.3 `POST /v2/scrape` options

| Field | Orcel | Wave | Rule |
| --- | --- | --- | --- |
| `url`, `formats: markdown, html, rawHtml, links` | yes | W1 | Public HTTPS; addresses bound into the approval |
| `formats: changeTracking` (git-diff) | yes | W1 | `change_tracking.rs`; `json` mode W2 |
| `onlyMainContent`, `includeTags`, `excludeTags` | yes | W1 | Component `transform_html` (copied `html.rs`) |
| `waitFor`, `timeout`, `parsers: pdf` | yes | W1 | Engine timeouts; contained parser |
| `maxAge` | `0` in W1; cache W2 | W1/W2 | |
| `headers` | yes, policy-gated (4.12) | W1 | Per-client permission; secrets from the OS store; destination-scoped; redacted |
| `formats: screenshot`, `actions` | yes | W2 | Engine capture contract; each action an approved browser shape |
| `formats: json`, `summary`, `question`, `highlights`, `query`, `attributes`, `images`, `branding`, `product`, `menu` | yes | W2 | Component `extract` plus model provider; `attributes`, `images` via `html.rs` |
| `formats: audio`, `video`, `deterministicJson`, `rawBase64` | evaluated | W3 | |
| `blockAds` | yes (privacy default) | W2 | |
| `proxy: "stealth"`, `mobile`, `location` | opt-in (4.16) | W2 (engine support) | `PERMISSION_REQUIRED` without the client permission |
| `proxy: "basic"`/`"auto"` | no proxy | W1 | User proxy is a sensitive opt-in |
| `skipTlsVerification` | refused | never | Security bypass |
| `storeInCache`, `zeroDataRetention` | no-op | W1 | Nothing leaves the device |
| `lockdown`, `checkPromptInjection`, `redactPII`, `profile`, `threatProtection`, `auditMetadata`, `alexandria`, `maxCredits`, `domainTools`, `toolDetail`, `onlyCleanContent`, `minAge`, `removeBase64Images` | refused by name in W1 | re-evaluated W2 | Hosted features |
| `orcel.engine` | `fetch`, `chromium`; `obscura` (track B) | W1 | Engine named in result and audit |

### 5.4 Map and crawl options

| Field | Orcel | Rule |
| --- | --- | --- |
| `limit`, `maxDiscoveryDepth`, v1 `maxDepth`, timeout | yes | Within the user's budget (4.11) |
| `includePaths`, `excludePaths`, `regexOnFullURL`, `ignoreQueryParameters`, `sitemap`, `search` | yes | Filters narrow; scope is the boundary |
| `delay`, `maxConcurrency` | yes | Delay at least the budget floor; one page in flight per crawl unit |
| `scrapeOptions` | yes, subset of 5.3 | |
| `includeSubdomains`, `allowSubdomains`, `allowExternalLinks`, `crawlEntireDomain`, v1 `allowBackwardLinks` | W1: refused unless all origins are in the approved scope; W2: declared origin sets | Destination scope is enforced per page |
| `ignoreRobotsTxt: true`, `robotsUserAgent` | refused | Respect site authorization |
| `webhook` | refused W1; loopback-only W2 | No job egress |
| `prompt` | W2 | Model |

### 5.5 Status mapping

`not_started`, `dispatched` -> `scraping`; `completed` (`succeeded`/`partial`) -> `completed`; `completed` (`failed`) ->
`failed` with `code`; `cancelled` -> `cancelled`; `outcome_unknown` -> `failed` with `OUTCOME_UNKNOWN`. `creditsUsed` 0.

### 5.6 Licence statement

The contract layer (`orcel-contracts`, `orcel-web`, `orcel-jobs`, `orceld`, `orcel-mcp`) is Apache-2.0 Orcel code.
Copy-first Firecrawl code lives only in `apps/orcel-firecrawl` under AGPL-3.0 with its obligations (C-17). The FD-06
files are unchanged. The founder attestation is recorded separately (C-15). This is Orcel's engineering position, not
legal advice.

## 6. Donor file to destination mapping

### 6.1 Methods

`COPY` (verbatim or minimal change, upstream licence and notice kept, `PATCHES.md`), `PORT-ALGO`, `PORT-CODE`,
`CONTRACT-TEST`, `ORACLE`, `DATA`, `PATCH` (vendored with Orcel patches, own workspace), `REFERENCE`. Each copied
directory carries `PROVENANCE.json { repo, sha, paths, licence, attestation_ref, patches }` checked by WP1-01.

### 6.2 Wave 1

| Upstream (repo: path @ SHA) | Licence | Method | Destination | Packet |
| --- | --- | --- | --- | --- |
| firecrawl: `apps/api/native/src/html.rs`, `utils.rs` @ `42f4d669` | AGPL-3.0 | COPY (napi attributes and async wrappers removed; nodesig dependency removed) | `apps/orcel-firecrawl/src/upstream/html.rs`, `utils.rs` | WP1-08 |
| firecrawl: `apps/local/src/markdown.rs` | AGPL-3.0 | COPY | `apps/orcel-firecrawl/src/upstream/markdown.rs` | WP1-08 |
| firecrawl: `apps/api/native/src/crawler.rs` (`filter_links`, `filter_url`, `validate_regexes`, `parse_sitemap_xml`, `process_sitemap`), `xml.rs` | AGPL-3.0 | COPY | `apps/orcel-firecrawl/src/upstream/crawler.rs`, `xml.rs` | WP1-08 |
| firecrawl: `apps/api/native/src/{pdf,document,engpicker}.rs` | AGPL-3.0 | REFERENCE in W1 (Orcel's FD-06 doc-parser already covers documents); COPY candidates for W2 parity tests | n/a | W2 |
| firecrawl: `apps/local/src/{fetch,netguard,guard,crawl,scrape}.rs` | AGPL-3.0 | ORACLE (behaviour compared; Orcel's governed fetch and `crawl.rs` stay the network and scope authority) | `tests/firecrawl-compat` | WP1-09 |
| firecrawl: `apps/local/src/{serve,cloud,login,main}.rs` | AGPL-3.0 | not copied | n/a | n/a |
| firecrawl: `apps/js-sdk/firecrawl/src/v2/types.ts`, `methods/{scrape,map,crawl,batch,search}.ts`; `apps/python-sdk/firecrawl/v2/types.py`, `v1/client.py` | MIT | REFERENCE (interface facts) | `crates/orcel-web/src/{v2,v1}.rs` | WP1-05 |
| firecrawl: `apps/js-sdk/firecrawl` 4.54.0; `apps/python-sdk` 4.57.0; `apps/js-sdk/firecrawl/src/__tests__/e2e/v2/{scrape,map,crawl,batch,search}.test.ts` | MIT | CONTRACT-TEST | `tests/firecrawl-compat/{js,py}` | WP1-09 |
| crawlee @ `7bec9ad5`: `packages/core/src/storages/{request-queue,request-dedup-cache}.ts`, `packages/basic-crawler/src/internals/{throttling-request-manager,basic-crawler,request-timeout,errors}.ts`, `autoscaling/{autoscaled-pool,snapshotter,system-status,memory-load-signal,weighted-avg}.ts` | Apache-2.0 | PORT-ALGO | `crates/orcel-jobs/src/*` | WP1-04 |
| crawlee: `test/basic-crawler/throttling-request-manager.test.ts`, `test/core/autoscaling/*.test.ts` | Apache-2.0 | ORACLE | `crates/orcel-jobs/tests/` | WP1-04 |
| scrapling @ `bb223f2f`: `scrapling/spiders/{checkpoint,scheduler,throttle}.py` | BSD-3-Clause | REFERENCE | `crates/orcel-jobs/src/{checkpoint,throttle}.rs` | WP1-04 |

### 6.3 Wave 2 and track B

| Upstream | Licence | Method | Destination | Packet |
| --- | --- | --- | --- | --- |
| firecrawl: `apps/api/src/lib/extract/**` (build-document, build-prompts, completions, helpers; not the Redis and fire-0 cloud paths) | AGPL-3.0 | COPY (TypeScript, run on the pinned Node runtime inside the component; model calls proxied by `orceld`) | `apps/orcel-firecrawl/extract/` | WP2-13 |
| firecrawl: `apps/api/src/lib/change-tracking-diff.ts` json mode, `apps/api/src/controllers/v2/types.ts` formats | AGPL-3.0 | COPY or REFERENCE | component | WP2-13 |
| obscura @ `0d9a2f76`: whole tree, vendored | Apache-2.0 (+ MIT, OFL vendored) | PATCH: pipe CDP transport in `crates/obscura-cdp/src/{server,dispatch,lib}.rs`; `crates/obscura-cli/src/main.rs` pipe mode, `serve` and MCP compiled out; `obscura-net` egress routed to the host broker or sandbox-denied; stealth stack behind a cargo feature, enabled only by the 4.16 gate | `third_party/obscura/` | WPB-02 |
| agent-browser @ `53384771`: `cli/src/native/{snapshot,element,actions,interaction,pointer,screenshot,diff,tab_binding,browser,network}.rs`, `cli/src/native/cdp/{chrome,obscura,discovery}.rs`, `parity_tests.rs`, `e2e_tests.rs`, `evals/cases/*` | Apache-2.0 | PORT-ALGO / PORT-CODE (tests) | browser host, worker, `tests/browser-corpus` | WPB-01, WPB-03, WPB-04 |
| crawlee: `packages/utils/src/internals/{extract-microdata,open-graph-parser,social}.ts`; scrapling: `engines/toolbelt/ad_domains.py` (DATA), `parser.py`, `core/storage.py` | Apache-2.0, BSD-3-Clause | PORT-ALGO, DATA | extraction, navigation blocklist | WP2-08 |
| scrapling: `engines/toolbelt/fingerprints.py`; crawlee `session-pool/fingerprint.ts` | BSD-3-Clause, Apache-2.0 | PORT-ALGO behind the 4.16 sensitive gate | browser host privacy profile | WP2-14 |

## 7. Dependency versions

**Existing pins (unchanged):** Rust 1.97.1; main-workspace MSRV 1.82; doc-parser MSRV 1.88; Node 24.19.0 (CI), worker
floor >= 22.15.0; playwright-core 1.63.0; @modelcontextprotocol/server 2.3.1; zod 4.6.7; typescript 5.9.3;
serde_json 1.0.151; sha2 0.10; fs4 1.1; regex 1.13.1; similar 2.7.0; windows-sys 0.52 (new features
`Win32_System_EventLog`, `Win32_System_Services`, `Win32_System_JobObjects`, `Win32_System_RemoteDesktop` added in the
packets that need them; no new crate); windows 0.58 (adds `Security_Credentials` for Hello in `orcel-lifecycle`);
tokio 1.47 (orcel-contain only); cargo-deny 0.20.2.

**New in Wave 1:**

| Item | Version | Licence | Scope |
| --- | --- | --- | --- |
| schemars | =1.2.3 | MIT | `orcel-contracts` dev-dependency |
| kuchikiki | =0.8.2 | MIT | `apps/orcel-firecrawl` (as upstream) |
| lol_html | =2.6.0 | BSD-3-Clause | `apps/orcel-firecrawl` |
| url | =2.5.7 | MIT OR Apache-2.0 | `apps/orcel-firecrawl` |
| psl | =2.1.140 | MIT OR Apache-2.0 | `apps/orcel-firecrawl` |
| strsim | 0.11 line, exact patch pinned at packet start | MIT | `apps/orcel-firecrawl` |
| roxmltree | =0.20.0 | MIT OR Apache-2.0 | `apps/orcel-firecrawl` |
| texting_robots | =0.2.2 | MIT OR Apache-2.0 | `apps/orcel-firecrawl` |
| regex, serde, serde_json | as upstream (1.11.2+, 1.0.219, 1.0.143) | MIT OR Apache-2.0 | `apps/orcel-firecrawl` |
| @mendable/firecrawl-js | 4.54.0 | MIT | `tests/firecrawl-compat` dev |
| firecrawl-py | 4.57.0 | MIT | CI-only virtualenv |
| rustls, rustls-platform-verifier | 0.23.x latest patch (not the `0.24.0-dev` prerelease) and 0.7.1 or newest, pinned at WP1-13 start | MIT OR Apache-2.0 OR ISC; MIT OR Apache-2.0 | `orcel-provider-network`, macOS and Linux only |

Every version is re-checked at packet start (at least 14 days old, recorded checksum); `cargo deny` runs per workspace.

**Track B and Wave 2:** Obscura vendored source at `0d9a2f76` (release `v0.2.7`, tag commit `0ecc4177`, for comparison),
built `--locked --offline`, V8 archives pre-fetched by SHA-256, provenance attested; Chromium and Edge as qualified by
the browser host; OpenAPI 3.1.0 via zod's `z.toJSONSchema`.

## 8. Packets and order

### 8.1 Order

```text
 Wave 1 (Windows first)                       Track X (starts now)            Track B (starts now)
 WP1-00 activation PR                          WP1-13 macOS/Linux transport    WPB-01 engine abstraction
 WP1-01 licence+provenance gates  --+          WPX-01 macOS/Linux authority    WPB-02 Obscura patched build
 WP1-02 contracts ---------------+  |          WPX-02 cross-platform web qual  WPB-03 agent-browser parity port
 WP1-03 audit chain <------------+  |          WPX-03 macOS/Linux executors    WPB-04 measured corpus trial
 WP1-04 jobs <-------------------+  |
 WP1-05 web schemas <------------+  |
 WP1-08 fetch engine + component <--+ (needs 01 for the AGPL carve-out, 05)
 WP1-06 dispatch (03,04,05,08) -> WP1-07 MCP/REST -> WP1-09 harness -> WP1-16 headers + privacy gate
 WP1-10 authority service + dispatcher (02,03) -> WP1-12 indicator -> WP1-14 standing approvals
   -> WP1-15 executors: shells (SG-000096), filesystem/processes/apps (SG-000097)
 WP1-11 journeys J-1, J-2, J-3, J-3b
```

### 8.2 Wave 1 packets

Every packet: exact-head CI on `ubuntu-latest`, `windows-latest`, `macos-latest`; Review Gates (Jev, Alibaba OCR
delegation); zero unresolved threads; security judge where marked; d1-local advisory only. **WP1-01, 02, 03, 04, 05
and 08 are ready to implement** and are written to the file level.

#### WP1-00 Activation PR

- Copy `prep/unified-grains/SG-000131.draft.json`, `SG-000132`, `SG-000133`, `SG-000134` and `SG-000097` into
  `.specgrain/specs/` (drop the `draft_note` field; keep `state: "GRAIN"`), apply `SG-000096.amendment.draft.json` to
  `.specgrain/specs/SG-000096.json`, record the founder decisions of 2026-11-17 and the go-ahead in `CURRENT.md`,
  update the open-grain assertion in `apps/orcel-mcp/src/p20-architecture.test.ts` (today it pins the open set to
  SG-000096, SG-000119, SG-000127, SG-000128), and correct the Firecrawl entry of `DONOR_REGISTRY.md` and
  `donor_registry.json`. SG-000101 and SG-000102 stay reserved for P20.
- Tests: `node scripts/check-current-identity.mjs`; the `ci.yml` "Validate SpecGrain JSON and canonical evidence" step;
  `npm test` in `apps/orcel-mcp` (p20 architecture test).

#### WP1-01 Licence and provenance gates (ready)

Files:
- `deny.toml` (root workspace): `[licenses] allow = ["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC",
  "Unicode-3.0", "Zlib", "0BSD", "MPL-2.0"]` with `MPL-2.0` permitted only through `[[licenses.exceptions]]` entries;
  `confidence-threshold = 0.93`; `[bans] multiple-versions = "warn"`; `[sources] unknown-registry = "deny"`,
  `unknown-git = "deny"`.
- `apps/orcel-firecrawl/deny.toml` (created with the component in WP1-08) allows `AGPL-3.0` for the component crate
  only (`[[licenses.exceptions]] name = "orcel-firecrawl"`).
- `scripts/check-npm-licenses.mjs` and `.test.mjs`: walks every `package-lock.json` under `apps/`, `packages/`,
  `tests/`; reads each package's `license`; applies the allowlist; `tests/` may add `PSF-2.0`; exits non-zero naming the
  package and lock file.
- `scripts/check-agpl-markers.mjs` and `.test.mjs`: scans `crates/`, `apps/`, `packages/`, `tests/` for
  `GNU AFFERO` and `SPDX-License-Identifier: AGPL`; allowed only under `apps/orcel-firecrawl/` and in the paths listed in
  `docs/orcel/notices/fd06-files.txt` (new; one repository-relative path per line, from the FD-06 record).
- `scripts/check-provenance.mjs` and `.test.mjs`: every directory named `upstream`, `third_party` or `vendor` under
  `apps/` and `third_party/` holds a `PROVENANCE.json` with `repo`, `sha` (40 hex), `paths`, `licence`,
  `attestation_ref` (a file under `docs/orcel/grants/` or `null`) and `patches`, and a licence text file.
- `crates/orceld/tests/dependency_direction.rs`: runs `cargo metadata --format-version 1` and asserts section 3's rules.
- `.github/workflows/ci.yml`: add `cargo deny check licenses bans sources` for the root workspace on all three Rust
  legs, and the three node scripts on the Governance job.

Definition of done: current main passes; a fixture crate with an AGPL dependency, a fixture file with an AGPL header
outside the allowlist, an unpinned `upstream/` directory and a kernel crate depending on an app each fail.
Tests: the commands above. CI: all legs.

#### WP1-02 Contracts v1 (ready)

Files in `crates/orcel-contracts/src/`: `identity.rs` (Principal, PrincipalKind, Device, OsFamily, Arch,
OsIdentityBinding), `lease.rs` (LeaseView, LeaseState, LeaseRef, GrantRef, DispatchAuthority, StandingApproval,
AuthorityMode, ExecutorClass moved), `session.rs`, `tool.rs` (ToolEntry, EffectClass, ApprovalClass, RemoteExposure),
`capability.rs` (CapabilityReport, CapabilityEntry, CapabilityStatus with `permission_required`), `job.rs` (Job,
JobKind, JobOutcome, JobProgress, ExecutionState moved), `event.rs` (AuditEvent, AuditEventKind, AnchorRef), `sidecar.rs`
(section 4.9 frames), `web.rs` (WebCrawlRequest, WebScope, HeaderSpec, PrivacyProfileRef, Ids, Engine, SitemapMode,
ExtractRequest), `canonical.rs` (`canonical_json`), and `lib.rs` (`FailureCode` additions of 4.10 and `http_status`).
`orcel-policy/src/full_control.rs` re-exports the moved enums. Dev-dependency `schemars =1.2.3`; `tests/contracts.rs`
(round trips over `tests/fixtures/*.json`, unknown-field refusal, frozen spellings, canonical JSON vectors, every
`FailureCode` mapped), `tests/schema_drift.rs` (regenerates `docs/orcel/contracts/schema/*.json`).
Definition of done: `cargo test -p orcel-contracts` and `cargo test -p orcel-policy` pass with no behaviour change.

#### WP1-03 Audit chain (ready)

Files: `crates/orcel-audit/src/chain.rs` (`ChainWriter::open(path)`, `append(&mut self, AuditEvent) -> Result<AnchorRef>`
flushing with `File::sync_data`, `rotate`), `verify.rs` (`verify_file`, `verify_with_anchors`), `anchor.rs`
(Windows: `RegisterEventSourceW`, `ReportEventW`, `EvtQuery`; `windows-sys` features `Win32_System_EventLog`; other OSes:
no-op returning `AnchorUnavailable` until track X). `crates/orceld` calls the writer before each dispatch in the existing
dispatch function of `main.rs` and refuses on error. `crates/orcel-lifecycle/src/commands.rs` adds `orcel audit verify`.
Tests: `cargo test -p orcel-audit chain_` (edit, delete, reorder, truncation, rotation), `cargo test -p orceld
audit_chain_`, `cargo test -p orceld audit_anchor_` (Windows), `cargo test -p orceld --test audit_anchor_standard_user`
(Windows, temporary standard account), `node scripts/check-audit-redaction.mjs`. Definition of done: as tests, plus no
raw argv, URL, header value or SID in any event. Security judge: yes.

#### WP1-04 orcel-jobs (ready)

Files: `crates/orcel-jobs/Cargo.toml` (deps: orcel-contracts, orcel-journal, serde, serde_json, sha2, fs4);
`src/lib.rs` (`JobStore::open(root)`, `submit(JobSpec, owner) -> JobId`, `claim_unit`, `complete_unit`, `cancel`,
`status(id, owner)`, `list(owner)`, `on_restart()`), `queue.rs`, `throttle.rs` (`Throttle::wait_for(origin)`),
`retry.rs`, `concurrency.rs`, `checkpoint.rs`, `store.rs`, `budget.rs` (`Budget::defaults()`, `load(path)`,
`validate(&WebCrawlRequest)`, resource-protection ceilings of 4.11), `owner.rs`. Tests: unit tests per module;
state-machine property tests; restart test; throttle within 10 ms; budget validation; store caps. CI: all legs.

#### WP1-05 orcel-web (ready)

Files: `crates/orcel-web/Cargo.toml` (deps: orcel-contracts, serde, serde_json); `src/v2.rs` (ScrapeRequestV2,
MapRequestV2, CrawlRequestV2, BatchScrapeRequestV2, SearchRequestV2, FormatV2), `src/v1.rs` (v1 bodies mapped to v2),
`src/refuse.rs` (every unsupported field refused by name with its wave), `src/translate.rs` (`scrape_envelope`,
`crawl_request`, `map_request`, `batch_request`, `search_envelope`), `src/document.rs` (`document_v2`), `src/status.rs`
(5.5), `src/policy_fields.rs` (headers, privacy and task extraction for `orceld` to check). Tests: `cargo test -p
orcel-web` with fixtures written from the MIT SDK types, one per row of 5.3 and 5.4.

#### WP1-08 Fetch engine and the Firecrawl component (ready)

Files:
- `apps/orcel-firecrawl/` (own workspace): `Cargo.toml` (`license = "AGPL-3.0"`, deps of 7.2), `LICENSE` (upstream root
  text), `NOTICE`, `PROVENANCE.json` (`firecrawl/firecrawl`, `42f4d669954649ce33466a2a50e8215c7f1f4d1c`, the copied
  paths, `attestation_ref: docs/orcel/grants/2026-11-17-founder-attestation.md`), `PATCHES.md`, `deny.toml`,
  `rust-toolchain.toml` (1.97.1), `src/upstream/{html,markdown,crawler,xml,utils}.rs` (copied; patches: remove `#[napi]`
  and `napi::Result` wrappers, remove `nodesig`, keep function bodies), `src/main.rs` (stdin request, stdout result,
  4.17 operations), `tests/` (upstream behaviour fixtures plus Orcel protocol tests).
- `crates/orcel-provider-process/src/contained.rs`: a pinned entry for the component (path and SHA-256, as for the
  document parser).
- `crates/orceld/src/web_fetch_engine.rs`: governed fetch (Windows WinHTTP transport of `orcel-provider-network`, DNS
  pin and exact-peer check unchanged) then `transform_html` in the component.
- Release packaging: the component ships as `orcel-firecrawl-<ver>-windows-x64.zip` with its source archive, listed as
  an optional component by `scripts/package-release.mjs`; the core archive does not contain it.
Tests: `cargo test` in `apps/orcel-firecrawl` (output equals upstream fixtures for main-content, tag filters, links,
metadata, sitemap); `cargo test -p orceld web_fetch_engine_` (Windows; deterministic resolver and transport); a 60 s fuzz
run of `transform_html`. On macOS and Linux the engine reports `unsupported` until WP1-13.

#### WP1-06 to WP1-16 (implementation follows the ready packets)

| Packet | Scope | Prerequisites | Key tests | Runners |
| --- | --- | --- | --- | --- |
| WP1-06 | `orceld` web and job dispatch, `FetchCrawlDriver`, approvals of 4.11, budgets, ownership | 03, 04, 05, 08 | `cargo test -p orceld web_`, `fetch_crawl_` | Windows; others `unsupported` until WP1-13 |
| WP1-07 | MCP tools, Firecrawl REST routes, REST tokens, network-tool guard amendment for the eight web tools | 06 | `npm test` in `apps/orcel-mcp` | all |
| WP1-09 | Firecrawl contract harness, both SDKs, pinned fixture site | 07, 08 | `npm test` in `tests/firecrawl-compat/js`; `python -I -m pytest tests/firecrawl-compat/py` | Windows; X legs when WP1-13 lands |
| WP1-10 | Authority service (Windows), `orcel authority install/enroll`, pipe anti-squatting and client server-identity checks, grant window after service-observed unlock, narrow default scope, Event Log scope record (4101), Hello presence, Authorize/Stop, service-owned Job Objects, `orceld fc-worker`, lease store migration from the user state root, dispatcher in `orceld`, SG-000095 path moved behind it | 02, 03 | `cargo test -p orcel-authority`; `cargo test -p orceld full_control_dispatch_`; Windows native: service install in CI; standard-user caller cannot read service state; a pre-created pipe makes the service refuse to start; a rogue pipe instance cannot be created by a user process; clients refuse a server whose PID or owner SID is wrong; grant refused without a recorded intent, outside the unlock window after it, and while a lease is active; a routine lock and unlock without an intent opens nothing; the `WTSSendMessageW` confirmation shows the intent's scope and cannot be answered by `SendInput` or `PostMessageW` from a medium-integrity process (or is recorded as not input-protected); No and timeout clear the intent; events 4101 and 4102 recorded; Event Log 4101 matches the granted scope; `orceld` cannot terminate or change a service-owned job and a child cannot break away; Stop kills an in-flight `fc-worker` operation; stop by session lock (`LockWorkStation`) and expiry; audit records carry `asserted_by_session`, caller PID and image; no lease means Safe path unchanged | Windows native; security judge |
| WP1-12 | Indicator (4.14) | 10 | `cargo test -p orcel-indicator`; Windows native visibility, injected-input, close-as-Stop, hotkey-failure and `DisableLockWorkstation` tests | Windows; security judge |
| WP1-14 | Standing approvals (4.15) | 10, 12 | `cargo test -p orcel-authority standing_` (scope, client, expiry, stop) | Windows; security judge |
| WP1-15 | Executors: SG-000096 interactive shells (PowerShell, cmd, Git Bash, WSL bash; ConPTY; T02-T04), SG-000097 filesystem across authorized roots, process inspection and termination, app launch and close | 10, 14 | SG-000096 and SG-000097 suites; every executor and the `fc-worker` in a service-owned Job Object; stop kills every tree | Windows; security judge |
| WP1-16 | Credential headers and the sensitive-feature gate (4.12, 4.16), SG-000040 header amendment | 06, 07 | `cargo test -p orceld web_headers_`, `web_privacy_`; redaction scan | Windows; others with WP1-13 |
| WP1-11 | Journeys J-1, J-2, J-3, J-3b; README and `RELEASE_READINESS.md` | all | 10.1 | Windows; founder-present runs |

### 8.3 Track X (cross-platform, starts now; FD-UP-7 and FD-UP-12 decided)

| Packet | Scope | Key tests |
| --- | --- | --- |
| WP1-13 | macOS and Linux HTTPS transport in `orcel-provider-network`: `rustls` with the platform verifier over a `TcpStream` connected to one address from the validated set, hostname kept for SNI and certificate identity, exact-peer check, redirect and body rules as on Windows; SG-000040 amended for these OSes | deterministic adapters; live probe to `https://example.com/`; peer mismatch; macOS and Linux native; security judge |
| WPX-01 | Authority service on macOS (LaunchDaemon, `_orcel`, XPC, Secure Enclave presence) and Linux (systemd, dedicated user, polkit, `SO_PEERCRED`, logind lock) | native install and caller-isolation tests |
| WPX-02 | Cross-platform web qualification (J-1 and J-2 on macOS 15 arm64 and Ubuntu 24.04 / Fedora 41) | harness on all legs |
| WPX-03 | Executors and indicator on macOS and Linux (zsh, bash; filesystem; apps; input via the native host) | J-3 and J-3b per OS |

### 8.4 Track B (browser engines, starts now; FD-UP-6 decided)

| Packet | Scope |
| --- | --- |
| WPB-01 | Engine abstraction, capture contract (screenshot, PDF, tabs), Chromium/Playwright full fallback, engine reported per task, fallback never silent |
| WPB-02 | Obscura patched build (6.3): vendored, `--locked --offline`, V8 archives by SHA-256, provenance attested, pipe CDP, no listener, egress via the host broker or sandbox-denied, sensitive features behind the 4.16 gate |
| WPB-03 | agent-browser parity port and corpus |
| WPB-04 | Measured corpus trial; Obscura preferred where qualified per capability, Chromium otherwise |

### 8.5 Wave 2 and Wave 3

Wave 2: WP2-08 extraction metadata and privacy defaults; WP2-09 REST/OpenAPI from the catalog; WP2-10 TS SDK;
WP2-11 Firecrawl W2 rows; WP2-13 copied extract pipeline and structured outputs in the component; WP2-14 sensitive
privacy features per engine; SG-000100 browser profiles under Full Control. Wave 3: Android ADB (phone-harness port),
iPhone Mirroring, remote screen on the relay (SG-000105), Fleet reporting, Mika as a paired device, Python SDK,
model-backed `/v1` rows.

## 9. Platform floors

| Platform | Floor | Notes |
| --- | --- | --- |
| Windows | Windows 10 1809 (build 17763) or later, Windows 11, x64 | Hello key credentials (`Windows.Security.Credentials.KeyCredentialManager`) need a configured Hello PIN or biometric; availability on the 1809 floor is confirmed by the WP1-10 test; TPM optional (software KSP fallback); the authority service needs one administrator-consented install |
| macOS | 15.0 Sequoia, Apple Silicon | Unsigned development builds until FD-05; daemon install needs an administrator |
| Linux | Ubuntu 24.04 LTS, Fedora 41, x86_64; GNOME 46+, KDE Plasma 6 | Landlock ABI 3+, cgroup v2, polkit, logind |
| Android, iPhone | adb devices; iOS 18+ mirrored to macOS 15+ | Wave 3 |

## 10. Acceptance journeys and release gates

| Journey | What a person does | Pass criteria |
| --- | --- | --- |
| J-1 | Firecrawl SDK with explicit `apiUrl` scrapes, maps, crawls and searches (scripted fixture site; founder leg `https://docs.python.org/3/library/`) | Approvals visible; engine named; budgets and robots honoured; Firecrawl component output matches upstream fixtures; audit verifies |
| J-2 | Crawl, then cancel | Cancel probe: `cancelled` within 2 s; no fixture request after the acknowledgement beyond the in-flight page |
| J-3 | Grant Full User with Hello for a declared task; agent drives Notepad by keyboard and mouse; stop by the indicator, then again by Win+L | Every dispatch authorized and audited by the service; stop kills within 1 s; next call `LEASE_INVALID` |
| J-3b | Same grant; agent runs a PowerShell build in a visible terminal, edits files across an authorized drive, launches and closes an app | Everything visible and usable on the desktop; standing approval covers the task; out-of-scope paths refused; stop kills every Orcel-started tree |
| J-4 to J-8 | macOS/Linux parity, dual engine, App/MCP/API equivalence, mobile, remote | As revision 5 |

| Gate | Measure |
| --- | --- |
| G-1 | Contract fixtures, schema drift, frozen spellings, every `FailureCode` mapped |
| G-2 | Licence and provenance gates green; AGPL only in `apps/orcel-firecrawl` and FD-06 paths; source archive attached for the component |
| G-3 | 100% of Full Control dispatches have a service authorization and audit record written first; Safe golden pairs unchanged |
| G-4 | No Orcel child owns a listening socket except the documented loopback server; the authority service's state is unreadable by a standard-user process |
| G-5 | Every capability entry and parity row backed by a passing test or reported `unsupported`/`permission_required`/`blocked` |
| G-6 | Cancel 2 s; stop to executor death 1 s via indicator, CLI, session lock and expiry |
| G-7 | **Optimisation targets, measured and reported, not hard limits (FD-UP-13 decided):** 300 MB peak across Orcel processes excluding engines during the 50-page fixture crawl; 60 MB idle `orceld` |
| G-8 | Cross-platform legs green; native journeys per claimed OS |
| G-9 | Release provenance; component packaged separately with source; agents never approve the `release` environment |
| G-10 | Real consent runs by the founder, or recorded as pending |
| G-11 | Audit anchors verify on every journey |

## 11. Founder decisions (DECIDED 2026-11-17)

Relayed by the coordinating agent on 2026-11-17; wording is this document's summary.

| # | Decision | Encoded in |
| --- | --- | --- |
| FD-UP-1 | Firecrawl: full feature parity, copy first. Founder attests full permission to copy and adapt authorized donor code (Firecrawl, Browser Use, others, including authorized private repositories), recorded separately from upstream terms. Core stays independently licensed where necessary; AGPL code that cannot enter it runs as an isolated, locally operated component with obligations and source offer. v2 native, v1 where practical; scrape, crawl, map, search, extract, batch, document processing, structured outputs, change tracking; no Firecrawl Cloud dependency | C-15 to C-17, 4.17, 5, 6, WP1-08, WP2-13, `docs/orcel/grants/2026-11-17-founder-attestation.md`, SG-000133 |
| FD-UP-2 | Stealth and fingerprinting: legitimate privacy and compatibility features included; sensitive ones configurable, off by default, per-client permission, audited; respect site authorization; no security bypass | C-19, C-31, 4.16, 5.3, WP1-16, WP2-14; inventory records moved from BLOCKED |
| FD-UP-3 | `vercel-labs/agent-desktop` added as a candidate donor; search for the original continues; verified Vercel browser and computer-use projects included; Exa Browser and TinyFish added to the extended inventory as NOT STARTED, source unverified (the separate REA effort has produced no outputs yet) | `capability_inventory.json`, `DONOR_INVENTORY.md` section 7 |
| FD-UP-4 | Grain ids: SG-000131 (contracts, audit chain, licence and provenance checks), SG-000133 (web intelligence: Firecrawl-compatible scrape, search, extract and browser-free fetch), SG-000134 (jobs, crawl, map, batch), SG-000132 (Windows Full Control); activate SG-000097 (full filesystem) and continue SG-000096 (interactive shell) so J-3b lands in Wave 1; SG-000101 and SG-000102 stay reserved | 12, WP1-00 |
| FD-UP-5 | One approval per crawl or batch job, bound to client, scope, parameters and task; destination scope still enforced | C-33, 4.11 |
| FD-UP-6 | Obscura preferred; an Orcel-specific secure patch (pipe CDP, sensitive features gated) authorized now without waiting on upstream; Chromium/Playwright full fallback, reported never silent | C-08, C-12, 6.3, track B |
| FD-UP-7 | Web tools in release builds once qualified; Windows first; macOS/Linux transport work starts now in parallel | 8.3, WP1-13 |
| FD-UP-8 | Custom request headers supported with OS secret storage, per-client permission, destination scoping, redaction | C-32, 4.12, WP1-16 |
| FD-UP-9 | Full Control architecture that prevents self-escalation and tampering while giving comprehensive control (all shells, filesystem across authorized drives, app management, window/mouse/keyboard, browser automation, processes, git, long-running automation, remote when authorized). Revision 6 replaces the revision 4 profiles with the authority service of 4.13: executors run on the user's desktop with the user's token; Orcel's keys, leases, audit and stop live in a separate service identity; OS limits stated in C-27 | C-25 to C-30, 4.13, 4.14, WP1-10, WP1-12, WP1-15, SG-000132, SG-000097, SG-000096 |
| FD-UP-10 | Standing approvals tied to identified client, declared task, scope and expiry; audited; emergency stop preserved | C-04, 4.15, WP1-14 |
| FD-UP-11 | Crawl page, depth, duration and resource budgets user-configurable with sensible defaults; no fixed product caps beyond resource protection | C-34, 4.11, WP1-04 |
| FD-UP-12 | macOS/Linux network implementation and cross-platform qualification approved, in parallel with Windows | 8.3 |
| FD-UP-13 | 300 MB peak and 60 MB idle are measured optimisation targets, not hard limits | G-7 |

**Consequences recorded for the founder (no decision requested; the founder can correct them):**
1. Full Control needs the authority service, installed once with administrator consent; without it Full Control
   answers `AUTHORITY_UNAVAILABLE` and every other feature works.
2. Full Control grants the agent the user's own rights; the OS limits in C-27 cannot be engineered away without
   giving up the comprehensive usability FD-UP-9 requires.
3. The existing SG-000095 desktop-input path moves behind the service, so after WP1-10 desktop input also needs the
   service.

## 12. Grain drafts and what this document does not do

Activation-ready drafts in [`unified-grains/`](unified-grains/) (state `GRAIN`, with a `draft_note` the activation PR
removes):

| File | Grain | Packets |
| --- | --- | --- |
| `SG-000131.draft.json` | Contracts v1, audit chain and anchors, licence and provenance gates | WP1-00 to WP1-03 |
| `SG-000133.draft.json` | Web intelligence: Firecrawl-compatible scrape, search, extract; browser-free fetch; the isolated Firecrawl component; credential headers and privacy gate | WP1-05, WP1-06 (scrape, search), WP1-07, WP1-08, WP1-09, WP1-16, WP1-13 (with track X) |
| `SG-000134.draft.json` | Jobs, crawl, map, batch, budgets | WP1-04, WP1-06 (jobs), WP1-07, WP1-09 |
| `SG-000132.draft.json` | Windows Full Control: authority service, dispatcher, indicator, standing approvals | WP1-10, WP1-12, WP1-14 |
| `SG-000097.draft.json` | Full filesystem and workstation parity under Full Control (DESKAL-P20) | WP1-15 |
| `SG-000096.amendment.draft.json` | Continuation of SG-000096 on the authority service | WP1-15 |

The earlier `SG-000101.draft.json` and `SG-000102.draft.json` are removed; SG-000101 and SG-000102 stay reserved for
their P20 roles. This document does not activate grains, import or build donor code, add dependencies, or change README
or release claims; the canonical SG-000093, SG-000095, SG-000108, SG-000010, SG-000040 and SG-000060 records govern
until their amendments land.

## 13. Review and decision history

### 13.0 Revision 2 (first fresh-context reviews)

| Finding | Resolution | Where |
| --- | --- | --- |
| R1 fetch transport Windows-only | **Superseded by FD-UP-7 and FD-UP-12 (revision 6): the macOS and Linux transport is built now in parallel, as WP1-13 (track X); the text below is history.** Chosen: fetch engine is **Windows-only in Wave 1**, reusing the qualified WinHTTP SG-000040 transport; macOS/Linux report `unsupported`. Justification: a non-Windows transport is new network authority needing its own guard amendment and judge (S3), and section 7.2 keeps runtime crate deps at zero. Scoped packet WP2-12 (rustls + platform verifier, DNS pin, exact peer, SG-000040 amendment) and FD-UP-12 | 2.3, 4.6, 5.1, WP1-06, WP1-08, WP2-12, 7.3, 11 |
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


### 13.4 Revision 6 (founder decisions of 2026-11-17)

The tables above record what revisions 2 to 5 did in answer to review findings. Revision 6 restructures the document
around the founder's decisions; where it changes a design those tables describe, the current sections govern:

| Earlier design | Revision 6 |
| --- | --- |
| Executors under restricted tokens, profile S on a hidden desktop and profile D for the native host, with deny ACEs on Orcel state and processes (revisions 2 to 5, sections 4.13 and 4.14 then) | Executors run on the user's desktop with the user's token so computer use works in full; Orcel's keys, leases, epoch, standing approvals, Full Control audit and stop move into the authority service (4.13); OS limits stated in C-27 |
| Indicator as an enforcement precondition holding Job Object handles and writing revoke requests | Indicator is disclosure plus a Stop that calls the service directly; the service holds the Job Objects and enforces expiry, session lock and sign-out (4.14) |
| Event Log anchor written per user without source registration | The service registers the source at install; the per-user unregistered write remains the fallback for `orceld`'s Safe chain where the service is absent (4.8) |
| Firecrawl reimplemented in Apache code only; AGPL sidecar optional | Copy first: the contract layer stays Apache, copied Firecrawl code runs in the isolated AGPL component `apps/orcel-firecrawl` (C-17, 4.17, WP1-08) |
| Stealth BLOCKED; headers refused; crawl caps fixed at 50/5/10 min | Opt-in sensitive features behind a per-client gate (4.16); credential headers from the OS secret store (4.12); budgets user-configurable with resource-protection ceilings only (4.11) |
| Fetch engine Windows-only, macOS/Linux deferred to Wave 2; Obscura patch pending a decision | Track X and track B start now (8.3, 8.4) |
| Grains SG-000131, SG-000101, SG-000102, SG-000132 | SG-000131, SG-000133, SG-000134, SG-000132, plus SG-000097 activated and SG-000096 continued (12) |
| G-7 numbers as blocking gates | Measured optimisation targets (G-7) |

### 13.5 Revision 7 (security review of `4e0f3606`)

| Finding | Resolution | Where |
| --- | --- | --- |
| 1 Pipe squatting (blocker) | Pipe created with `FILE_FLAG_FIRST_PIPE_INSTANCE` (service refuses to run if the name exists) and `PIPE_REJECT_REMOTE_CLIENTS`; client ACE `FILE_READ_DATA`, `FILE_WRITE_DATA`, `SYNCHRONIZE` only for `INTERACTIVE`, never `GENERIC_WRITE` or `FILE_APPEND_DATA` (`FILE_CREATE_PIPE_INSTANCE`); every client checks `GetNamedPipeServerProcessId` against `QueryServiceStatusEx` and the pipe owner against the `NT SERVICE\OrcelAuthority` SID before sending; automatic (not delayed) start | 4.13, WP1-10 |
| 2 Job Objects (blocker) | The service creates and owns every executor Job Object (random `Global\` name, fail if it exists, kill-on-close, no breakaway limits) and grants the session only `JOB_OBJECT_ASSIGN_PROCESS`; `orceld` checks the owner, creates suspended, assigns, resumes; Full Control filesystem, process and git operations run in an `orceld fc-worker` child inside a service-owned job, so Stop kills in-flight operations; 4.14 table updated | 4.13, 4.14, WP1-10, WP1-15, SG-000132, SG-000097, SG-000096 amendment |
| 3 Audit as claims (major) | `AuditEvent` gains `asserted_by_session`, `caller_pid`, `caller_image`; C-27 (e) states that during a lease the agent can impersonate `orceld` to the service, so the Full Control audit is tamper-evident storage of session-asserted claims plus service-observed facts | C-27, 4.8, 4.13 |
| 4 Hello does not show scope (major; blocker before SG-000105) | Grants, renewals and standing approvals only inside a 120 s window opened by a service-observed `WTS_SESSION_UNLOCK` with no lease active; narrow default scope; granted scope written to the Event Log (event 4101) and shown by the indicator as the service reports it; SG-000105 must not ship before this | 4.13, 4.14, SG-000132 |
| 5 Heartbeat (nit) | Stated: the indicator heartbeat proves nothing against a same-user agent | C-27 (c), 4.13, 4.14 |
| 6 PIN observation (nit) | C-27 (d): persisted code from an earlier session can observe a PIN at a later grant; biometric Hello recommended in the grant prompt | C-27, 4.13 |

### 13.6 Revision 8 (nits from the review of `d6f2b3ba`)

| Nit | Resolution | Where |
| --- | --- | --- |
| 1 Owner check needs `READ_CONTROL` | `INTERACTIVE` now gets `FILE_READ_DATA`, `FILE_WRITE_DATA`, `SYNCHRONIZE` and `READ_CONTROL`; `READ_CONTROL` cannot create pipe instances | 4.13 |
| 2 Induced grant windows | Chosen design: a grant needs a prior **grant intent** recorded by the service (one per session, 5-minute expiry, Event Log 4102), then a service-observed unlock, then a **service-rendered confirmation** (`WTSSendMessageW`, created by the system for the service, showing scope, client, task and expiry, Yes/No, 60 s), then Windows Hello. Routine unlocks without an intent open nothing. Residual recorded in C-27 (f): a same-user process can record an intent and lock the session, and can cover or imitate the confirmation, so the user must read the scope in the service's own confirmation; WP1-10 verifies the confirmation cannot be answered by injected input, and records it as not input-protected if that fails | C-27 (f), 4.13, WP1-10, SG-000132 |
