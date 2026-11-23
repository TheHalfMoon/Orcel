# Cotra Architecture and Delivery Plan

Status: CANONICAL PLAN (delivered through COTRA-P13; the current canonical state is recorded in `docs/canonical/CURRENT.md`)
Planning snapshot: 2026-09-23
Canonical bootstrap base: 7de4779682b9e8dc794d6c675d7ed6c420355d13
Target platform: Windows 11 first
Primary client: ChatGPT through MCP
Default connectivity: OpenAI Secure MCP Tunnel
Founder-funded hosted infrastructure: NONE

## 1. Product definition

Cotra means Computer Orchestration & Trusted Runtime Access.

Cotra is a standalone, local-first MCP gateway that lets an authorized ChatGPT session inspect and operate a Windows computer through bounded, auditable capabilities. It is not a generic remote shell and it is not a public remote desktop service.

The product goal is to replace the useful day-to-day behavior of tools such as Desktop Commander while materially improving the trust model:

ChatGPT
  -> OpenAI Secure MCP Tunnel
  -> cotra-mcp
  -> local policy kernel
  -> approval boundary
  -> typed Windows capability providers
  -> evidence + audit

The MCP protocol is a client integration boundary. It is not the privileged security boundary.

## 2. Non-negotiable invariants

1. No inbound public port is required for the default ChatGPT path.
2. The local privileged authority never trusts MCP tool annotations as authorization.
3. No universal run_anything tool exists.
4. Every request is normalized before policy evaluation.
5. Every state-changing request is bound to a workspace/session identity.
6. File authorization is evaluated against final resolved Windows paths, not string prefixes.
7. Child processes never inherit Cotra tunnel credentials or secret-store credentials.
8. Process lifecycle controls such as Job Objects are never described as a sandbox by themselves.
9. Human approval is a separate authority. The agent must not approve its own protected action.
10. Cotra-owned approval surfaces are excluded from desktop automation and input injection.
11. High-risk approvals require strong local user presence, not only an automatable UI button.
12. Structured automation is preferred over visual automation.
13. Visual coordinate control is a last-resort provider with a lower capability ceiling.
14. Network egress is destination-scoped and fail-closed.
15. Secrets are redacted from model output, logs, error messages, and child environments.
16. A successful request is not reported as verified unless a postcondition was actually checked.
17. Cancellation is not equivalent to verified process termination.
18. The default architecture requires no Cotra-hosted paid infrastructure.

## 3. Architecture decision

Cotra is standalone. Kernux is not a dependency and Cotra must not modify or depend on Kernux governance, runtime, or release state.

The implementation is split into narrow processes so compromise of the MCP edge does not automatically become unrestricted local authority.

### 3.1 cotra-mcp

Language: TypeScript / Node.js.

Responsibilities:
- MCP tool/resource exposure.
- JSON schema validation at the protocol edge.
- client session identity.
- request correlation IDs.
- translation between MCP requests and Cotra internal contracts.
- streaming progress and typed failures.
- no direct privileged Windows calls.
- no direct secret-store access.
- no direct approval authority.

Reasoning:
- the TypeScript MCP ecosystem is mature;
- this process should remain disposable and low authority;
- protocol churn should not force changes in the security kernel.

### 3.2 cotrad

Language: Rust.

Role: local policy and authority kernel.

Responsibilities:
- capability grants.
- workspace registry.
- normalized request authorization.
- approval policy.
- audit/evidence policy.
- provider routing.
- egress policy.
- versioned internal contracts.
- denial reasons that are safe to expose to the MCP client.

Windows hardening target:
- run under a dedicated service identity when service mode is introduced;
- protect configuration and policy state with filesystem ACLs;
- expose only authenticated local IPC;
- never expose an unauthenticated TCP listener.

### 3.3 cotra-session

Language: Rust.

Role: per-interactive-session Windows adapter.

Responsibilities:
- UI Automation.
- screenshots.
- window/process observation requiring the interactive desktop.
- clipboard access.
- constrained input injection when explicitly authorized.
- user-session browser launch/attachment.

cotra-session does not decide policy. It receives signed/bound work from cotrad and returns evidence.

### 3.4 cotra-approve

Implementation target: Tauri or native Windows UI with a Rust core.

Role: local human approval and trust UI.

Approval levels:
- SOFT: local explicit click for lower-risk writes/network actions.
- STRONG: local user-verification flow for destructive, privileged, security-sensitive, or trust-boundary-changing actions.

STRONG approval should use a Windows user-presence mechanism such as Windows Hello/WebAuthn where feasible. A plain automatable button is not considered sufficient for the highest-risk class.

### 3.5 cotra-tunnel

Cotra does not reimplement OpenAI Secure MCP Tunnel in the first release.

Responsibilities:
- supervise the official openai/tunnel-client binary/process;
- validate configured profile health;
- expose tunnel status locally;
- keep the runtime API key out of cotra-mcp tool data and child process environments;
- provide installation guidance and version reporting;
- never silently copy the tunnel key into logs or support bundles.

### 3.6 provider boundary

Providers are separate typed modules:

- fs
- process
- powershell
- git
- apps
- uia
- screenshot
- browser
- clipboard
- network
- system

A provider receives only an already-authorized request plus the minimum contextual capability token required for that operation.

## 4. Internal request model

Every privileged operation is represented by a normalized request envelope.

Required fields:
- request_id
- client_session_id
- workspace_id
- capability
- operation
- normalized_target
- normalized_arguments
- requested_risk
- policy_revision
- provider_ceiling
- created_at
- expires_at
- correlation_id

Optional fields:
- expected_origin
- expected_window_identity
- expected_file_identity
- expected_process_identity
- expected_git_head
- network_destination
- secret_reference_ids
- postcondition

The internal IPC protocol is versioned and typed. Initial implementation may use length-prefixed JSON over Windows named pipes with strict schemas. It must not reuse the external MCP connection as the authority channel.

## 5. Capability taxonomy

Cotra evaluates both capability family and effect level.

Effect levels:
- OBSERVE
- READ
- PROPOSE
- WRITE
- EXECUTE
- NETWORK
- DESTRUCTIVE
- PRIVILEGED

Examples:

OBSERVE:
- system.status
- apps.list
- process.list
- git.status

READ:
- fs.read
- fs.search
- browser.snapshot
- clipboard.read

PROPOSE:
- fs.patch.preview
- git.commit.preview
- process.command.preview

WRITE:
- fs.write
- fs.patch
- git.stage
- clipboard.write

EXECUTE:
- process.spawn
- powershell.run
- git.commit
- browser.navigate

NETWORK:
- browser.external_request
- network.fetch
- package.download

DESTRUCTIVE:
- fs.delete
- git.reset_hard
- process.kill_tree
- browser.clear_profile

PRIVILEGED:
- service.install
- policy.change
- workspace.trust_change
- credential_binding_change
- elevation.request

## 6. Permission profiles

Profiles are policy templates, not bypass modes.

READ_ONLY:
- OBSERVE + READ within trusted workspaces.
- no mutation.
- no process execution.
- no external network beyond tunnel transport.

DEVELOPMENT:
- adds bounded WRITE and EXECUTE in trusted developer workspaces.
- Git mutation allowed.
- package/network actions require destination policy and may require approval.

BALANCED:
- intended default.
- reads are mostly automatic inside trusted scopes.
- writes and execution are risk-classified.
- sensitive writes, personal browser profile access, clipboard reads, and external network may require approval.

FULL:
- broadest configurable capability set.
- does not disable strong approval for PRIVILEGED actions.
- does not disable hard denials or protected Cotra surfaces.

## 7. Workspace model

A workspace is a security object, not only a path.

Workspace record:
- workspace_id
- display_name
- allowed_roots
- denied_subtrees
- allowed_git_repositories
- allowed_process_cwd roots
- network policy
- browser profile policy
- approval overrides
- trust state
- revision

Rules:
- requests bind to one workspace_id;
- a session cannot silently change workspace;
- changing trusted roots is PRIVILEGED;
- root membership is checked using final Windows path identity;
- workspace revision is included in approval digests;
- stale approvals do not survive policy/workspace revision changes.

## 8. Windows filesystem security

String-prefix checks are prohibited as the final authorization mechanism.

Read/open flow:
1. parse and normalize the requested path;
2. reject unsupported device namespaces and malformed alternate forms;
3. open the object or safe ancestor with Windows file APIs;
4. resolve the final path using handle-based resolution;
5. record volume/file identity when practical;
6. evaluate the final resolved target against workspace policy;
7. execute the operation using the validated identity where possible;
8. re-check critical identity after mutation-sensitive transitions.

Create flow:
1. resolve and authorize the parent directory;
2. reject unsafe reparse-point transitions;
3. create relative to the authorized parent;
4. resolve the created object;
5. verify it remained inside policy;
6. fail closed on ambiguity.

Must test:
- symlinks;
- junctions;
- mount points;
- alternate data streams;
- device paths;
- UNC paths;
- case normalization;
- trailing spaces/dots behavior;
- long paths;
- race attempts;
- parent replacement.

## 9. Process and PowerShell security

### 9.1 process.spawn

Default interface is argv-first:
- executable
- argv[]
- cwd
- curated env
- timeout
- stdin policy
- output bounds
- network class
- postcondition

Raw shell concatenation is not the primitive.

### 9.2 powershell.run

PowerShell is a separate capability because script text has a larger effect surface than argv-only process launch.

Controls:
- explicit workspace cwd;
- sanitized environment;
- output/time limits;
- no tunnel key inheritance;
- no Cotra secret-store handles;
- no implicit profile loading by default;
- transcript metadata without storing secret values;
- policy can require script preview approval;
- high-risk commands remain denied even if syntactically valid.

ConstrainedLanguage may be used when the host is already protected by Windows application-control policy. Cotra must not claim ConstrainedLanguage alone is an unbypassable sandbox.

### 9.3 process containment

Use restricted tokens / reduced privileges where feasible.

Use Job Objects for:
- grouping child processes;
- lifecycle accounting;
- kill-on-close behavior where appropriate;
- resource controls.

Job Objects are lifecycle/resource controls, not the sole security boundary.

The hardened target should prevent agent-spawned processes from opening Cotra policy/approval IPC or reading Cotra protected state.

## 10. Secrets

Secret classes:
- tunnel runtime credential;
- external service tokens;
- browser/session credentials;
- Cotra internal keys.

Rules:
- secrets are referenced by opaque IDs;
- tools never return raw secret values;
- secrets are never injected into unrelated child environments;
- redaction occurs before audit/model output;
- support bundles exclude secret material;
- secret access is a separately audited capability.

Windows storage:
- use Windows protected storage primitives;
- per-user secrets may use DPAPI user scope;
- service-scoped secrets should use a service-bound protected mechanism such as CNG/DPAPI-NG or equivalent ACL-bound design;
- machine-wide DPAPI scope is not treated as equivalent to per-identity secrecy.

## 11. Approval architecture

### 11.1 approval digest

An approval is bound to:
- request_id
- capability
- exact normalized target
- exact argv/script digest
- workspace_id
- workspace revision
- network destination
- expected origin/window/process identity
- secret reference IDs, never secret values
- consequence summary
- policy revision
- nonce
- expiry
- reuse scope

Any material drift invalidates the approval.

### 11.2 protected surfaces

When an approval is pending:
- Cotra approval windows are hard-denied targets for UI Automation;
- Cotra processes/windows are hard-denied for coordinate input;
- any global interactive input lease held by the agent is suspended;
- the MCP client cannot call an approve tool;
- approval is accepted only through the local approval authority.

### 11.3 strong approval

PRIVILEGED and selected DESTRUCTIVE operations require strong local presence.

Strong approval should resist synthetic input. Windows Hello/WebAuthn-style user verification is the preferred target when available.

Threat-model truth:
If arbitrary code executes as the same fully privileged user with access to Cotra memory/state, a soft same-user UI prompt alone cannot be considered a complete security boundary. Cotra therefore combines privilege reduction, separate identities/IPC, protected state, and strong user verification for the highest-risk operations.

## 12. Git provider

Expose Git as typed operations before shell use:
- status
- diff
- log
- branch list
- create branch
- stage
- unstage
- commit
- fetch
- compare
- push
- guarded reset/revert

Requirements:
- repository must be within an allowed workspace;
- expected HEAD can be supplied for mutation;
- push is NETWORK + WRITE;
- force push is DESTRUCTIVE and denied by default;
- destructive history rewrite requires strong approval if enabled at all;
- success includes resulting commit/ref evidence.

## 13. Browser hierarchy

Preferred order:
1. page-provided structured tools such as WebMCP where explicitly trusted;
2. Playwright/DOM/accessibility tree;
3. semantic browser provider;
4. visual browser understanding;
5. coordinate input.

Default browser mode:
- dedicated Cotra automation profile;
- no personal cookies by default;
- downloads scoped to workspace;
- uploads scoped to approved files;
- external origin changes visible in evidence.

Personal-profile mode:
- explicit opt-in;
- higher risk;
- origin-bound;
- credential/payment flows require approval policy.

Browser request security:
- validate scheme/host/port;
- re-resolve DNS where relevant;
- apply destination policy after resolution;
- prevent arbitrary SSRF into loopback/link-local/private ranges unless explicitly trusted;
- downloads are treated as untrusted input.

## 14. Windows UI Automation hierarchy

Desktop interaction priority:
1. application-specific typed adapter;
2. Windows UI Automation patterns;
3. targeted Win32 APIs;
4. browser DOM/accessibility provider;
5. screenshot + semantic vision;
6. coordinate input;
7. global keyboard/mouse injection.

UIA selectors should prefer stable attributes:
- process identity
- window identity
- AutomationId
- control type
- accessible name
- supported control pattern
- relative tree path

Before mutation:
- re-resolve stale elements;
- confirm expected app/window;
- confirm target pattern and enabled state;
- bind the action to current UI evidence.

Coordinate actions are forbidden against:
- Cotra approval UI;
- credential/security dialogs unless an explicit future design safely supports them;
- unknown windows when a sensitive action is pending.

## 15. Human input safety

Cotra uses an input lease for injected pointer/keyboard activity.

Rules:
- one automation owner at a time;
- human input interrupts automation;
- stale screen evidence invalidates the next coordinate action;
- emergency stop immediately revokes the lease;
- approval pending revokes/suspends the lease;
- agent cannot suppress the emergency stop.

## 16. Clipboard

Clipboard is sensitive by default.

READ:
- explicit capability;
- optional approval;
- size limit;
- content-type detection;
- secret-pattern redaction policy;
- never poll continuously by default.

WRITE:
- explicit capability;
- content preview in audit;
- no hidden binary formats in the first release.

## 17. Network egress

Every network-capable request declares an egress class:
- NONE
- TUNNEL_TRANSPORT
- DIRECT_DESTINATION
- CONNECTED_ACCOUNT
- EXTERNAL_MODEL
- EXTERNAL_TOOL
- REMOTE_RUNTIME
- UPDATE
- TELEMETRY

Default:
- TELEMETRY disabled;
- arbitrary proxying disabled;
- destination is explicit;
- redirects cannot silently widen destination authority;
- unknown sensitive egress fails closed.

Cotra is not a general-purpose tunnel or pivot proxy.

## 18. Audit and evidence

Audit event fields:
- event_id
- timestamp
- request_id
- client_session_id
- workspace_id
- capability
- operation
- normalized target summary
- policy decision
- approval decision/reference
- provider
- start/end state
- exit/status code
- evidence references
- redaction summary
- policy revision

Evidence may include:
- resulting file identity/hash;
- Git resulting HEAD;
- process exit code;
- verified process termination;
- UIA element state after action;
- resulting URL/origin;
- screenshot hash/reference.

Local storage target:
- SQLite or equivalent local store;
- filesystem ACL protection;
- append-only event semantics at the application layer;
- optional hash chaining for tamper evidence;
- no raw secret storage.

## 19. Typed failure model

Minimum failure classes:
- INVALID_REQUEST
- CAPABILITY_DENIED
- WORKSPACE_DENIED
- PATH_ESCAPE
- PATH_RACE_DETECTED
- APPROVAL_REQUIRED
- APPROVAL_DENIED
- APPROVAL_EXPIRED
- APPROVAL_STALE
- PROTECTED_SURFACE
- PROVIDER_UNAVAILABLE
- PROVIDER_CEILING
- PROCESS_TIMEOUT
- PROCESS_TERMINATION_UNVERIFIED
- OUTPUT_LIMIT
- NETWORK_DENIED
- ORIGIN_MISMATCH
- WINDOW_MISMATCH
- TARGET_STALE
- SECRET_ACCESS_DENIED
- TUNNEL_UNAVAILABLE
- POSTCONDITION_FAILED
- INDETERMINATE

Do not collapse security denials into generic INTERNAL_ERROR.

## 20. Secure MCP Tunnel integration

The preferred ChatGPT topology is:

ChatGPT
  -> OpenAI-hosted tunnel endpoint
  -> outbound HTTPS polling by official tunnel-client
  -> local cotra-mcp
  -> cotrad

Cotra does not need a public listener in this mode.

Operational requirements:
- health check;
- readiness check;
- tunnel profile validation;
- exact local MCP target;
- runtime credential kept out of Cotra tool results;
- clear disconnected/degraded status;
- local-only admin/status surfaces by default.

Public plugin distribution is a separate deployment model and is not required for the first product.

## 21. Zero-cost architecture rule

Cotra itself operates no required hosted control plane.

Allowed:
- local processes;
- local storage;
- official outbound tunnel client;
- user-selected third-party APIs or product subscriptions.

Not allowed as a default dependency:
- Cotra-operated paid relay;
- required Cotra cloud database;
- required Cotra SaaS auth;
- hidden per-request founder cost.

External account or API charges remain the responsibility of the selected external service and are not represented as Cotra-zero-cost guarantees.

## 22. Repository shape

Target monorepo:

apps/
  cotra-mcp/
  cotra-approve/

crates/
  cotrad/
  cotra-contracts/
  cotra-policy/
  cotra-audit/
  cotra-windows/
  cotra-session/
  cotra-provider-fs/
  cotra-provider-process/
  cotra-provider-git/
  cotra-provider-browser/
  cotra-provider-uia/

docs/
  canonical/
  security/
  research/
  governance/

.specgrain/
  specs/

tests/
  contract/
  security/
  windows/
  e2e/

## 23. Delivery program

### COTRA-P00 — Governance and provenance

Exit:
- architecture canonical;
- threat model canonical;
- source ledger pinned;
- Diffcipline review rules canonical;
- license decision recorded before donor code is copied.

### COTRA-P01 — Contracts and policy kernel

Implement:
- internal request envelope;
- capability/effect taxonomy;
- workspace identity;
- typed failures;
- policy decision object;
- local IPC skeleton.

Exit:
- deny-by-default;
- contract tests;
- malformed/unknown capability tests;
- no privileged provider yet.

### COTRA-P02 — Read-only workspace runtime

Implement:
- system.status;
- workspace.get;
- fs.stat/read/search/list;
- Git status/diff/log read-only;
- local audit.

Exit:
- reparse/junction/path-escape tests;
- no out-of-workspace read;
- evidence records;
- Windows native qualification.

### COTRA-P03 — Secure MCP Tunnel E2E

Implement:
- cotra-mcp;
- tunnel supervision/status;
- ChatGPT read-only flow.

Exit:
- no public inbound listener;
- disconnect/reconnect typed behavior;
- runtime key absent from child env/logs/model output;
- ChatGPT can read an explicitly trusted test workspace.

### COTRA-P04 — File mutation and approvals

Implement:
- patch preview;
- write/create/rename/delete;
- SOFT approval;
- exact target digest;
- TOCTOU protections.

Exit:
- approved target drift fails;
- Cotra approval window cannot be agent-targeted;
- destructive operations remain denied or strongly approved.

### COTRA-P05 — Process and PowerShell runtime

Implement:
- argv process execution;
- bounded PowerShell;
- reduced token strategy;
- Job Object lifecycle;
- output/time limits;
- termination evidence.

Exit:
- no tunnel secret inheritance;
- cancellation vs verified termination distinguished;
- Cotra protected state/IPC inaccessible to restricted child where architecture supports it.

### COTRA-P06 — Git mutation

Implement:
- branch/stage/commit/fetch/push;
- expected HEAD;
- typed evidence.

Exit:
- force push denied by default;
- network policy applied;
- resulting refs verified.

### COTRA-P07 — Strong approval and trust UX

Implement:
- strong user-presence path;
- workspace trust management;
- approval history;
- emergency revoke.

Exit:
- agent cannot produce a valid strong approval through its own tool/input surface;
- approval replay/drift tests pass.

### COTRA-P08 — Structured browser

Implement:
- isolated browser profile;
- Playwright/DOM/accessibility;
- origin binding;
- download/upload scope;
- egress controls.

Exit:
- SSRF tests;
- redirect widening tests;
- personal profile disabled by default.

### COTRA-P09 — Windows UI Automation

Implement:
- app/window observe;
- UIA tree query;
- invoke/value/select/toggle/scroll patterns;
- stale target detection.

Exit:
- Cotra windows protected;
- structured action preferred;
- expected process/window identity enforced.

### COTRA-P10 — Vision and coordinate fallback

Implement:
- screenshot evidence;
- visual target proposals;
- coordinate provider with input lease;
- human interruption.

Exit:
- provider ceiling enforced;
- protected surfaces denied;
- stale-frame tests;
- no silent fallback from structured denial into coordinates.

### COTRA-P11 — Clipboard and bounded network

Implement:
- clipboard read/write;
- network.fetch if still justified;
- destination controls;
- redaction.

Exit:
- no continuous clipboard surveillance;
- destination policy and private-address tests;
- secrets not emitted.

### COTRA-P12 — Installer and lifecycle

Implement:
- signed/reproducible release plan;
- per-user install first unless service hardening requires system install;
- tunnel-client setup assistant;
- start/stop/status/doctor;
- uninstall and state cleanup.

Exit:
- clean install on supported Windows;
- clean uninstall;
- explicit retained-data choices;
- recovery from failed update.

### COTRA-P13 — Release hardening

Exit:
- threat-model regression suite;
- dependency/license review;
- SBOM;
- artifact provenance;
- independent security review;
- fresh Windows E2E;
- rollback/recovery drill;
- no known blocking findings.

## 24. First usable release

The first useful release is not full desktop autonomy.

MVP capability:
- ChatGPT connects through Secure MCP Tunnel;
- explicit workspace trust;
- read/list/search files;
- bounded file edits with local approval;
- Git status/diff/branch/commit;
- bounded process/PowerShell execution;
- local audit/status;
- tunnel health;
- no unrestricted UI automation required for MVP.

This release should already be safer for everyday development work than an unrestricted shell-style MCP.

## 25. Testing strategy

Unit:
- schema normalization;
- capability decisions;
- approval digest;
- redaction;
- egress policy.

Property/fuzz:
- path normalization;
- URI parsing;
- request decoding;
- policy rule combinations.

Windows security:
- symlink/junction escape;
- parent replacement;
- restricted child access;
- named-pipe ACL;
- environment leakage;
- Cotra process targeting;
- approval replay.

Integration:
- MCP -> policy -> provider -> audit;
- timeout/cancellation;
- tunnel disconnect/reconnect;
- Git expected-HEAD conflicts.

E2E:
- fresh Windows user profile;
- trusted temporary workspace;
- ChatGPT through tunnel;
- read/edit/commit flow;
- approval flow;
- emergency stop.

Negative tests are mandatory for every privileged capability.

## 26. CI and qualification

Required CI as implementation begins:
- Rust format/lint/test;
- TypeScript format/lint/typecheck/test;
- dependency audit;
- license/provenance gate;
- SpecGrain schema gate;
- Diffcipline diff gate;
- secret scan;
- Windows native job;
- Linux jobs only for portable components without false parity claims.

No Windows-specific capability is considered proven by a Linux-only CI result.

## 27. Review gates

Every implementation PR must provide:
- exact base SHA;
- exact head SHA;
- changed-file list;
- diff stat;
- SpecGrain work packet;
- exact-head CI result;
- Windows qualification when applicable;
- Diffcipline exact-diff review;
- independent code review of the exact head, recorded on the PR (a process rule, not a GitHub check; `docs/governance/DIFFCIPLINE.md` section 10);
- Alibaba Open Code Review pass where integrated;
- security review for new capability/authority;
- negative and adversarial regression tests for every changed boundary;
- zero unresolved blocking review threads;
- post-merge verification before canonical effectiveness is claimed.

## 28. Source-reuse policy

Cotra may learn from and reuse compatible source only after:
1. source pin recorded;
2. upstream license verified;
3. user permission recorded when relevant;
4. copied/adapted files identified;
5. copyright/license notices preserved;
6. dependency or copy decision justified;
7. security assumptions re-reviewed for Cotra's stronger trust model.

Do not bulk-copy a donor architecture merely because code reuse is permitted.

## 29. Explicit non-goals for v1

- macOS/Linux host parity;
- Cotra cloud control plane;
- autonomous elevation;
- hidden browser credential scraping;
- credential-dialog automation;
- bypassing OS security prompts;
- arbitrary LAN pivoting;
- full unattended destructive desktop automation;
- public plugin marketplace distribution.

## 30. Implementation start condition

Implementation may begin when:
- this architecture is reviewed;
- THREAT_MODEL is reviewed;
- SOURCE_LEDGER is reviewed;
- SG-000001 is accepted;
- license decision for Cotra itself is recorded;
- no blocking architecture/security gap remains.

The first implementation packet is SG-000001: trusted read-only MCP path and policy skeleton.


## 31. Client identity and v1 trust mode

Cotra v1 is a single-owner local product.

The first release does not pretend that an arbitrary MCP request contains a cryptographically meaningful human identity. Instead:

- the configured tunnel/app connection is one remote client trust context;
- Cotra creates its own local client_session_id for each connected MCP session;
- local workspace grants and approvals remain authoritative;
- remote annotations, display names, or page/tool descriptions never become identity proof;
- multi-user enterprise delegation is deferred until an authenticated principal can be bound to local policy without guesswork.

If future OpenAI product metadata exposes a stable authenticated principal suitable for policy, Cotra may bind it only through an explicit versioned adapter and tests.

## 32. Protected Cotra state and local IPC

Cotra installation/state locations are never ordinary workspaces.

Protected classes:
- Cotra binaries;
- cotrad configuration;
- policy database;
- audit database;
- approval state;
- tunnel configuration/credentials;
- internal IPC endpoints.

Rules:
- filesystem tools hard-deny protected Cotra state even when a parent path is otherwise trusted;
- policy/trust changes use dedicated PRIVILEGED APIs, never general file write;
- cotrad IPC uses Windows named pipes or equivalent local IPC with explicit ACLs;
- authenticated session setup is separate from the MCP request itself;
- the hardened service design validates peer identity and minimizes which local processes can call privileged methods;
- agent-launched child processes must not receive Cotra IPC credentials/handles;
- a same-user string blocklist is not accepted as the security boundary.

Before EXECUTE is enabled, the implementation must prove that the selected restricted-token/service-identity model prevents ordinary agent-spawned children from directly changing Cotra protected state or forging approvals.

## 33. Long-running operations and reconnect semantics

Cotra distinguishes short tool calls from durable local operations.

Operation states:
- REQUESTED
- AUTHORIZED
- WAITING_APPROVAL
- QUEUED
- RUNNING
- CANCELLING
- COMPLETED
- FAILED
- CANCELLED
- INDETERMINATE

Long operations receive operation_id.

Required behavior:
- status can be queried after MCP reconnect;
- transport disconnect does not silently convert RUNNING to FAILED;
- policy decides whether a disconnect cancels a specific operation class;
- cancellation requests are idempotent;
- cancellation is not reported complete until termination/postcondition evidence exists;
- crash recovery marks uncertain work INDETERMINATE rather than inventing success;
- progress payloads are bounded;
- concurrency and queue limits prevent one client from exhausting the machine.

## 34. Privacy, retention, and support data

Cotra is local-first but local logs can still contain sensitive metadata.

Defaults:
- no product telemetry;
- no continuous clipboard capture;
- no continuous screenshot capture;
- no hidden browser-history collection;
- audit stores structured summaries rather than arbitrary full content where possible;
- secrets are redacted before persistence;
- screenshots are retained only when required for explicit evidence and under configurable retention;
- command output uses size/retention limits;
- support export is explicit, previewable, and redacted.

The user can purge:
- operation history;
- screenshots/evidence artifacts;
- cached browser automation state;
- local audit data subject to any chosen tamper-evidence policy.

Security-critical configuration changes remain separately recorded when policy requires it.

## 35. WSL boundary

WSL is a separate execution/filesystem trust boundary.

Do not treat WSL paths or processes as ordinary Windows paths by string conversion.

Future typed capabilities:
- wsl.list_distros
- wsl.exec
- wsl.workspace.map
- wsl.git.*

Rules:
- explicit distro allowlist;
- argv-style execution through wsl.exe --distribution <name> --exec -- <argv>;
- no implicit shell unless powershell/shell-equivalent authority is explicitly granted;
- Windows workspace and WSL workspace mappings are explicit;
- \wsl$ / \wsl.localhost paths are evaluated under a distinct provider policy;
- network effects inside WSL are classified as network authority;
- Cotra protected Windows state remains inaccessible through WSL paths where enforceable;
- WSL child environment does not inherit tunnel or Cotra secrets.

WSL support is not part of SG-000001. It belongs after the Windows process security model is proven.

## 36. Visual and screenshot safety

Default screenshot scope is the smallest useful target:
1. target window;
2. target monitor region;
3. full monitor only when necessary;
4. full desktop only by explicit capability.

Before a screenshot is returned:
- Cotra protected approval surfaces are excluded/redacted where feasible;
- evidence records scope and capture time;
- stale visual evidence has a short lifetime for coordinate actions;
- multi-monitor coordinates include monitor identity and DPI-aware transforms;
- a coordinate action cannot be replayed against a materially changed screen without revalidation.

## 37. Download and untrusted-file handling

Browser/network downloads are untrusted inputs.

Requirements:
- destination must be an approved workspace;
- preserve or add platform-origin metadata when practical;
- never auto-execute a downloaded file;
- executable/script/package launch is a new EXECUTE request;
- archive extraction re-applies workspace path traversal protections;
- filename/content-type mismatch is visible in evidence;
- package-manager installation is EXECUTE + WRITE + NETWORK and follows the same destination/approval model.

## 38. Project license decision

Planning decision in this PR: Apache License 2.0.

Reason:
- permissive open-source distribution;
- explicit patent grant;
- compatible at the project level with the MIT and Apache-2.0 source families currently being evaluated, subject to preserving upstream notices and file-level obligations.

This planning branch includes the Apache-2.0 license text. No donor source is imported by that act.

## 39. Architecture review result

The architecture is considered ready to start SG-000001 when this planning PR is accepted.

No unresolved design question blocks the read-only first grain.

Later grains still require proof before their authority can be enabled:
- EXECUTE requires restricted-child/protected-state evidence;
- STRONG approval requires a proven user-presence mechanism;
- browser personal-profile use requires origin and approval tests;
- UI coordinate control requires protected-surface and stale-frame tests;
- WSL requires separate provider policy.

These are staged proof obligations, not hidden implementation assumptions.
