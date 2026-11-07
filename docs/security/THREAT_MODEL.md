# Orcel Threat Model

> **Windows state root, 2026-11-07:** it is now `%USERPROFILE%\.orcel`, not `%LOCALAPPDATA%\Orcel`, which this document may still name. Other software on an ordinary account can hold rights on `AppData` that Orcel rightly refuses. See `crates/orcel-platform/src/paths.rs` and `legacy.rs`.

Status: INITIAL CANONICAL SECURITY MODEL
Date: 2026-09-23

> Product identity note: this model was authored under the Orcel program name.
> The current product is Orcel. `orceld`, `%LOCALAPPDATA%\Orcel` storage
> paths, and `Orcel`-qualified protected surfaces below denote retained
> compatibility identifiers governed by `docs/identity/ORCEL_RENAME.md`.

## 1. Security objective

Orcel must let an authorized AI client perform useful local work without turning MCP connectivity into ambient Windows authority.

The security target is capability-bounded local automation with explicit trust scopes, protected approvals, destination-scoped egress, secret isolation, and auditable evidence.

## 2. Trust zones

ZONE A — OpenAI product / remote MCP caller
Trusted to send authenticated requests from the configured product context.
Not trusted to define local authorization.

ZONE B — Secure MCP Tunnel transport
Trusted only as configured transport.
Not the local authorization authority.

ZONE C — orcel-mcp
Treat as network/protocol-facing and potentially compromiseable.
Must not hold broad privileged authority.

ZONE D — orceld policy kernel
Primary local authorization authority.
Protected state and IPC.

ZONE E — capability providers
Receive only bounded authorized requests.

ZONE F — interactive user session
Contains browser, desktop, clipboard, and human input.
Potentially sensitive and mutable.

ZONE G — local human approval
Independent authority for protected actions.

ZONE H — external destinations
Untrusted unless specifically allowed.

## 3. Protected assets

- user files;
- source repositories;
- SSH/Git credentials;
- browser sessions;
- clipboard contents;
- local application data;
- Orcel configuration;
- workspace policy;
- approval authority;
- tunnel runtime credentials;
- API tokens;
- audit trail;
- Windows account integrity.

## 4. Threats and required controls

### T01 — Public exposure of the local MCP server

Threat:
A local tool server is bound publicly or firewall/port-forwarding creates inbound exposure.

Controls:
- default Secure MCP Tunnel;
- loopback/private local bind only;
- no public listener in standard install;
- doctor detects unsafe bind;
- installer does not create inbound firewall rule.

Tests:
- fresh install has no inbound Orcel firewall requirement;
- network listener inventory verifies expected local-only state.

### T02 — MCP caller escalates through tool metadata

Threat:
The remote caller labels a tool safe/read-only and gains broader authority.

Controls:
- local policy ignores remote annotations for authorization;
- capability/effect is derived from local tool definition and normalized request.

Tests:
- falsified annotations do not change decision.

### T03 — Workspace escape through symlink/junction/reparse point

Threat:
A path appears inside an allowed root but resolves outside it.

Controls:
- handle-based final path resolution;
- reparse-point handling;
- authorized parent flow for creates;
- identity revalidation.

Tests:
- symlink/junction/mount escape;
- path alias variants;
- parent replacement race.

### T04 — TOCTOU path swap

Threat:
Target changes between authorization and operation.

Controls:
- open/validate by handle;
- operate on validated handle when possible;
- re-check identity on critical transitions;
- fail closed on ambiguity.

### T05 — Shell becomes universal bypass

Threat:
Agent uses PowerShell/cmd/native tools to read protected Orcel state, alter policy, approve requests, or exfiltrate secrets.

Controls:
- separate execution capability;
- reduced token strategy;
- protected orceld state/IPC;
- curated environment;
- no secret inheritance;
- deny protected Orcel paths/processes where enforceable;
- strong approval for policy/trust changes.

Residual risk:
If arbitrary code runs as the same unrestricted user with sufficient rights, complete isolation is not possible with application-level blocklists alone. Hardened releases must rely on OS identities/tokens/ACLs rather than string deny lists.

### T06 — Tunnel credential exfiltration

Threat:
Child process, log, crash dump, or tool output exposes the OpenAI tunnel key.

Controls:
- separate tunnel supervisor;
- narrow secret handoff;
- no child environment inheritance;
- redaction;
- support-bundle exclusion;
- process/env leakage tests.

### T07 — Agent self-approves via UI Automation

Threat:
Agent clicks its own approval dialog.

Controls:
- protected Orcel process/window identities;
- UIA provider denies Orcel approval surfaces;
- coordinate provider denies Orcel surfaces;
- suspend input lease while approval pending;
- no MCP approve tool.

### T08 — Agent self-approves via synthetic input

Threat:
Global keyboard/mouse injection activates approval.

Controls:
- suspend/revoke input injection during approval;
- highest-risk actions require strong user verification;
- soft approval not sufficient for PRIVILEGED class.

### T09 — Agent calls approval IPC directly

Threat:
A process spawned by the agent connects to local approval channel.

Controls:
- separate IPC;
- ACLs;
- capability-bound nonces;
- process/identity restrictions where feasible;
- restricted child tokens;
- no approval secret in environment.

Tests:
- agent child cannot forge/replay approval.

### T10 — Approval replay

Threat:
A previous approval authorizes a changed target/command.

Controls:
- digest includes exact normalized request, workspace/policy revision, nonce, expiry;
- one-shot by default;
- drift invalidates approval.

### T11 — Approval UI race / target changed after approval

Controls:
- expected target identity;
- short expiry;
- post-approval revalidation before execution.

### T12 — Browser SSRF / LAN pivot

Threat:
Browser/network provider accesses loopback, private network, metadata endpoint, or unexpected redirect.

Controls:
- destination policy;
- DNS/IP classification;
- redirect re-authorization;
- private/link-local/loopback denied unless explicit.

### T13 — Browser credential abuse

Threat:
Agent uses personal session to submit payment, expose secrets, or change account security.

Controls:
- isolated browser profile default;
- personal profile explicit;
- origin-bound capability;
- approval for credential/payment/security changes;
- no credential-dialog automation in v1.

### T14 — Page-provided tool injection

Threat:
WebMCP/page tool claims safe behavior or malicious schema/descriptions manipulate policy.

Controls:
- treat page tool metadata as untrusted;
- local capability mapping;
- explicit origin binding;
- schema size/depth limits.

### T15 — UI target confusion

Threat:
UI changes and action hits another application/control.

Controls:
- expected process/window identity;
- stable UIA selectors;
- stale element detection;
- re-resolve before mutation;
- visual evidence freshness.

### T16 — Coordinate fallback widens authority

Threat:
Structured action denied, agent falls back to unrestricted clicks.

Controls:
- provider ceiling travels with request;
- no silent escalation;
- coordinates require separate capability/approval;
- protected surfaces hard denied.

### T17 — Human/agent input collision

Threat:
User moves mouse/types while automation continues.

Controls:
- exclusive input lease;
- human input interrupts;
- stale frame invalidation;
- emergency stop.

### T18 — Clipboard secret leakage

Controls:
- no background polling;
- explicit read capability;
- size/type bounds;
- optional approval;
- redaction;
- audit without raw secret values.

### T19 — Process termination falsely reported

Threat:
Agent says a process stopped when descendants remain.

Controls:
- track process identity/tree;
- Job Object where applicable;
- verify termination;
- PROCESS_TERMINATION_UNVERIFIED failure.

### T20 — Output/log resource exhaustion

Controls:
- stdout/stderr byte limits;
- rate limits;
- timeouts;
- bounded screenshots;
- audit payload limits.

### T21 — Audit contains secrets

Controls:
- structured redaction before persistence;
- secret references instead of values;
- sensitive-field allowlist;
- security tests with seeded fake secrets.

### T22 — Audit tampering

Controls:
- protected ACL;
- append-only application semantics;
- optional hash chaining;
- export verification.

Residual risk:
Local administrator/malware can alter local evidence unless stronger external attestation is introduced. Orcel v1 does not claim resistance to a compromised administrator.

### T23 — Malicious update or dependency

Controls:
- lockfiles;
- checksum/signature verification;
- SBOM;
- dependency audit;
- provenance;
- pinned release process.

### T24 — Donor-code trust transfer

Threat:
Orcel copies code with weaker assumptions or hidden network behavior.

Controls:
- source ledger;
- file-level provenance;
- license gate;
- semantic security review;
- no bulk donor import.

### T25 — Orcel configuration tampering

Controls:
- ACL-protected config;
- policy revision;
- privileged trust changes;
- audit;
- safe defaults;
- signed/reproducible release target.

### T26 — Secret storage misuse

Controls:
- DPAPI/CNG/identity-bound protected storage;
- no plaintext config secrets;
- minimal secret lifetime;
- zeroization where practical.

### T27 — Local same-user compromise

Threat:
Malware already running with the user's full rights attacks Orcel.

Boundary:
Orcel reduces exposure and protects privileged components where possible, but v1 does not claim to defend against a fully compromised Windows administrator or equivalent local attacker.

### T28 — Elevation bypass

Controls:
- no autonomous UAC bypass;
- elevation is a PRIVILEGED capability;
- explicit strong local presence;
- no credential capture.

## 5. Security assumptions

- Windows kernel and user account are not already fully compromised.
- OpenAI account/workspace authentication is managed by the user.
- tunnel-client is obtained from the official source/release path.
- the user intentionally trusts configured workspaces.
- the user can physically interact with the machine for protected approvals.

## 6. Out of scope for initial release

- resistance to malicious kernel drivers;
- resistance to a compromised Windows administrator;
- hardware-backed remote attestation;
- enterprise DLP replacement;
- unattended privilege elevation;
- public multi-tenant Orcel cloud.

## 7. Security release gate

A release cannot be called hardened until:
- all implemented threat controls have tests;
- Windows-native security tests pass;
- dependency/provenance review passes;
- no unresolved critical/high finding exists;
- protected approval invariant is demonstrated;
- secret-leak test suite passes;
- tunnel path is private by default;
- rollback and uninstall are tested.
