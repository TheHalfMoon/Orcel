# Orcel Universal Connectivity Threat Model

Status: IMPLEMENTATION-READY PROPOSAL
Base: `5feff3f15cc7e20464cafffd7b87d713b65a012f`
Date: 2026-10-01
Companion: `docs/canonical/UNIVERSAL_AI_ACCESS_PLAN.md`

> Product identity note: this analysis was authored under the Orcel program
> name. The current product is Orcel. `orceld`, `%LOCALAPPDATA%\Orcel`
> storage paths, and `Orcel`-qualified protected surfaces below denote
> retained compatibility identifiers governed by
> `docs/identity/ORCEL_RENAME.md`.

## 1. Scope

This document extends Orcel's existing local threat model to cover provider-neutral local MCP transports, a public remote MCP edge, OAuth, a shared/self-hosted relay, device identity, pairing, revocation, and multi-provider use.

It does not replace the existing closed threat model for filesystem, process, Git, browser, UIA, screenshot, coordinate input, clipboard, bounded network, approvals, trust, installer, update, or release supply chain.

The universal layer must preserve those controls.

## 2. Security objective

A remote or local AI client may request only individually exposed Orcel tools. Every requested local effect must still be authorized by `orceld`, workspace policy, provider ceiling, and local approval rules.

Compromise or misuse of an AI provider, MCP client, relay, OAuth token, or transport must not by itself create unrestricted OS authority or local approval authority.

## 3. Assets

Protect:

- workspace data;
- local files and Git repositories;
- executable/process authority;
- browser/UIA/screenshot/clipboard data;
- approval and trust state;
- Orcel policy and audit state;
- device private key;
- remote OAuth access/refresh tokens;
- pairing state;
- device/account route mapping;
- request/result confidentiality and integrity in transit;
- tool-surface definition and annotations;
- release artifacts and relay deployments.

## 4. Adversaries

Consider:

- malicious or prompt-injected model output;
- malicious MCP host/client;
- stolen provider session or OAuth token;
- malicious webpage on the local machine;
- other unprivileged local process;
- malicious remote internet client;
- another legitimate Orcel user/tenant;
- compromised shared relay application;
- compromised relay operator account;
- network attacker outside TLS;
- malicious or compromised dependency;
- user error during pairing/profile selection;
- denial-of-service attacker.

The model does not claim to protect against arbitrary code already executing with unrestricted access to the same protected user secrets/memory as Orcel. Strong local presence remains required for the highest-risk trust changes.

## 5. Trust boundaries

- `AI model -> MCP client`: untrusted intent/arguments.
- `MCP client -> local transport`: protocol boundary only.
- `hosted provider -> public relay`: authenticated public transport boundary.
- `OAuth -> relay account/principal`: remote identity boundary.
- `relay account -> paired device route`: tenant/device isolation boundary.
- `relay -> outbound device link`: authenticated transport boundary.
- `local MCP edge -> orceld`: authenticated local IPC boundary.
- `orceld -> provider`: capability token/provider ceiling boundary.
- `orceld -> approval authority`: independent human authority boundary.

## 6. Threat catalogue

### UC-T01 Cross-tenant routing

Threat: a request authenticated for user/device A reaches device B.

Controls:

- opaque tenant-scoped device identifiers;
- route lookup keyed by authenticated principal + selected paired device;
- device channel authenticated to its exact device public key;
- route binding included in relay frames;
- no fallback to another online device;
- two-user/two-device negative tests.

Exit evidence: cross-route requests, including read-only calls, fail before local MCP dispatch, and results never reach the wrong principal.

### UC-T02 Device identity spoofing

Threat: attacker registers or resumes a channel as another device.

Controls:

- local device key pair;
- challenge/response registration;
- private key never sent;
- key rotation/revocation;
- challenge expiry and replay rejection.

### UC-T03 Pairing-code theft/replay

Threat: intercepted or guessed code pairs the wrong remote principal.

Controls:

- high entropy;
- short expiry;
- one-shot consumption;
- attempt/rate limits;
- local display/confirmation;
- explicit target device/account identity during confirmation;
- invalidate on revoke/success/expiry.

### UC-T04 OAuth CSRF

Threat: attacker causes a victim to bind the wrong authorization transaction.

Controls:

- OAuth authorization-code + PKCE;
- state/transaction binding;
- exact redirect allowlist;
- no implicit flow;
- short-lived authorization codes.

### UC-T05 Authorization-server mix-up

Threat: callback/token exchange is accepted from the wrong issuer.

Controls:

- exact issuer identifiers;
- RFC 9207 `iss` validation when advertised;
- exact metadata/resource binding;
- never normalize issuer strings silently.

### UC-T06 Token substitution / wrong audience

Threat: a valid token for another service is accepted by the relay MCP resource.

Controls:

- verify signature, issuer, audience/resource, expiry/not-before, and scopes on every request;
- resource-specific token issuance;
- reject bearer tokens without the required audience.

### UC-T07 Access-token replay

Threat: stolen access token is reused.

Controls:

- short token lifetime;
- TLS;
- scope minimization;
- revocation/session epoch;
- provider client identification where supported;
- token never grants local approval.

### UC-T08 Refresh-token persistence after revoke

Threat: user revokes a connection but refresh token silently restores it.

Controls:

- server-side refresh-token/session family revocation;
- connection/device epoch checked during refresh and request validation;
- revoke tests on active and expired access-token paths.

### UC-T09 Forged provider identity

Threat: arbitrary client claims to be ChatGPT, Claude, or Mistral.

Controls:

- provider identity is never inferred from user-agent strings;
- OAuth client identity is validated from the configured OAuth path;
- OpenAI mTLS may be validated as defense in depth when supported;
- provider label is not local authority.

### UC-T10 MCP session fixation/collision

Threat: one client guesses/reuses another MCP session ID.

Controls:

- cryptographically random session IDs when the negotiated MCP era requires sessions;
- session scoped to authenticated principal + device + connection;
- invalid/missing session IDs fail closed only when the negotiated protocol requires a session; stateless requests follow the SDK/spec;
- bounded session lifetime;
- modern stateless protocol handled according to the SDK/spec rather than emulating legacy session state.

### UC-T11 Relay-frame replay

Threat: relay/device message is resent to repeat an operation.

Controls:

- connection-scoped sequence/replay nonce;
- expiry;
- correlation binding;
- duplicate rejection;
- existing Orcel approval one-shot/digest controls remain independent defense in depth.

### UC-T12 Relay-frame reordering

Threat: messages arrive in an order that changes meaning or session state.

Controls:

- defined ordering semantics;
- sequence checks for ordered frame classes;
- independent correlation IDs for concurrency;
- impossible order fails with typed transport error.

### UC-T13 Route substitution after reconnect

Threat: reconnect resumes on a different user/device route.

Controls:

- reconnect binds to the same authenticated device key and route epoch;
- route epoch changes on revoke/re-pair;
- no route migration without explicit new pairing.

### UC-T14 Offline queued mutation

Threat: write/execute request is delivered minutes later when the user no longer expects it.

Controls:

- no durable offline queue for mutating calls;
- no durable offline queue for read calls;
- short transport reconnect grace only;
- original Orcel request/approval expiry remains effective;
- queued items expire before dispatch;
- device offline returns `DEVICE_OFFLINE` rather than silently persisting work.

### UC-T15 Approval drift across reconnect

Threat: transport reconnect makes an old approval valid for a changed request/session.

Controls:

- existing nonce/expiry/digest/workspace/policy binding;
- reconnect does not rewrite request IDs or approval digests;
- stale/expired approvals fail closed.

### UC-T16 Workspace/policy drift across reconnect

Threat: request authorized under an earlier revision executes after policy change.

Controls:

- `orceld` re-evaluates current revision;
- approval digest includes workspace/policy revision;
- relay does not cache local allow decisions.

### UC-T17 Tool-catalog drift

Threat: remote edge exposes a tool/shape not present in the reviewed local catalog.

Controls:

- single tool registry source;
- profile manifests generated/tested from that registry;
- schema + annotation snapshots in CI;
- no relay-defined arbitrary tool forwarding.

### UC-T18 Generic executor smuggling

Threat: safe-looking public tool contains a command/method field that creates hidden arbitrary authority.

Controls:

- no `run_anything`, generic operation dispatcher, arbitrary URL proxy, schema-fetch/execute pattern, or hidden subcommands;
- each effect is a separately reviewed tool;
- strict schemas with `additionalProperties` rejection where supported.

### UC-T19 Local DNS rebinding

Threat: malicious webpage reaches the loopback MCP server through a rebound hostname.

Controls:

- loopback-only bind;
- Host allowlist;
- Origin validation;
- no wildcard CORS;
- protected local auth token;
- tests with forged Host/Origin.

### UC-T20 Malicious local process uses loopback transport

Threat: another same-user process calls the MCP server.

Controls:

- protected local access secret stored with user ACL;
- short/rotatable listener credential;
- local process is still subject to `orceld` workspace/approval policy;
- documentation does not claim loopback auth protects against arbitrary same-user compromise.

### UC-T21 Relay plaintext/log leakage

Threat: file contents, screenshots, clipboard data, process output, or secrets are persisted in relay logs/metrics.

Controls:

- payload logging prohibited;
- structured logs use route/result classes only;
- secret scanner and log tests;
- request/result bodies held only transiently;
- support bundles exclude payloads;
- privacy policy states transient processing honestly.

### UC-T22 Wrong-principal result delivery

Threat: result from device A is delivered to another authenticated client.

Controls:

- result correlation binds tenant + device + connection + request;
- response path never uses request ID alone globally;
- two-tenant concurrency tests.

### UC-T23 Prompt-injection-driven exfiltration

Threat: malicious local content instructs model to send unrelated local data outward.

Controls:

- tool scope remains workspace/capability bound;
- outbound/public-network operations separately classified and approved;
- upload/network tools never accept generic local paths unless a specific authorized grain permits it;
- provider annotations mark open-world/write behavior accurately;
- local approvals show consequence/target, not model rationale alone.

### UC-T24 Relay as generic pivot proxy

Threat: relay/device channel is abused to reach arbitrary LAN/internet endpoints.

Controls:

- relay protocol carries MCP frames only;
- local edge exposes named tools only;
- no CONNECT/SOCKS/raw TCP/general HTTP forwarding;
- existing destination-scoped network provider remains separately gated.

### UC-T25 Protected Orcel surface targeted through new desktop exposure

Threat: newly exposed UIA/screenshot/coordinate tools approve their own operations or manipulate Orcel security UI.

Controls:

- preserve existing protected-process/window rules;
- approval pending suspends input lease;
- no tool to approve/trust/revoke through UI automation;
- cross-provider tests prove identical denial.

### UC-T26 Executable-registry widening remotely

Threat: remote model adds PowerShell/cmd/arbitrary executable then invokes it.

Controls:

- registry changes local human-only PRIVILEGED operation;
- STRONG presence;
- no MCP registry-mutation tool;
- registry entries versioned and included in policy revision;
- test remote attempts cannot create entries.

### UC-T27 Provider scope confusion

Threat: read-only provider connection invokes write/execute tools.

Controls:

- per-tool required scopes;
- remote token scope checked before relay dispatch;
- local policy remains second boundary;
- scope downgrade/upgrade requires OAuth reauthorization.

### UC-T28 Provider credential cross-use

Threat: Claude connection credentials are accepted as OpenAI/Orcel connection or vice versa.

Controls:

- issuer/client/resource checks;
- provider connection records separate;
- provider labels cannot override authenticated issuer/client identity.

### UC-T29 Cancellation ambiguity

Threat: remote host cancels and Orcel reports local process terminated when it is not verified.

Controls:

- propagate cancellation when supported;
- retain existing `PROCESS_TERMINATION_UNVERIFIED` distinction;
- transport close does not fabricate process state.

### UC-T30 Free-tier exhaustion / DoS

Threat: attacker consumes community relay quota and blocks legitimate users.

Controls:

- per-principal/device/IP rate limits as appropriate;
- bounded connection and message limits;
- WebSocket hibernation/reference-host efficiency;
- no paid overflow;
- clear `REMOTE_RATE_LIMITED`/unavailable behavior;
- self-host/local modes remain usable.

### UC-T30b Compromised-relay device flooding

Threat: a compromised relay or hijacked device-channel session floods a paired device with requests and approval prompts, causing denial of service or approval fatigue.

Controls:

- per-device request, concurrency, and approval-prompt rate limits at the local edge;
- backpressure from the local edge to the device channel;
- fail closed on overload with typed `REMOTE_RATE_LIMITED` or `REMOTE_SESSION_INACTIVE` rather than queuing unbounded work;
- no durable queue for reads or writes after overload, lease expiry, or revocation;
- qualification includes flooding from a compromised relay and approval-rate behavior.

### UC-T31 Pairing enumeration/privacy leak

Threat: attacker learns whether a device/account exists from pairing responses.

Controls:

- uniform failure shapes/timing where practical;
- no user/email/device display data in unauthenticated errors;
- opaque identifiers.

### UC-T32 Device private-key extraction through tools

Threat: model reads protected key through filesystem/process surfaces.

Controls:

- Orcel protected state remains outside admitted workspaces;
- child processes remain isolated from Orcel secrets;
- secret paths excluded by policy;
- no tool returns raw device key.

### UC-T33 Stale public metadata

Threat: directory/provider scans use old tool schemas while production behavior widens.

Controls:

- public metadata is versioned;
- continuous schema diff checks;
- no behavior widening without reviewed grain;
- provider rescans/submission updates when required.

### UC-T34 Dependency/supply-chain compromise

Threat: new OAuth/relay/MCP packages introduce code execution or credential theft.

Controls:

- pinned dependencies/lockfiles;
- cargo/npm audit;
- license review;
- SBOM/provenance;
- minimal dependency selection;
- exact-head independent code review (from 2026-11-23; before that, TypeSafe Jev), Alibaba Open Code Review, and manual review.

### UC-T35 Relay operator impersonation

Threat: operator manually routes a request to a victim device.

Controls:

- authenticated account/device route state;
- a device-verifiable authorization envelope binds the authenticated principal, connection, selected device, and request digest before local dispatch;
- local dispatch rejects a remapped principal-to-device route even when the relay/device channel itself is authenticated;
- local policy/approval still required;
- active local remote-session lease still required for every remote dispatch, including reads;
- sensitive effects show local target/consequence;
- self-hosted mode for users who do not trust shared relay;
- no claim that shared relay is end-to-end encrypted from provider to device.

### UC-T36 Tool result amplification

Threat: tiny request produces huge output that causes cost, memory pressure, or accidental disclosure.

Controls:

- per-tool output ceilings inherited from providers;
- relay hard result ceiling;
- truncation explicitly reported;
- no silent fallback to unbounded streaming.

## 7. Provider-specific constraints

### OpenAI public plugin

- public production HTTPS Streamable HTTP endpoint;
- OAuth 2.1 for private/write user-specific access;
- accurate required tool annotations;
- no generic executor/discovery escape hatch;
- directory review and publisher/domain requirements;
- OpenAI client mTLS may be verified as defense in depth where available.

### Claude remote connector

- public internet reachability for remote connector mode;
- local Desktop Extension is a separate local path;
- one remote backend must not assume requests originate locally merely because the user is on Claude Desktop.

### Mistral Vibe Work

- HTTPS remote MCP endpoint;
- static tool behavior compatible with current custom-connector limits;
- do not rely on MCP resources/dynamic tool discovery for core operation.

### Mistral Vibe Code / local clients

- stdio and Streamable HTTP are supported targets;
- OAuth-dependent local paths must not be required where a client lacks OAuth support.

## 8. Required qualification before P15 exit

- two-principal/two-device routing isolation, including read-only cross-route attempts and wrong-principal result delivery;
- provider/client identity tests;
- PKCE/state/issuer/audience/scope OAuth tests;
- access/refresh revoke tests, including principal-wide and all-route revocation;
- pairing brute-force/replay/expiry tests;
- device challenge/replay/rotation tests;
- duplicate/reordered/expired relay frame tests;
- reconnect/stale route tests;
- offline mutation non-queueing test;
- offline read non-queueing test after lease expiry, revoke, lock/logoff invalidation, and profile/policy change;
- compromised-relay device flooding and approval-rate/backpressure test;
- device-verifiable authorization envelope test for principal/connection/device/request-digest binding;
- cancellation ambiguity test;
- loopback Host/Origin/DNS-rebinding tests;
- payload/log redaction tests;
- quota/rate/backpressure tests;
- public/local tool-schema equivalence tests;
- protected Orcel surface regressions;
- executable-registry remote-widening denial;
- all pre-existing local security regression suites unchanged unless an explicit successor grain lawfully changes a boundary.

## 9. Residual risks to state publicly

Even after qualification:

- a shared relay processes remote MCP plaintext transiently after TLS termination;
- compromise of the user's already-unrestricted same-user environment can undermine local secret boundaries outside Orcel's model;
- provider behavior, account policy, directory availability, and review decisions are external;
- public relay availability can be limited by free-tier quotas;
- prompt injection cannot be solved only by transport/authentication and remains constrained by least privilege, local approval, and output/egress controls.

These risks must not be hidden by marketing language.
