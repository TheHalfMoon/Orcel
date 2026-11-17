# SG-000132 slice 1: the Orcel authority service

Status: implemented and tested on branch `authority/sg132-service`; not installed. The founder approved the
build on 2026-11-17 ("Yes, build it"). Installing it is the founder's elevated step in
[SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec: `.specgrain/specs/SG-000132.json` (with its
SG-000135 amendment) and sections 1.2, 4.8, 4.13 to 4.15 of
[UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md).

## What this slice does

Orcel's Full Control authority leaves the user session. Today the full-control store keeps `authority.key`
(a 256-bit HMAC key) in the user's own state root (`crates/orcel-policy/src/full_control_store.rs`), so any
process running as the user, an agent included, can read the key, mint a lease and rewrite the epoch. This
slice adds a Windows service, `OrcelAuthority`, running as the virtual account `NT SERVICE\OrcelAuthority`,
that holds the lease-signing key, the leases, the authority epoch, a monotonic revocation counter, the
enrolled Windows Hello public keys and the Full Control audit chain in `%ProgramData%\Orcel\authority`, a
directory users cannot read. Leases are signed with an asymmetric key (ECDSA P-256), so orceld verifies them
with the published public key without ever holding the private key.

## Files

| Path | Role |
| --- | --- |
| `crates/orcel-authority/src/lease.rs` | Lease shapes (desktop Full User, browser Full Access), scope validation, the narrow default, signing input |
| `crates/orcel-authority/src/core.rs` | The authority state machine: intents, unlock window, confirmation, presence, issuance, verify, authorize, revoke, stop, session end, expiry |
| `crates/orcel-authority/src/audit.rs` | Hash-chained audit with session-asserted claims apart from service-observed facts |
| `crates/orcel-authority/src/protocol.rs` | Pipe wire format (length-prefixed JSON, 64 KiB frames, strict requests) |
| `crates/orcel-authority/src/pipe_sddl.rs` | Pipe security descriptor and the exact client access mask |
| `crates/orcel-authority/src/caller.rs` | Observed caller facts and roles (orceld, interactive, other) |
| `crates/orcel-authority/src/client.rs` | The client: server verification, fail closed, lease verification |
| `crates/orcel-authority/src/win/crypto.rs` | CNG ECDSA P-256 signer and verifier, DPAPI wrapping, RSA PKCS#1 Hello signature check, randomness |
| `crates/orcel-authority/src/win/pipe.rs` | Pipe server instances (first-instance rule) and the verified client open |
| `crates/orcel-authority/src/win/identity.rs` | Caller SID, logon session, TS session, INTERACTIVE, PID and image from the pipe |
| `crates/orcel-authority/src/win/acl.rs` | State directory and parent ACL checks (read only) |
| `crates/orcel-authority/src/win/eventlog.rs` | Event Log source `Orcel` (4100, 4101, 4102, 4103); console mode writes a file |
| `crates/orcel-authority/src/win/confirm.rs` | `WTSSendMessageW` confirmation |
| `crates/orcel-authority/src/win/runtime.rs`, `service.rs` | Shared runtime, SCM entry, session changes |
| `crates/orcel-authority/src/bin/orcel-authority.rs` | `orcel-authority.exe` (service, or `--console` harness) |
| `crates/orceld/src/authority_link.rs` | orceld's link: `ServiceOwnerChannel`, `orceld authority-status`, `orceld authority-verify` |
| `scripts/install-orcel-authority.ps1` | The founder's elevated install and uninstall |

Deviation from the spec's layout: the service binary lives in `crates/orcel-authority` (`[[bin]]`) instead of
`apps/orcel-authority-service`, because `crates/orceld/tests/dependency_direction.rs` refuses path packages
outside `crates/` in the main workspace graph and the spec's app has no code of its own yet. Moving the binary
into an app later changes no protocol.

## Design

### Requests

`Status`, `GrantBegin`, `EnrollBegin`, `IntentStatus`, `PresenceComplete`, `CancelIntent`, `List`, `Verify`,
`Authorize`, `Revoke`, `Stop` (`crates/orcel-authority/src/protocol.rs`). Unknown requests and unknown fields are
refused. The spec's `StandingBegin`, `StandingComplete` and `Heartbeat` are later slices.

### Grant flow (spec 4.13 steps 1 to 6)

1. `GrantBegin` records the session's single pending intent (audit and Event Log 4102), expiring after 5
   minutes. It is refused to orceld (by observed image), to any caller not in an interactive logon of the active
   console session, to any claimed origin other than the owner CLI (MCP, agent, remote, orceld), when no Hello
   key is enrolled, while a lease is active in the session, and while another intent is pending there.
2. Only the first service-observed `WTS_SESSION_UNLOCK` of that session after the intent, with no lease active,
   opens a 120 s window. A routine unlock without an intent opens nothing.
3. The scope defaults to desktop input only, no roots, no shells, 30 minutes; widening is explicit and validated
   (shells with the shell executor, roots with the filesystem executor, absolute drive paths, never the
   authority's own state, never `Admin` or `Remote`).
4. The service renders the confirmation with `WTSSendMessageW` ("Orcel Authority": scope, client, task, expiry,
   requester, and the C-27 disclosures), Yes/No, 60 s, outside the core lock. Only Yes continues.
5. The service derives a 32-byte challenge from the intent digest and a fresh nonce; the user session signs it
   with the enrolled Windows Hello key credential (RSA PKCS#1 v1.5 over SHA-256); the service verifies it. One
   attempt per intent.
6. The lease is signed, stored, audited and its granted scope written to the Event Log as 4101.

Enrollment uses the same intent, unlock, confirmation and signature steps; the signature is a proof of
possession by the key being enrolled. One key per Windows user; replacing it needs an administrator reset.

### Leases, epoch and revocation counter

A lease body (`orcel.authority-lease/1`) binds the scope, the Windows user SID, the logon session, the TS session,
the session-asserted principal and task, the observed requester, the epoch, the revocation counter at issuance,
times, the key id and the grant evidence. The service signs `orcel-authority-lease-signature/1\n ||
canonical_json(body)` with ECDSA P-256 (CNG). `Revoke` adds one to the revocation counter. `Stop`, session lock,
sign-out, disconnect and expiry end the leases concerned and advance both the epoch and the counter (C-28). Both
only grow and persist; a state file missing while audit records exist refuses to start.

### Pipe and anti-squatting

`\\.\pipe\orcel-authority`, created at start with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`:
a pre-existing name makes the service refuse to run (event 4103). SDDL
`O:<svc>G:<svc>D:P(A;;FA;;;<svc>)(A;;0x00120003;;;IU)`: the service SID owns it and has full control;
INTERACTIVE gets exactly `FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE | READ_CONTROL`, never
`FILE_APPEND_DATA` (`FILE_CREATE_PIPE_INSTANCE`) or `GENERIC_WRITE`. Clients open with exactly that mask and,
before sending anything, check `GetNamedPipeServerProcessId` against the service PID from
`QueryServiceStatusEx` and the pipe owner (`GetSecurityInfo`) against the SID of `NT SERVICE\OrcelAuthority`
(`LookupAccountNameW`). Console mode uses `\\.\pipe\orcel-authority-console-<suffix>`, never the service name.

### Caller identity and roles

For every connection the service reads, from the OS, the client's token user SID, logon session, TS session
and INTERACTIVE membership (impersonating the client on the handling thread only; a failed revert aborts the
process), its PID, and its image path (read while impersonating, since the service account cannot open user
processes). Clients therefore connect with `SECURITY_IMPERSONATION`, after verifying the server. Roles: orceld
(the image equals a trusted path from `config.json`), interactive (interactive logon in the active console
session), other. Only orceld may `Authorize`; only interactive callers may record intents and complete
presence; `Stop` works for any caller of the logon session; `Verify`, `List` and `Revoke` act only on leases
bound to the caller's SID and logon session.

### Audit and Event Log

`audit.jsonl` in the state directory: each record has `seq`, `prev_digest`, `asserted_by_session` (what the
caller claimed: capability, operation, principal, task, action digest, scope), `observed` (caller SID, logon
session, TS session, PID, image, role), `detail` (the decision) and its digest. The chain is verified at every
start; a break refuses to start. `Authorize` appends and flushes its record before it answers (write before
dispatch). Anchors (`orcel-anchor/1|authority|audit.jsonl|<seq>|<digest>`, event 4100) every 32 records and on
lease, stop, enrollment, start and shutdown. Events carry the service account SID as their user, which tells
them apart from entries a user process writes under the same source name.

### orceld

`crates/orceld/src/authority_link.rs` adds `ServiceOwnerChannel` (verify a lease through the installed service,
report the service-observed requester) and the `orceld authority-status` and `orceld authority-verify <lease>`
commands. Every failure is `AUTHORITY_UNAVAILABLE`; nothing falls back to the user-readable store.

How OB-08 (`origin/browser/ob08-full-access`) plugs in when it merges: its `OwnerChannel::requester` is
implemented by `ServiceOwnerChannel::requester`; `ManagementEnv::default(true)` (issuance on the interim store)
is replaced by the service's grant flow with the `BrowserFullAccess` scope, which uses OB-08's family
vocabulary; the live browser's pre-dispatch check calls `Verify` (and `Authorize` once the dispatcher lands);
interim-store leases end at migration and are never converted (SG-000135 amendment change 3). No new browser
lease is written to the user-readable store once the link is wired.

Desktop lease migration plan (SG-000095 path, unchanged in this slice): (1) slice 2 adds the user-session CLI
(`orcel authority enroll`, `orcel full-control grant`) on this protocol; (2) WP1-12's
`full_control_dispatch.rs` calls `Authorize` for DesktopInput before every dispatch and `uia.rs`'s
`require_full_user_desktop` switches from `full_control_store::check_current_desktop_input` to it; (3) once a
service-issued desktop lease works end to end on the founder's PC, issuance in
`orcel-lifecycle/src/full_control.rs` is removed, `authority.key` is deleted at first service start, and the
per-user store is retired. Until step 2 lands, the user-readable store remains the desktop path's weakness.

## Real versus deferred

| Item | State in slice 1 |
| --- | --- |
| Service binary, SCM entry, virtual account, automatic start, session-change handling | Real; runs only after the founder's install |
| Protected state directory and its check (owner, protected DACL, allowed SIDs, parent not swappable) | Real; the service refuses to start otherwise |
| Asymmetric lease signatures, public key published read-only, verification without the key | Real |
| Signing key at rest | CNG software key, DPAPI-wrapped under the service account, in the protected directory. TPM (Platform Crypto Provider, non-exportable) deferred |
| Epoch, revocation counter, Stop, session lock/sign-out/disconnect stop, expiry | Real |
| Pipe anti-squatting (first instance, reject remote, exact mask, owner and PID check by clients) | Real |
| Grant intent, service-observed unlock window, narrow default, confirmation, Hello signature check, 4101/4102 | Real in the service; the user-session side (KeyCredential enroll and sign) is slice 2, so no real grant can be made yet |
| Confirmation input protection (WP1-10 proof that injected input cannot answer it) | Deferred; every lease records `confirmation_input_protected: false` |
| Hello key attestation (proving the enrolled key is a Hello key) | Deferred; enrollment trusts the confirmed user (residual below) |
| orceld image signature requirement | Deferred; trusted by exact path only (development builds are unsigned) |
| `Authorize` | Real for lease, epoch, binding, executor, principal, audit first; no Job Object (returns `job_name: null`), no standing approval, no heartbeat |
| Service-owned Job Objects, `fc-worker`, standing approvals, indicator, dispatcher | Later slices (WP1-10, WP1-12, WP1-14) |
| Event Log | Real (registered source, service SID as user); console mode writes `events.jsonl` |

## Guarantees that hold only when installed

The console harness (`orcel-authority --console --state-dir <tmp> --pipe-suffix <s>`) runs the same core and
protocol under the current user. There: the state directory is the user's, so the user can read the key; the pipe
owner is the user, so any process of the user can create pipe instances; no session change is observed, so no
grant window opens and nothing can be issued; events go to a file. Status reports `"mode":"console"` and
`"can_issue":false`. Clients that use `AuthorityClient::installed()` (orceld does) never talk to a console
instance, because they require the service's PID and SID.

## Threat model against same-user agents

An agent with Full Control runs with the user's token in the user's session (C-27). Against it:

- It cannot read or write the authority state (ACL), unwrap the key (DPAPI under the service account), replace the
  service binary (`%ProgramFiles%`), or swap the state directory (owner and parent checks).
- It cannot mint or extend a lease: issuance needs an intent, a service-observed unlock, Yes on a service-rendered
  confirmation and a Hello signature. It cannot answer `Authorize` as the service: clients check PID and owner.
- It cannot squat the pipe while the service runs (no `FILE_CREATE_PIPE_INSTANCE`); if it creates the name
  before the service starts, the service refuses to run (denial of service, never a spoof).
- It can claim anything in a request: `Authorize`'s action is a session-asserted claim, recorded as such with the
  observed caller (C-27 e). It can start the trusted orceld image or inject into it, so the orceld role is defense
  in depth, not a boundary.
- It can record an intent, lock the session and cover or imitate the confirmation (C-27 f); the confirmation
  text tells the user to approve only what they asked for. With enrollment not yet attested, an agent that
  records an enrollment intent for its own software key before the owner enrolls, and gets the owner to approve
  that confirmation, would hold a "presence" key; the confirmation shows the key fingerprint and the requesting
  process. Hello attestation closes this in a later slice.
- It can deny service: hold the 32 connection slots, kill the indicator (later), or stop leases. Stop and expiry
  still end authority through the service's own session-change handling and timers.

## SG-000132 acceptance mapping

| Acceptance | Slice 1 evidence |
| --- | --- |
| A standard-user process cannot read the state directory or use the key | Install creates the protected ACL; the service refuses an unprotected or user-owned directory (`win::acl` tests); key DPAPI-wrapped (`win::crypto` test). Founder check in the runbook |
| Grant, renewal and standing approval fail without a valid Hello signature and while a lease is active | `core_tests` (bad signature, active lease, window closed); standing approvals later |
| Authorize refuses wrong session, expired or revoked lease, epoch drift, wrong client, ...; audit first | `core_tests` (binding, revoke, stop, expiry, principal, executor, Admin) and the audit record check; Job Object and heartbeat parts later |
| Stop by CLI, lock, sign-out, expiry; next call LEASE_INVALID | `core_tests` (stop, session lock, expiry); indicator and the 1 s Job Object kill later |
| J-3 and J-3b | Later (dispatcher) |
| Admin executor refused | `lease` and `core_tests`, console `Authorize` test |
| Pre-created pipe name refuses start; no second instance; clients refuse wrong PID or owner | Console tests (squat, second server, wrong PID, wrong owner, live DACL mask); the no-second-instance guarantee holds only installed |
| Job Object acceptance | Later |
| Grant without intent or outside the window refused; unlock without intent opens nothing; 4101 matches scope; narrow default | `core_tests` |
| Audit records carry asserted_by_session, caller PID and image | `core_tests` and the console audit test |

## Tests

- `cargo test -p orcel-authority`: 24 unit tests (lease shapes, audit chain tamper and removal, framing, SDDL and
  mask, roles, ACL rules, CNG signing and DPAPI persistence, Hello RSA verification, the grant flow and its
  refusals, counters, bindings, browser scope) and 9 console-harness integration tests (status, server
  verification before sending, fail closed when absent, pre-created name, second server, live DACL, issuance
  refusal, Authorize gating, malformed frames and audit chain after shutdown).
- `cargo test -p orceld sg132_`: orceld's link fails closed and its commands parse.

## Next slices

1. User-session CLI: `orcel authority enroll` and `orcel full-control grant` (WinRT `KeyCredentialManager`),
   founder's first real enrollment and grant; verify `WTSSendMessageW` from the virtual account.
2. Job Objects created and owned by the service, `orceld fc-worker`, `Authorize` returning `job_name`.
3. Dispatcher (`full_control_dispatch.rs`), desktop path migration, retirement of `authority.key`.
4. Standing approvals, indicator and heartbeat; OB-08 wiring; TPM key; Hello attestation; WP1-10 input proof.
