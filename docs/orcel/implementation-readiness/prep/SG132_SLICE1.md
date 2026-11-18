# SG-000132 slice 1: the Orcel authority service

Status: implemented and tested on branch `authority/sg132-service`; not installed. The founder approved the
build on 2026-11-17 ("Yes, build it"). Installing it is the founder's elevated step in
[SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec: `.specgrain/specs/SG-000132.json` (with its
SG-000135 amendment) and sections 1.2, 4.8, 4.13 to 4.15 of
[UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md). Revision 2 of this slice answers the independent
review of `ecb66ab3` (findings 1 to 9), revision 3 the re-review of `2d774e45`; both are listed at the end.

Slice 2 (attested enrollment, the grant CLIs, OB-08 on the service, the desktop migration step) is
[SG132_SLICE2.md](SG132_SLICE2.md).

**No grant completes in slice 1.** Windows Hello enrollment is refused (`enrollment_unavailable`) until slice 2
brings attested keys and an elevated enrollment caller; without an enrolled key `GrantBegin` is refused. The
grant flow below is implemented and tested with an enrolled key seeded by the tests only.

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
| `crates/orcel-authority/src/lease.rs` | Lease shapes (desktop Full User, browser Full Access), scope validation, display-text rule, narrow default, signing input |
| `crates/orcel-authority/src/core.rs` | State machine: intents (process-bound, one-time code), unlock window, confirmation text, text-bound challenge, issuance, verify, authorize, revoke, stop, session end, expiry, signed events |
| `crates/orcel-authority/src/audit.rs` | Hash-chained audit with session-asserted claims apart from service-observed facts |
| `crates/orcel-authority/src/protocol.rs` | Pipe wire format (length-prefixed JSON, 64 KiB frames, strict requests) |
| `crates/orcel-authority/src/pipe_sddl.rs` | Pipe security descriptor and the exact client access mask |
| `crates/orcel-authority/src/caller.rs` | Observed caller facts and roles (orceld, interactive, other) |
| `crates/orcel-authority/src/client.rs` | The client: server verification, fail closed, lease verification |
| `crates/orcel-authority/src/win/crypto.rs` | CNG ECDSA P-256 signer and verifier, DPAPI wrapping, RSA PKCS#1 Hello signature check, randomness |
| `crates/orcel-authority/src/win/pipe.rs` | Pipe server instances (first-instance rule) and the verified client open |
| `crates/orcel-authority/src/win/identity.rs` | Caller SID, logon session, TS session, INTERACTIVE, PID and image from the pipe |
| `crates/orcel-authority/src/win/acl.rs` | State directory, parent and trusted-image path ACL checks (read only; unknown ACE types are unsafe) |
| `crates/orcel-authority/src/win/eventlog.rs` | Event Log source `Orcel` (4100 to 4103); console mode writes a file |
| `crates/orcel-authority/src/win/confirm.rs` | `WTSSendMessageW` confirmation |
| `crates/orcel-authority/src/win/runtime.rs`, `service.rs` | Shared runtime, SCM entry, start checks, session changes |
| `crates/orcel-authority/src/bin/orcel-authority.rs` | `orcel-authority.exe` (service, `install` / `uninstall`, or `--console` harness) |
| `crates/orceld/src/authority_link.rs` | orceld's link: `ServiceOwnerChannel`, `orceld authority-status`, `orceld authority-verify` |
| `crates/orcel-authority/src/win/install.rs`, `install_os.rs` | The founder's elevated install and uninstall, native (no PowerShell or .NET): run from the admin-only staging folder, which it verifies up to the volume root; known folders, never environment variables; System32-only DLL search; binaries hashed and copied through held handles; rollback on failure |
| `.github/workflows/ci.yml` job `authority-artifact` | Builds the three binaries for the exact commit, attests the build provenance of every file, checks it with `gh attestation verify` and uploads them with `SHA256SUMS.txt` as a workflow artifact (no release) |
| `.github/workflows/ci.yml` job `authority-install-e2e`, `scripts/authority-install-e2e.ps1` | Runs the runbook's Stage, Install and Uninstall command lines on a disposable runner in a hostile environment and checks staging ACLs, refusals, rollback, install, fail-closed grant and reset, recovery and uninstall (JSON report) |

Deviation from the spec's layout: the service binary lives in `crates/orcel-authority` (`[[bin]]`) instead of
`apps/orcel-authority-service`, because `crates/orceld/tests/dependency_direction.rs` refuses path packages
outside `crates/` in the main workspace graph. Moving the binary into an app later changes no protocol.

## Design

### Requests

`Status`, `GrantBegin`, `EnrollBegin` (always refused in slice 1), `IntentStatus`, `PresenceComplete`,
`CancelIntent`, `List`, `Verify`, `Authorize`, `Revoke`, `Stop`. Unknown requests and fields are refused. The
spec's `StandingBegin`, `StandingComplete` and `Heartbeat` are later slices.

### Grant flow (spec 4.13 steps 1 to 6)

1. `GrantBegin` records the session's single pending intent (audit and Event Log 4102), expiring after 5
   minutes, bound to the requesting process (observed PID, creation time and image; an unreadable image or
   creation time is refused, and a reused PID is another caller) and returns a one-time code
   (`XXXX-XXXX`) to that process only. `IntentStatus`, `CancelIntent` and `PresenceComplete` are answered only
   for that same process, user and logon session; a second intent in the session is refused while one is
   pending, so another process cannot take over or replace the slot. Refused: orceld (observed image), callers
   not in an interactive logon of the active console session, a claimed origin other than the owner CLI, no
   enrolled key, a lease active in the session.
2. Only the first service-observed `WTS_SESSION_UNLOCK` of that session after the intent, with no lease active,
   opens a 120 s window. A routine unlock without an intent opens nothing.
3. The scope defaults to desktop input only, no roots, no shells, 30 minutes; widening is explicit and validated.
4. The service renders the confirmation with `WTSSendMessageW` ("Orcel Authority": the one-time code, scope,
   client, task, expiry, requesting process, and the C-27 disclosures), Yes/No, 60 s, outside the core lock.
   The text tells the user to choose No unless the code and process match what their orcel command printed.
5. On Yes the service derives the 32-byte challenge as `SHA-256(domain || intent digest || SHA-256(exact
   confirmation text) || nonce)`. The requesting process returns the one-time code and the Windows Hello
   signature over the challenge; the service checks both (one attempt per intent). Hello presence is not
   consent: consent is the Yes on the service-rendered text, and the challenge binds the signature to that
   text's digest. `IntentStatus` returns the text and its digest so the CLI can show what is being signed.
6. The lease is signed, stored, audited and its granted scope written as event 4101. Its grant evidence
   records the intent digest, `confirmation_text_digest`, `confirmation_input_protected: false` and the
   presence key digest.

### Confirmation text

Every caller-supplied field the box shows is printable ASCII (U+0020 to U+007E) with no leading, trailing or
repeated spaces: principal and task at most 64 characters, roots at most 128, at most 8 roots and 16 origins
(OB-08 allows 64 origins; the service lowers it so the scope fits the box), and the whole scope description at
most 1,200 characters. Line and paragraph separators (U+2028, U+2029), bidi controls (U+202E), zero-width
characters and every other format character are refused. The observed image path is cleaned (non-ASCII
becomes `?`) and cut to its last 160 characters.

### The one-time code

The code links the confirmation box to the command the user ran; it is not a secret. A same-user process can
read the console or the screen (UI Automation) and can take the single pending-intent slot first. The user must
refuse any box whose code they did not just start in their own terminal; Windows Hello (slice 2) is the gate.

### Origin claims

`ClaimedOrigin` (owner CLI, MCP, agent, remote, orceld) is an unverified claim any process can set. The service
refuses every value but the owner CLI, which only stops honest callers. The weight is carried by observed facts
(orceld image, interactive console logon), the one-time code only the requesting process receives and the box
shows, the process binding of the intent, the service-rendered confirmation and Windows Hello.

### Enrollment (refused in slice 1; slice 2 design)

`EnrollBegin` answers `Unsupported` with the reason `enrollment_unavailable` for every caller. Slice 2 enables it
only with all of: (a) an elevated enrollment caller: the service requires the caller's token to be elevated
(full administrator token, so enrollment passes a UAC prompt on the secure desktop), observed from the token, not
claimed; (b) the key's fingerprint shown in that UAC-gated tool and again in the service-rendered box, which must
match; (c) an attested `KeyCredentialManager` key: the CLI sends `KeyCredential.GetAttestationAsync()`'s
attestation and certificate chain, and the service verifies the chain to a TPM manufacturer root and that the
attested key is the enrolled public key, refusing unattested keys. Replacing an enrolled key needs the same
steps plus an administrator reset of the old one.

### Leases, epoch and revocation counter

A lease body (`orcel.authority-lease/1`) binds the scope, the Windows user SID, the logon session, the TS session,
the session-asserted principal and task, the observed requester, the epoch, the revocation counter at issuance,
times, the key id and the grant evidence. The service signs `orcel-authority-lease-signature/1\n ||
canonical_json(body)` with ECDSA P-256 (CNG). `Revoke` adds one to the revocation counter. `Stop`, session lock,
sign-out, disconnect and expiry end the leases concerned and advance both the epoch and the counter (C-28). Both
only grow and persist. The service refuses to start when the state file is missing while audit records exist,
and when `lease-signing.key` is missing while audit records exist (it never silently replaces the key).

### Pipe and anti-squatting

`\\.\pipe\orcel-authority`, created at start with `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`:
a pre-existing name makes the service refuse to run (event 4103). SDDL
`O:<svc>G:<svc>D:P(A;;FA;;;<svc>)(A;;0x00120083;;;IU)`: INTERACTIVE gets exactly
`FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL` (`CreateFileW` adds `FILE_READ_ATTRIBUTES` to every open, so without it every non-owner client is refused; found by the CI install E2E), never `FILE_APPEND_DATA`
(`FILE_CREATE_PIPE_INSTANCE`) or `GENERIC_WRITE`. Clients open with exactly that mask and, before sending
anything, check `GetNamedPipeServerProcessId` against the service PID from `QueryServiceStatusEx` and the pipe
owner against the SID of `NT SERVICE\OrcelAuthority`. Console mode uses `\\.\pipe\orcel-authority-console-<s>`.

### Caller identity, roles and the trusted orceld

For every connection, after its first frame, the service reads from the OS the client's token user SID, logon
session, TS session and INTERACTIVE membership (impersonating on the handling thread only; a failed revert aborts
the process), its PID and its image path (read while impersonating). Roles: orceld (the image equals a trusted
path from `config.json`), interactive, other. The installer trusts only `%ProgramFiles%\Orcel\orceld.exe`, copied
from the hash-pinned artifact. At start the service refuses any trusted path outside `%ProgramFiles%\Orcel\`, and
reads the owner and effective DACL of the file and every directory above it: the file must be owned by SYSTEM,
Administrators, TrustedInstaller or the service and writable or replaceable by no one else; no directory on the
path may be owned by anyone else or grant anyone else delete-child, delete, permission or ownership rights.
No element of the path may be a reparse point (junction, symbolic link, mount point). The service applies the
same rules to its own `orcel-authority.exe`, and the state directory and its parent may not be reparse points.

### ACL checks

The state directory must be owned by SYSTEM, Administrators or the service, have a protected DACL, and grant
access only to those three (inherit-only ACEs included); its parent must be owned by SYSTEM or Administrators
and let nobody else add, delete or rename entries. Any ACE type other than plain allow and deny (object, callback
and conditional ACEs) makes a check fail as unsafe. The installer creates each directory with its owner and
protected DACL in one call and reads them back.

### Audit and Event Log

`audit.jsonl`: each record has `seq`, `prev_digest`, `asserted_by_session` (what the caller claimed),
`observed` (caller SID, logon session, TS session, PID, image, role), `detail` and its digest; verified at every
start; a break refuses to start. `Authorize` appends and flushes before it answers. Anchors (event 4100) every 32
records and on lease, stop, start and shutdown. A dedicated Event Log channel with restricted write needs an
instrumentation manifest installed with `wevtutil`, which slice 1 does not add; instead every event the service
writes ends with `|sig=<hex>`, the lease key's ECDSA signature over `orcel-authority-event-signature/1\n || text`,
and carries the service account SID as its user. The signed part is
`orcel-event/1|id=<event id>|audit_seq=<last audit record>|<text>`, so the event id and the chain position are
signed with the text. An entry another process writes under the `Orcel` source does not verify against the
published public key. The start-refusal event 4103 is written before the key is loaded
and is unsigned.

### orceld

`crates/orceld/src/authority_link.rs` adds `ServiceOwnerChannel` (verify a lease through the installed service,
report the service-observed requester) and the `orceld authority-status` and `orceld authority-verify <lease>`
commands. Every failure is `AUTHORITY_UNAVAILABLE`; nothing falls back to the user-readable store. OB-08's
`OwnerChannel::requester` is implemented by `ServiceOwnerChannel::requester` when it merges; its interim-store
issuance is replaced by the service's grant flow; interim-store leases end at migration and are never converted.

Desktop lease migration plan (SG-000095 path, unchanged in this slice): (1) slice 2 adds enrollment and the
user-session grant CLI; (2) WP1-12's `full_control_dispatch.rs` calls `Authorize` before every DesktopInput
dispatch and `uia.rs` switches from `full_control_store::check_current_desktop_input` to it; (3) once a
service-issued desktop lease works end to end, issuance in `orcel-lifecycle/src/full_control.rs` is removed and
the per-user `authority.key` store is retired. Until step 2 the user-readable store remains the desktop path's
weakness.

## Real versus deferred

| Item | State in slice 1 |
| --- | --- |
| Service, SCM entry, virtual account, automatic start, session changes | Real; runs only after the founder's install |
| Hash-pinned install (CI artifact with SHA-256, verified before and after copy), script self-hash | Real |
| Protected state directory, parent, trusted-image path checks | Real; the service refuses to start otherwise |
| Asymmetric lease signatures, published public key | Real |
| Signing key at rest | CNG software key, DPAPI-wrapped under the service account; TPM deferred |
| Epoch, revocation counter, Stop, session lock/sign-out/disconnect stop, expiry | Real |
| Pipe anti-squatting and client server verification | Real |
| Intent, unlock window, narrow default, one-time code, process-bound intent, ASCII-only box, text-bound challenge, 4101/4102 | Real in the service; no grant completes because enrollment is refused |
| Enrollment (elevated caller, attested key, fingerprint check) | Deferred to slice 2; refused with `enrollment_unavailable` |
| Confirmation input protection (WP1-10) | Deferred; every lease records `confirmation_input_protected: false` |
| orceld image signature requirement | Deferred; trusted by exact protected path |
| `Authorize` | Real for lease, epoch, binding, executor, principal, audit first; no Job Object, standing approval or heartbeat |
| Dedicated Event Log channel | Deferred; events are signed by the lease key instead |

## Guarantees that hold only when installed

The console harness runs the same core and protocol under the current user: the state is the user's, the pipe
owner is the user (any process of the user may create instances), no session change is observed (no grant
window), events go to a file, and the trusted-image path check is skipped (tests trust their own executable).
Status reports `"mode":"console"` and `"can_issue":false`. orceld's `AuthorityClient::installed()` never talks to
a console instance.

## Threat model against same-user agents

An agent with Full Control runs with the user's token (C-27). It cannot read or write the authority state,
unwrap the key, replace the service binary or the trusted orceld (both in `%ProgramFiles%`, checked at start),
swap the state directory, mint or extend a lease, enroll a key (refused), or answer as the service. It can claim
anything in a request (recorded as a claim), start the trusted orceld image or inject into it (the orceld role is
defense in depth), record its own intent, lock the session and imitate the confirmation (C-27 f: the box shows a
code the user's own command printed and the requesting process), and deny service (32 connection slots). If the
user runs elevated, an agent can do anything, the service included; the runbook asks for a standard account or
UAC "Always notify".

## SG-000132 acceptance mapping

| Acceptance | Slice 1 evidence |
| --- | --- |
| A standard-user process cannot read the state directory or use the key | Installer creates the protected ACL; service refuses an unprotected, user-owned or swappable directory (`win::acl` tests); key DPAPI-wrapped (`win::crypto`); founder check in the runbook |
| Grant, renewal and standing approval fail without a valid Hello signature and while a lease is active | `core_tests` (bad signature, wrong code, active lease, window closed); enrollment refused; standing approvals later |
| Authorize refuses wrong session, expired or revoked lease, epoch drift, wrong client; audit first | `core_tests`; Job Object and heartbeat parts later |
| Stop by CLI, lock, sign-out, expiry; next call LEASE_INVALID | `core_tests`; indicator and Job Object kill later |
| J-3 and J-3b | Later |
| Admin executor refused | `lease`, `core_tests`, console `Authorize` test |
| Pre-created pipe refuses start; no second instance; clients refuse wrong PID or owner | Console tests; no-second-instance holds only installed |
| Job Object acceptance | Later |
| Grant without intent or outside the window refused; unlock without intent opens nothing; 4101 matches scope; narrow default | `core_tests` |
| Audit records carry asserted_by_session, caller PID and image | `core_tests` and the console audit test |

## Tests

- `cargo test -p orcel-authority`: 34 unit tests (lease shapes, audit tamper and removal, framing, SDDL, roles,
  ACL rules including owner, parent, trusted-image chain and a live System32 versus temp-file check, CNG signing
  and DPAPI, Hello RSA verification, enrollment refusal, the grant flow with code, process binding and text-bound
  challenge, wrong code and signature, ASCII-only fields with U+2028, U+2029, U+202E, U+200B, U+FEFF and padding,
  window and timeouts, counters, missing key with history, signed events, bindings, browser scope, trusted image
  prefix, process creation-time binding, junctions on a path, signed event id), 9 console-harness integration
  tests, and 5 install-script tests (hash-pinned install order, protected creation, uninstall wait and profile
  removal, parse and an unelevated `-WhatIf` preview with a good and a wrong hash under PowerShell 5.1 and 7).
- `cargo test -p orceld sg132_`: orceld's link fails closed and its commands parse.

## Review findings of `ecb66ab3` and their answers

1. Install supply chain: hash-pinned artifact only, CI `authority-artifact` job, script self-hash, runbook.
2. Enrollment: refused (`enrollment_unavailable`); slice 2 design above; no grant completes in slice 1.
3. Origin claims: documented as unverified; one-time code in the box and required at completion; process-bound,
   single intent slot.
4. Confirmation text: printable ASCII only, lower caps, tests with separators, bidi, zero-width and padding.
5. Trusted orceld: installed to `%ProgramFiles%\Orcel`, hash-verified, only path trusted, path ACLs checked at start.
6. `confirmation_input_protected: false` kept; challenge bound to the exact text digest; presence is not consent.
7. Event Log: events signed by the lease key; dedicated channel deferred.
8. `%ProgramData%\Orcel` and the authority directories created with their security in one call, then verified.
9. Missing key with audit history refuses start; unknown ACE types unsafe; uninstall waits for stop and removes
   the virtual account profile; recovery note in the runbook; daily-work note in the runbook.

## Re-review findings of `2d774e45` and their answers

1. CI trust: `authority-artifact` runs only for a push or manual dispatch on `main` of TheHalfMoon/Orcel (never
   for pull requests) and prints the SHA-256 values in its log; the runbook takes them from the log on
   github.com, with an admin-only clone as the alternative.
2. `FileSystemAclExtensions.Create(DirectoryInfo, DirectorySecurity)` fixed; the script tests parse it and run
   the unelevated `-WhatIf` preview under both Windows PowerShell 5.1 and PowerShell 7 (which found and fixed
   `Get-FileHash` hashing nothing under `-WhatIf` in 5.1: hashing now uses .NET directly).
3. Intents bind the requester's creation time; an empty image or unknown creation time is refused.
4. The install checks a pre-existing `%ProgramFiles%\Orcel` and `Authority` folder; the service checks its own
   binary's path.
5. Reparse points on any checked path element are refused.
6. Events sign their id and the audit sequence number.
7. The runbook explains that the one-time code is a link, not a secret.

## Next slices

1. Enrollment as designed above and the user-session grant CLI; founder's first real grant; verify
   `WTSSendMessageW` from the virtual account.
2. Service-owned Job Objects, `orceld fc-worker`, `Authorize` returning `job_name`.
3. Dispatcher, desktop path migration, retirement of `authority.key`.
4. Standing approvals, indicator and heartbeat; OB-08 wiring; TPM key; WP1-10 input proof; Event Log channel.
