# SG-000132 slice 2: attested enrollment, the grant CLIs, OB-08 on the service

Status: implemented and tested on branch `authority/sg132-slice2`; not installed, not reviewed. The founder
approved building and testing the service on this PC on 2026-11-17. Nothing in this slice was installed, no
UAC or Windows Hello prompt was triggered, and no system, registry or ACL setting changed. Slice 1 is
[SG132_SLICE1.md](SG132_SLICE1.md); installing is [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Specs:
`.specgrain/specs/SG-000132.json` and `.specgrain/specs/SG-000135.json` (OB-08).

**What slice 2 makes possible:** a real, owner-only grant. After the founder installs the service, enrolls a
TPM-attested Windows Hello key from an elevated terminal and runs a grant, the service issues a signed desktop
or browser lease, and orceld uses it only after checking its signature with the service's public key and
asking the service's `Authorize` for each action.

**Branch shape.** OB-08 (`origin/browser/ob08-full-access`, head `0da91505`) is built on OB-03 (PR #806, not
yet on main). This branch merges OB-03's branch head, cherry-picks OB-08's two commits, then reworks OB-08 so
leases come from the service only. A PR from this branch carries OB-03's diff until #806 merges.

## 1. Attested enrollment (`orcel authority enroll`)

Flow (all refusals fail closed and are audited):

1. The founder starts `%ProgramFiles%\Orcel\orcel.exe authority enroll --pause` elevated and directly
   (`Start-Process -Verb RunAs`; the UAC prompt on the secure desktop is the human gate, and UAC must be
   "Always notify"). The CLI refuses to start unelevated, refuses when the service reports that it
   cannot verify attestations, and refuses when a key is already enrolled (unless `--replace`), so it never
   overwrites the Hello container's key by accident.
2. The CLI creates the key with `KeyCredentialManager.RequestCreateAsync("Orcel Authority")` (Hello prompt;
   the private key stays in the user's Hello container, non-exportable), reads its public key as
   SubjectPublicKeyInfo DER and calls `KeyCredential.GetAttestationAsync()`. If Windows cannot attest the key
   (`NotSupported`, `TemporaryFailure`, any error), enrollment stops there.
3. `EnrollBegin { public key, attestation, certificate chain, replace }` reaches the service. The service checks,
   from the caller's token and never from a claim: interactive role in the active console session, owner-CLI
   origin, the **trusted owner CLI image**, UAC "Always notify" on the secure desktop, **elevated token** (`TokenElevation` and integrity at least High), a readable requesting image and
   creation time. Console mode never enrolls.
4. The service verifies the attestation (section 2). Then it records an enrollment intent bound to the
   requesting process and renders its own confirmation box ("Orcel Authority", `WTSSendMessageW`) with the
   one-time code and the key fingerprint (SHA-256 of the SPKI in 16 groups of four hex digits). The CLI prints
   the same code and fingerprint; it also checks the fingerprint the service returned against the key it holds.
5. On Yes, the service issues a 32-byte challenge,
   `SHA-256("orcel-authority-enrollment-challenge/1\n" || key digest | intent digest | text digest | nonce)`.
   The NEW key signs it: possession of the key (whether a gesture was needed is not provable, section 2).
6. Only then is the key enrolled (state, audit `enrollment`, Event Log **4104** with the fingerprint).

Re-enrollment: `orcel authority enroll --replace` (elevated, same checks, the box says it REPLACES the old
fingerprint). Reset: `orcel authority reset` (elevated, `ResetEnrollment`, a service-rendered box; on Yes the
key is removed). Both end every lease of that user and advance the epoch.

Known limit: an elevated token of a *different* account (a standard user with over-the-shoulder elevation)
enrolls a key for that admin account, not the standard user; grants by the standard user then find no key
and are refused. Slice 2 supports an administrator account with UAC set to "Always notify" (the runbook's
advice); standard-account enrollment is a later design.

## Independent review of `6fb9d3d9` and the answers

The review passed the code to merge and asked for these before the founder enrolls:

- **F1 (a) UAC policy.** The service reads `EnableLUA`, `ConsentPromptBehaviorAdmin` and
  `PromptOnSecureDesktop` from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  (read-only, `win/uac.rs`), reports them in Status (`uac`, `uac_always_notify_on_secure_desktop`) and refuses
  enrollment and reset unless they are 1, 2 and 1 ("Always notify" on the secure desktop). A value it cannot
  read counts as not set. A standard account elevating with separate administrator credentials stays
  UNSUPPORTED: the elevated process runs as the administrator, whose Hello container is not the user's, so the
  key would belong to the administrator and the user's grants would find no key (refused, fail closed).
- **F1 (b) Trusted owner CLI.** Grant, enrollment and reset intents are refused unless the observed requesting
  image is a configured trusted owner CLI. The installer copies the hash-pinned `orcel.exe` to
  `%ProgramFiles%\Orcel\orcel.exe` (new `-OrcelSha256`; CI's artifact job builds and hashes it) and writes it
  to `config.json` as `trusted_owner_cli_images`; the service applies the orceld path and ACL checks to it at
  start. Status reports `caller_is_owner_cli`. Console mode takes `--trusted-cli` (tests and the scripted E2E
  trust their own runner). Residual (as for orceld): a process running as the user can start that image.
- **F1 (c) Elevated launches.** Every elevated step now starts one program directly from a normal shell
  (`Start-Process -Verb RunAs` on `%ProgramFiles%\Orcel\orcel.exe ... --pause`, or on
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <verified script>`), never an elevated terminal or a
  shell that loads the user's profile (runbook, "How every elevated step is started").
- **F2/F3 Residuals.** An attested key may be gesture-free (any TPM key certified by a Microsoft AIK passes the
  attestation check; nothing in it says KeyCredentialManager made it or that it needs a gesture); the
  attestation binds the key to *a* TPM with a Microsoft AIK, not to this PC's TPM (no EK or AIK of this PC is
  pinned); and there is no freshness (no service nonce). Windows Hello is therefore not an independent gate:
  the human gate is the Yes in the service-rendered box after a service-observed unlock (and, for enrollment,
  the UAC prompt on the secure desktop). The box and the runbook recommend a PIN or fingerprint over face
  recognition.
- **F4 Browser Authorize.** `AuthorizeClaims` carries the action's `origin`; for a browser lease the service
  refuses an `operation` that is not one of the lease's families and an origin that is not one of its origins
  (a missing origin is invalid). orceld sends the committed origin the covered action lands on.
- **F5 Desktop digest.** The desktop gate's action digest now binds the workspace, capability, operation,
  target, arguments and time (`desktop_action_digest`).
- **F6 Replacement order.** Keys live in two Hello slots ("Orcel Authority A" and "B"). `enroll --replace`
  creates the new key in the slot that does not hold the enrolled key; the enrolled key is deleted only after
  the service enrolled the new one (after the box's Yes and the new key's signature). Grants open the slot whose
  key matches the service's enrolled fingerprint. A process running as the user can delete Hello keys: that is
  a denial of service and fails closed (no key signs, grants are refused until the owner enrolls again).
- **F7 Wording.** A browser grant's box says "Orcel Browser Full Access (routine actions in one Orcel browser
  session)" and "Approve this browser grant?".

Tests for the review: `review_f1_*` (default UAC refuses enrollment and reset, Status reports the values, any
image but the trusted CLI is refused for grant and enrollment), `review_f4_f7_*` (family, origin and missing
origin refused; browser box wording; desktop wording kept), `the_uac_policy_is_read_without_writing`,
`roles_follow_observed_facts` (owner CLI match), the trusted-image prefix checks for the CLI, the install-script
tests (orcel.exe hashed before and after copying, config), `sg132_the_desktop_action_digest_binds_target_and_arguments`,
`sg132_a_new_key_never_takes_the_enrolled_slot`, and the console scripted grant with `--trusted-cli`. After
merging main (OB-03, OB-04), the scripted E2E passed again on this PC (2026-11-18): 54 receipts chained (head
`64fc24cc2a52485d`, receipt domain `orcel-ob08-receipt/3` with both `lease_id` and `profile`), the Full Access
part as before, and OB-04's phases (16 approvals, cookie kept across the restart, profiles isolated).

## 2. What the attestation check verifies, and what it cannot

`crates/orcel-authority/src/attestation.rs`, with a strict DER reader in `der.rs`:

| Verified | How |
| --- | --- |
| A TPM 2.0 `TPM2_Certify` statement | `PCP_KEY_ATTESTATION_BLOB` ("KADS", platform 2), `TPMS_ATTEST` with `TPM_GENERATED_VALUE` and `TPM_ST_ATTEST_CERTIFY` |
| It certifies exactly this public area | name = `nameAlg || H(TPMT_PUBLIC)` (SHA-256 or SHA-384) equals the certified name |
| The public area is the enrolled key | RSA modulus and exponent equal the SPKI's; at least 2048 bits |
| Non-exportable, TPM-generated signing key | `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `sign` set; `restricted` clear |
| Signed by an AIK | the statement's RSASSA signature (SHA-256/384) verifies with the leaf certificate's key; the leaf carries the TCG AIK usage 2.23.133.8.3 and is not a CA |
| The AIK chains to a pinned root | each certificate signed by the next (sha256RSA/sha384RSA), issuers are CAs, all valid now, no unknown critical extension; the root is the pinned Microsoft TPM Root Certificate Authority 2014 (SHA-256 `870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da`), in the chain or in `LocalMachine\CA`/`ROOT` (matched by that hash only) |

Not verified (recorded in every enrollment's `attestation.not_verified` and in Status `deferred`):

- that the key **requires a Hello gesture**: the attestation does not state it. KeyCredentialManager keys do,
  and step 5's signature is the evidence that this key signed once after a gesture. An attested TPM key made
  some other way (NCrypt with a Microsoft AIK) would also pass the check; the elevation and the fingerprint
  in the service's box are the gates against that, and an elevated attacker owns the machine anyway.
- **freshness**: `GetAttestationAsync` takes no nonce, so `extraData` is not the service's.
- **AIK revocation**: no CRL or OCSP is fetched (the service has no network access).
- **real hardware output**: no Hello key was created on this PC (that prompts). The parser follows the
  documented PCP layout (`MPCP` key blob with a `TPM2B_PUBLIC`, or a bare `TPM2B_PUBLIC`). If Windows returns a
  different layout or a chain format other than concatenated DER certificates, enrollment is **refused**, not
  accepted; the founder's first enrollment is the real test (runbook step "enroll").

If this PC has no pinned root, `EnrollBegin` answers `enrollment_unavailable` and Status says
`enrollment_available: false`. On this PC the root is present (`LocalMachine\CA`, SHA-1
`D4FFDB19BA590FFFAA34DB5F4B568706A2978436`); the founder should compare its SHA-256 with Microsoft's
published value before the first enrollment.

## 3. Grants (`orcel full-control grant`, `orcel browser grant`)

Both run the slice 1 grant flow through the service (`crates/orcel-lifecycle/src/authority_grant.rs`):
`GrantBegin` records the intent and returns the one-time code, which the CLI prints with its PID; the CLI waits
(polling `IntentStatus`, bounded by the 5-minute intent and the 120 s window) for the service-observed unlock
and the Yes in the service's box; it checks that the confirmation text matches its digest, then the enrolled
Hello key signs the challenge, which is bound to that text's digest; `PresenceComplete` returns the signed
lease. A Hello failure cancels the intent.

- `orcel full-control grant [--minutes N] [--executors a,b] [--root D:\x]... [--shells] [--client c] [--task t]`:
  with no widening flags the scope is the narrow default (desktop input only, no roots, no shells, 30 min).
  The service refuses Admin and Remote, roots without the filesystem executor, shells without
  `shell_process`, more than 8 roots and anything over 720 minutes.
- `orcel browser grant --session <bs-...> --client-ref <cl-...> --origin <https://host>... [--families ...]
  [--task t] [--minutes N]`: one broker session, its client (`client_ref`, also the lease's principal, so
  `Authorize` binds it), exact canonical origins (1 to 16), families from `navigate, click, type, select, tabs`
  only (`read`, `scroll`, `download` are refused by the CLI, the service and orceld), at most 12 hours.
  `orcel browser leases` and `orcel browser revoke <id>` list and revoke through the service.

## 4. OB-08 on the service

- **Issuance:** only the service. orceld's `browser.lease.issue` is refused ("leases come from the Orcel
  authority service only"); `list` and `revoke` go to the service. OB-08's owner-channel seam, its
  `browser-lease-dev-issuance` feature and the browser-lease additions to the user-readable store
  (`full_control_store.rs`, the HMAC'd revocation mark, `LocalGrantProof::id_key`) are removed; the release
  sweep now fails if `browser-lease-dev-issuance` is named outside docs. Default, development and release
  builds have no issuance path in orceld at all.
- **Verification in orceld** (`crates/orceld/src/authority_link.rs`, `ServiceLeaseSource`): Status over the
  verified pipe (server PID from the SCM, owner = the service SID) gives the public key; its key id must match.
  `List` gives this user's and logon session's leases; each active browser lease is admitted only if its ECDSA
  P-256 signature verifies with that key and its shape is canonical (`admit_browser_lease`). No key orceld or
  the user can read signs a lease. Only the trusted orceld image (role `orceld`) uses leases; any other orceld
  sees no lease and asks as before.
- **Per action:** the cached lease is re-checked against one fresh service read (lease still listed and
  unchanged, service epoch unchanged, revocation counter not behind, binding, session, client, task, expiry),
  the approval ledger's epoch (an emergency revoke since caching ends it), the clock and the takeover gate; then
  the service's audit-first `Authorize` (executor Browser, principal = client_ref, an action digest over lease,
  record, family, origin and page). Any failure refuses that action `lease_invalid`, nothing sent; later actions
  ask.
- **Kept from OB-08 unchanged:** the routine classifier (`orcel-contracts` `browser_impact`), GET-only covered
  link clicks, the host's refusal of every non-GET page request from the first covered action in a lifetime,
  secret-value refusal (looks secret, or matches a stored secret; an unreadable secret store asks), no cover
  without the takeover gate, intervention marks taken at caching and page open, invalidation on revoke, epoch
  move, session end and human interruption. A session end now revokes its lease at the service.

## 5. Desktop lease migration step

- `orcel full-control grant|revoke|status` use the service whenever it is installed (registered with the SCM;
  an SCM that cannot be asked counts as installed, fail closed). The old per-user store is **deprecated**: it
  keeps its existing behaviour only where the service is not installed and prints a deprecation note; it issues
  nothing once the service is installed (`revoke` still clears it, authority reducing).
- orceld's DesktopInput gate (`uia.rs` -> `authority_link::desktop_input_gate`): with the service installed,
  only an active, signature-verified, service-issued desktop lease of this user and logon session counts, and
  the service's `Authorize` (DesktopInput, audit first) must allow it; an unreachable service refuses, never
  falls back. Without the service, the deprecated store check is unchanged. Residual: the desktop gate names the
  lease's own principal in `Authorize` (orceld does not know the MCP client at that gate); WP1-12's dispatcher
  carries the real client.
- Next: WP1-12 moves every lease-gated executor behind `Authorize` with Job Objects, then the store is retired.

## 6. Threat model updates (same-user agent with Full Control)

| Attack | Slice 2 answer |
| --- | --- |
| Enroll its own key | Needs an elevated token (UAC secure desktop), an attested TPM key and a Yes on the fingerprint box. Residual: with UAC below "Always notify", auto-elevation bypasses exist; the runbook requires "Always notify". An agent that is already elevated owns the machine. |
| Replace or reset the founder's key | Same gates; the box says REPLACES/REMOVE with the old fingerprint; all leases end and the epoch moves. |
| Forge or widen a browser lease | Needs the service's ECDSA key (DPAPI-wrapped under the virtual account, ACL-protected); orceld verifies every lease with the service-reported key. |
| Replay a revoked lease | The service lists it as revoked (not admitted); counters only grow; orceld refuses a service counter behind what it saw. |
| Use a lease from a dev orceld it controls | Only the trusted `%ProgramFiles%\Orcel\orceld.exe` gets `Authorize`; residual (slice 1): a same-user process can start or inject into that image. |
| Answer the confirmation or Hello | Unchanged from slice 1: confirmation input protection is WP1-10 (`confirmation_input_protected: false`); Hello needs the gesture. |
| Submit, pay, post through a covered action | Routine-only classification, GET-only covered clicks, non-GET blocking, secret refusal (OB-08, unchanged). |

## 7. What the founder must do

1. Install per [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md) from a hash-pinned build of this branch's
   reviewed commit (UAC set to "Always notify").
2. Check `orcel authority status`: `mode service`, `enrollment available true`.
3. Compare the pinned root: `Get-ChildItem Cert:\LocalMachine\CA | Where-Object Thumbprint -eq
   D4FFDB19BA590FFFAA34DB5F4B568706A2978436`, its SHA-256 must be `870c7a35...a999da` and match Microsoft's
   published Microsoft TPM Root Certificate Authority 2014.
4. Elevated and directly (runbook step 7): `Start-Process -Verb RunAs -FilePath
   "$env:ProgramFiles\Orcel\orcel.exe" -ArgumentList 'authority','enroll','--pause'`. Create the key in the Hello prompt; compare the code
   and fingerprint printed with the Orcel Authority box; Yes; one more Hello gesture. If attestation fails, send
   the CLI's message: that is the hardware fact this slice could not record.
5. From a normal terminal: `& "$env:ProgramFiles\Orcel\orcel.exe" full-control grant` (narrow default), then Win+L and unlock; compare code,
   process and scope in the box; Yes; Hello. Then `orcel full-control status` and `orceld authority-status`.
6. Browser: in an MCP session, `browser_session_create` returns `session_id` and `client_ref`; then
   `orcel browser grant --session <id> --client-ref <ref> --origin https://<site>`.
7. Check Event Viewer (Application, source Orcel): 4102 intents, 4104 enrollment, 4101 granted scope; each
   ends in `|sig=` that verifies with `authority-public\lease-signing-key.json`.

## Tests

- `cargo test -p orcel-authority`: 46 unit tests, including attestation against built test vectors (valid
  chain; root from the chain or from the store; wrong key; name mismatch; missing fixedTPM, fixedParent,
  sensitiveDataOrigin, sign; restricted; tampered statement; non-AIK signer; no AIK usage; unknown critical
  extension; expired; unpinned root; real pin list refuses the test root; malformed blobs), one recorded real
  vector (the Microsoft TPM root from this PC's store: pinned hash, self-signed, CA, current), DER bounds and
  times, enrollment (elevation, roles, claimed origins, attestation refused, no root, console mode, fingerprint
  box, wrong signer, full flow, grant with the new key), replace (epoch, leases end, old key fails), reset (No
  keeps, Yes removes once), browser grant limits (families, 17 origins, principal); 10 console-harness
  integration tests (enrollment and reset refused in console mode; with `--features authority-scripted-consent`,
  a whole browser grant over the pipe, a wrong presence refused, the lease verified with the published key,
  `Authorize` orceld-only, revoke); 5 install-script tests.
- `cargo test -p orceld -- ob08 sg132`: 26 tests: service-signed admission (stranger key, changed body,
  desktop lease, unimplemented family, list states), real ECDSA admission, the cache (coverage, one read and one
  `Authorize` per action, refused `Authorize`, scope, binding drift, epoch and counter, emergency revoke after
  caching, revoke and every change before dispatch, interruption, session end revokes at the service, status),
  management (issue refused, list, revoke, malformed), agents/MCP/remote refused, an unreachable service covers
  nothing.
- `cargo test -p orcel-policy browser_lease`, `cargo test -p orcel-lifecycle sg132` (scope parsing, narrow
  default, browser limits, fingerprint), the release-blocker sweep (dev issuance gone; scripted consent
  confined), dependency direction.
- Scripted E2E (`scripts/browser-full-e2e.mjs --consent scripted`): builds the authority console harness with
  `authority-scripted-consent`; the grant goes over the authority pipe; orceld finds the harness through
  `ORCEL_E2E_AUTHORITY` (only in its `browser-full-scripted-consent` test build). The scripted stand-in exists
  only in those test features; the sweep confines `authority-scripted-consent`. Run on this PC (2026-11-18,
  installed Edge, worker `node_modules` copied from a checkout with the same lockfiles): passed, 58 steps, 54
  receipts chained (head `1f104b2da9c7862a`), 7 SOFT prompts, 0 STRONG prompts in orceld, 1 scripted authority
  confirmation; service lease `al-b1a54bc9...`; 25 routine actions plus 3 on the posting page under it with 0
  prompts, no page post or beacon left; after the revoke the next open was refused `lease_invalid: the browser
  lease was revoked` and the one after asked. Scripted consent: not human acceptance.
- Test environment note: Orcel's private-root checks refuse a TEMP under `D:\` (Authenticated Users may write
  there), so the suites ran with TEMP in the user profile outside AppData; with that, `cargo test -p
  orcel-authority -p orceld -p orcel-lifecycle -p orcel-policy -p orcel-approval` passes (clipboard tests left
  to CI).

## Open risks

1. Real `GetAttestationAsync` output was never parsed (no Hello prompt allowed here): a layout difference
   refuses enrollment until fixed.
2. KeyCredentialManager from an elevated process is untested here; if Windows refuses it, enrollment needs a
   split design (create unelevated, submit elevated).
3. The attested key may be gesture-free, is not bound to this PC's TPM, and the attestation is not fresh
   (section 2 and the review answers); Hello is not an independent gate.
6. A standard account elevating with separate administrator credentials cannot enroll its own key (refused).
7. A process running as the user can delete the Hello keys (denial of service, fail closed).
4. Confirmation input protection (WP1-10) and the trusted-orceld-by-path residual are unchanged from slice 1.
5. The branch carries OB-03 (#806) until it merges; OB-08 needs its independent security re-judge on this shape.
