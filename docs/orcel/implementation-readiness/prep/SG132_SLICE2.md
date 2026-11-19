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

## Re-verify of `f4f72a93` and the answers

- **Shell tampering.** `Start-Process` runs in the user's own shell, which a process running as the user could
  have changed. The runbook now makes the UAC prompt the check: on every elevated step, **Show more details**,
  then the exact program location and full command line from its table (create the build folder, install,
  uninstall, start the service, enroll, replace, reset), and No on any difference. Explorer avoids the shell but
  passes no arguments, so it suits only argument-free programs, with the same check.
- **Built-in Administrator.** The service also reads `FilterAdministratorToken` (Status `uac`) and refuses
  enrollment and reset from an account whose SID is `S-1-5-21-...-500` unless it is 1 (that account elevates
  with no UAC prompt otherwise); Status reports `caller_is_builtin_administrator`.
- **Registry view.** The UAC values are read from the 64-bit view (`RRF_SUBKEY_WOW6464KEY`).
- **Missing enrolled key.** If a key is enrolled at the service but no Hello slot holds it, `enroll` creates
  nothing unless `--replace` is given (`plan_new_slot`).

Tests: `review_reverify_the_builtin_administrator_needs_admin_approval_mode`,
`sg132_a_new_key_never_takes_the_enrolled_slot` (now also the missing-key cases),
`the_uac_policy_is_read_without_writing` (reads `FilterAdministratorToken` too).

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

- that the key **requires a Hello gesture** (residual): the attestation does not state it, and step 5's
  signature shows only that the enrolling process could use the key. An attested TPM key made some other way
  (NCrypt with a Microsoft AIK) would also pass the check; the elevation, the trusted CLI image and the
  fingerprint in the service's box are the gates against that, and an elevated attacker owns the machine
  anyway.
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
  The dispatcher, the service-made Job Objects and `orceld fc-worker` are in [SG132_SLICE3.md](SG132_SLICE3.md).

## 6. Threat model updates (same-user agent with Full Control)

Every row names the tests that show its claim, or says it is not shown. "UNVERIFIED (founder run)" means only
the installed service on real hardware can show it; "residual" means it is a known limit, not a guarantee. Test
names are Rust test functions: `core_tests` and `attestation_tests` are in `crates/orcel-authority/src/`,
`console_harness` and `install_script` in `crates/orcel-authority/tests/`, `ob08_lease_tests` and
`authority_link` in `crates/orceld/src/`. "Scripted E2E" is `scripts/browser-full-e2e.mjs --consent scripted`
(scripted consent stands in for the unlock, the confirmation and Hello; not human acceptance).

| Attack | Claim | Evidence |
| --- | --- | --- |
| Enroll its own key without elevation | Refused: the service reads elevation from the caller's token | `core_tests::enrollment_needs_an_elevated_owner_and_a_verified_attestation`; `console_harness::issuance_is_refused_to_orceld_and_to_claimed_agent_origins` (console mode refuses enrollment and reset). That the installed service reads a real elevated token: UNVERIFIED (founder run) |
| Enroll from a process other than the installed CLI | Refused unless the observed image is a trusted owner CLI | `core_tests::review_f1_enroll_and_reset_need_always_notify_and_every_intent_the_owner_cli`; `caller::tests::roles_follow_observed_facts`; `service::tests::trusted_images_outside_program_files_orcel_are_refused`; `install_script::the_trusted_orceld_is_the_program_files_copy_and_directories_are_created_protected`. Residual: a process running as the user can start that image |
| Enroll while UAC would not prompt | Refused unless UAC is Always notify on the secure desktop, and from the built-in Administrator unless `FilterAdministratorToken` is 1 | `core_tests::review_f1_enroll_and_reset_need_always_notify_and_every_intent_the_owner_cli`, `core_tests::review_reverify_the_builtin_administrator_needs_admin_approval_mode`, `uac::tests::the_uac_policy_is_read_without_writing`. That the UAC prompt appears on the secure desktop and shows the expected command line: UNVERIFIED (founder run). Residual: an agent already elevated owns the machine |
| Enroll a software or unattested key | Refused unless the attestation verifies to the pinned root | `attestation_tests::the_attestation_must_be_about_the_enrolled_tpm_key`, `attestation_tests::the_statement_must_be_signed_by_an_aik_chaining_to_a_pinned_root`, `attestation_tests::malformed_blobs_are_refused`, `attestation_tests::the_pinned_microsoft_tpm_root_on_this_pc_is_self_signed_and_current` (built vectors plus the real root). A real `GetAttestationAsync` buffer: UNVERIFIED (founder run). Residual: an attested key may be gesture-free and is not bound to this PC's TPM; no freshness |
| Enroll a key the owner did not see | Enrolled only after a Yes on a box showing its fingerprint, then the new key's own signature | `core_tests::enrollment_shows_the_fingerprint_and_enrolls_only_after_the_new_key_signs`. That `WTSSendMessageW` from the virtual account reaches the console session: UNVERIFIED (founder run) |
| Replace or reset the owner's key | Same gates; the box names the old fingerprint; every lease of the user ends and the epoch moves; the new Hello key never overwrites the enrolled one | `core_tests::re_enrollment_needs_replace_and_ends_every_lease_of_the_user`, `core_tests::a_reset_needs_elevation_and_a_confirmed_yes`, `authority_grant::hello::tests::sg132_a_new_key_never_takes_the_enrolled_slot` |
| Delete the owner's Hello keys | Denial of service only: grants fail closed until the owner enrolls again | Residual (documented); no test, it needs Windows Hello |
| Record a grant and approve it itself | Needs the owner CLI image, a service-observed unlock, a Yes on the service's box bound into the challenge, and the enrolled key's signature | `core_tests::issuance_is_refused_for_every_non_owner_caller`, `core_tests::a_grant_binds_the_code_the_requesting_process_and_the_confirmation_text`, `core_tests::a_wrong_code_or_signature_is_refused_and_consumes_the_intent`, `core_tests::the_window_closes_and_a_no_or_a_timeout_ends_the_intent`. Residual (C-27 f, WP1-10): a same-user process can imitate the box or try to answer it (`confirmation_input_protected: false`) |
| Rely on Hello as consent | Not claimed: Hello shows presence and key possession only; the human gate is the Yes after a service-observed unlock | Residual (review F2); the box text: `core_tests::review_f4_f7_browser_authorize_checks_family_and_origin_and_the_box_says_browser` |
| Forge or widen a browser lease | orceld admits only leases whose ECDSA signature verifies with the service's key and whose scope is canonical | `ob08_lease_tests::ob08_only_service_signed_browser_leases_are_admitted`, `ob08_lease_tests::ob08_review_unimplemented_families_are_never_admitted`, `authority_link::tests::sg132_browser_leases_are_admitted_only_with_the_service_ecdsa_key`, `console_harness::a_scripted_grant_issues_a_signed_browser_lease_over_the_pipe` (with `--features authority-scripted-consent`); scripted E2E. That the installed state directory is unreadable to the user: `acl::tests::*` check the rules; on the installed service UNVERIFIED (founder run, runbook step 5) |
| Use a lease beyond its family or origin | The service's `Authorize` refuses a family or origin the lease does not name | `core_tests::review_f4_f7_browser_authorize_checks_family_and_origin_and_the_box_says_browser`; orceld side: `ob08_lease_tests::ob08_anything_not_positively_routine_or_out_of_scope_asks` |
| Replay a revoked or older lease | A revoked lease is not admitted; counters only grow; orceld refuses a service counter behind what it saw | `core_tests::revoke_stop_lock_and_expiry_move_the_counters_and_end_leases`, `ob08_lease_tests::ob08_revoke_between_decision_and_dispatch_refuses_at_once`, `ob08_lease_tests::ob08_review_a_service_that_went_back_refuses`, `ob08_lease_tests::ob08_every_change_found_right_before_dispatch_refuses`; scripted E2E (the action after the revoke refused `lease_invalid`) |
| Use a lease from a dev orceld it controls | Only the trusted orceld image gets `Authorize` and sees service leases | `console_harness::authorize_needs_the_trusted_orceld_image_and_a_live_lease`, `authority_link::tests::sg132_only_the_trusted_orceld_role_uses_service_leases`. Residual (slice 1): a same-user process can start or inject into that image |
| Keep acting after the owner intervenes | A person's input, an emergency revoke, session end or an unreachable service ends the lease's use | `ob08_lease_tests::ob08_human_interruption_ends_lease_use`, `ob08_lease_tests::ob08_an_emergency_revoke_after_caching_ends_the_lease`, `ob08_lease_tests::ob08_session_end_revokes_the_lease_at_the_service`, `authority_link::tests::sg132_an_unreachable_service_covers_nothing` |
| Act under a lease on a page waiting for human verification (OB-07) | HUMAN_VERIFICATION_REQUIRED is decided by the takeover gate (on for every browser_full session since OB-07) before the lease is consulted and again before it is used; the service's Authorize is never asked | `takeover_gate::tests::ob07_ob08_a_covered_action_on_a_page_awaiting_verification_is_refused_without_lease_use` (`crates/orceld`), `ob08_lease_tests::ob08_review_without_the_takeover_gate_nothing_is_covered` (the gate's absence still covers nothing, as a defense) |
| Submit, pay, post or send a secret through a covered action | Routine-only classification, GET-only covered clicks, non-GET blocking, secret refusal | `browser_impact::tests::submit_send_buy_publish_and_delete_links_are_high_impact`, `browser_impact::tests::unreadable_or_empty_names_are_unknown_never_routine` (`crates/orcel-contracts`), `worker_navigation::tests::ob08_the_lease_guard_refuses_every_page_request_but_get` (`crates/orcel-browser-host`), `ob08_lease_tests::ob08_review_secret_values_are_never_typed_under_a_lease`; scripted E2E (the submit link asked; no post or beacon left the posting page) |
| Act on the desktop with a stale or user-readable lease | With the service installed only a service lease and its `Authorize` count; the audit names the action's arguments | `authority_link::tests::sg132_the_desktop_action_digest_binds_target_and_arguments`. The gate against an installed service: UNVERIFIED (founder run); without the service the deprecated store behaves as before (existing `full_control_store` tests) |

## 7. What the founder must do (all UNVERIFIED until the founder runs them)

None of these steps has run: they need the installed service, UAC and Windows Hello, which this work could
not use. Each step says what it is the first evidence of.

1. Install per [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md) from a hash-pinned build of the reviewed
   commit, with UAC set to "Always notify" and the UAC prompt's details checked against the runbook's table.
   First evidence of: the install script on a real machine (only its `-WhatIf` preview is tested,
   `install_script::the_whatif_preview_runs_unelevated_in_every_shell_and_checks_hashes`).
2. `orcel authority status`: `mode service`, `enrollment available true`, `UAC always notify on secure desktop
   true`. First evidence of: the service start checks and the UAC read under the virtual account.
3. Compare the pinned root (runbook step 6). Already checked on this PC by
   `attestation_tests::the_pinned_microsoft_tpm_root_on_this_pc_is_self_signed_and_current`; the founder
   compares it with Microsoft's published value.
4. Enroll (runbook step 7, the UAC prompt's details checked): compare the code and fingerprint with the box;
   Yes; one more Hello gesture. First evidence of: KeyCredentialManager from an elevated process, a real
   attestation buffer, the service-rendered box. If attestation fails, report the CLI's message.
5. A first desktop grant (runbook step 8): Win+L, unlock, compare code, process and scope; Yes; Hello. First
   evidence of: the service-observed unlock and a real Hello signature.
6. A browser grant (runbook step 9) and one routine browser action through the installed orceld. First
   evidence of: OB-08 against the installed service (the scripted E2E used the console harness).
7. Event Viewer (Application, source Orcel): 4102, 4104, 4101, each ending in `|sig=` that verifies with
   `authority-public\lease-signing-key.json`.

## Tests

Counts at head (Windows, TEMP in the user profile outside AppData; clipboard tests left to CI):

- `cargo test -p orcel-authority`: 50 unit tests (`attestation_tests`, `core_tests`, `der`, `lease`,
  `caller`, `win::*` including `uac`), 9 `console_harness` tests (10 with `--features
  authority-scripted-consent`, which adds `a_scripted_grant_issues_a_signed_browser_lease_over_the_pipe`), 5
  `install_script` tests.
- `cargo test -p orceld -- ob08 sg132`: 28 tests (`ob08_lease_tests`, `authority_link::tests`).
- `cargo test -p orcel-lifecycle sg132`: 4 tests (scope parsing, narrow default, browser limits, fingerprint,
  key slots); `cargo test -p orcel-policy browser_lease`: 5 tests; the release-blocker sweep (dev issuance
  gone; scripted consent confined) and dependency direction.
- Scripted E2E, last run at `f4f72a93` after merging main: passed, 54 receipts chained (head
  `64fc24cc2a52485d`), 25 routine actions and 3 on the posting page under a service lease with 0 prompts, the
  submit asked, the action after the revoke refused `lease_invalid`, one scripted authority confirmation, and
  OB-04's phases. Scripted consent: not human acceptance.

## Open risks

1. Real `GetAttestationAsync` output was never parsed (no Hello prompt allowed here): a layout difference
   refuses enrollment until fixed (UNVERIFIED, founder run).
2. KeyCredentialManager from an elevated process is untested here; if Windows refuses it, enrollment needs a
   split design (create unelevated, submit elevated).
3. Residual: the attested key may be gesture-free, is not bound to this PC's TPM, and the attestation is not
   fresh (section 2 and the review answers); Hello is not an independent gate.
4. Residual: confirmation input protection (WP1-10) and the trusted-image-by-path weakness are unchanged from
   slice 1.
5. A standard account elevating with separate administrator credentials cannot enroll its own key (refused).
6. Residual: a process running as the user can delete the Hello keys (denial of service, fail closed).
7. OB-08 needs its independent security re-judge on this shape.
