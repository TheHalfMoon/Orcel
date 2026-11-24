# Approval integrity and new attack surfaces

Status: ADOPTED planning direction (founder decision, 2026-10-09; Sol revision governs where it differs from the Opus baseline). Grants no authority: every capability still needs its own grain, review and qualification. Current execution state: `EXECUTION_FRONTIER.md`. Evidence baseline of this revision: PR #283 at `87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985`, PR #282 at `10540885f3c52bd0c0d2f00cc23e3cafe067fe36`.

## Independent verdict on #278

Update 2026-10-10: #278 is repaired by PR #286 (merged as `main@1edfa20`, post-merge CI green, issue closed). Design, qualification evidence and residual risks: `docs/security/ISSUE-278_APPROVAL_LEDGER_INTEGRITY_NOTE.md`. The repair answers the qualification matrix below: one durable event transaction path under a per-transaction cross-process lock; strict verification of every event; fail-closed handling of torn, replaced or unverifiable ledgers; explicit evidence-preserving recovery (`orcel approvals recover`); prompts bound to chain identity and revoke epoch. Restart model chosen: approvals are not invalidated by a broker restart (they expire after five minutes); a fresh broker cannot detect deletion of a complete valid tail without an external anchor, which remains a documented residual risk.

The historical verdict follows.

CONFIRMED library integrity defects. Restart replay and record loss are reproduced, and two live broker instances can accept one token. Keep #278 open and prohibit new token-holding/session/remote privileges until an independently qualified repair. No production repair was made in this planning task.

Applicable root SECURITY.md assigns approvals, trust, leases and protected state to orceld. The tests run in a managed temporary repository copy, with the original production library unchanged and three tests added inside its existing test module. The first two reproduce Opus's cases; the third exercises two independently constructed public broker instances. Fake verified presence is a controlled test verifier, not an attempt to bypass real Windows Hello.

Command: `rtk proxy cargo test --locked --offline -p orcel-approval -- --nocapture --test-threads=1` on native Windows, Rust 1.97.1. Result: **27 existing tests passed, three added regressions failed, exit 101**, test duration 0.46 seconds. In-process replay denial passed before the restart replay assertion. This is an EXPERIMENTAL FINDING, not a passing repair qualification or a daemon-level exploit.

| Added assertion | Actual result |
|---|---|
| Issue A/B, consume A, reload, reject A | Reloaded ledger accepts A; assertion fails |
| Issue A, consume A, issue C, reload, retain C | C absent; assertion fails |
| Two brokers load the same issued token; second rejects after first consumes | Both accept; assertion fails |

Retained raw run log SHA-256: `8f9cf8db98b23f19fa007fd76630debeee450712415da951c1ed422a6d402b2e`. The review delivery includes the harness patch and exact command; no tests were committed to production code. Normal unit passes do not cover these failure modes.

## Root cause and reachability

At the reviewed [approval source](https://github.com/TheHalfMoon/Orcel/blob/87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985/crates/orcel-approval/src/lib.rs), load_or_create (line 965) silently accepts a valid prefix after read/parse/chain failures. consume (line 1114, tip mutation near 1192) rewinds the chain tip to the issuance checksum; append_consumed_marker (1223) fails to advance it to the new marker. record_decision and record_revoke also update memory/tip/epoch before persistence succeeds. flush is not durable sync; a per-instance Mutex is not an OS-wide single-writer lock. Loading the entire file is unbounded.

The inspected [filesystem mutation callsite](https://github.com/TheHalfMoon/Orcel/blob/87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985/crates/orceld/src/fs_mutation.rs#L96) requests and consumes the token within one call. This limits the demonstrated restart exploit there: no surviving externally replayable token was shown. I did not prove that every shipped callsite is safe, nor demonstrate unauthorized production dispatch after restart. Opus's categorical 'tokens never cross a boundary' and numerical LOW exploitability are broader than this evidence. Integrity/audit loss is confirmed; production exposure remains to be traced completely. Future persisted approvals, interactive sessions, remote delivery and cross-device actions materially increase risk.

## Repair assessment: direction right, not sufficient

| Proposed repair element | Assessment / necessary correction |
|---|---|
| Immutable issued and consumed events, linear chain | Correct. Include revoke and denied events with one serialization/version rule and bounded parser. |
| Advance tip only after write + flush + sync | Correct for every event and epoch, not only consume. Never dispatch before durable consume. |
| Lifetime exclusive Windows lock | Correct goal; lock the actual ledger identity and avoid replaceable-lock-file races. Handle second process, crash and path aliasing. |
| Deny any malformed/corrupt load | Correct. Distinguish truly absent first-install ledger from unreadable, malformed, tampered and partial existing files. Preserve forensic bytes. |
| HMAC + DPAPI | Authenticates bytes against attackers without the key. Same-user DPAPI/key access remains a limitation; it does not make same-user tampering impossible. |
| Valid-prefix rollback | HMAC chaining does not detect removal of an intact tail or restoration of an old valid file. Require protected monotonic anchor/rollback defense, or a simpler explicitly adopted session-bound token design that invalidates all prior-session approvals and makes recovery fail closed. Audit truncation detection remains separate. |
| Automatic .legacy-broken rename/new genesis | Reject silent recovery. Preserve evidence, invalidate all prior tokens/leases, require explicit trusted recovery/migration and test interruption at each phase. Five-minute TTL is not 'no impact' proof. |
| Revert to old ledger | Reject. Disable dependent capabilities on repair failure; rollback must not re-enable known-broken replay semantics. |

On an ambiguous append/sync failure, deny dispatch and poison the broker for further authority-changing operations until validated recovery. Do not continue writing from an unknown in-memory tip. A durable consumed record followed by a crash before dispatch may deny a retry; availability loss is preferable to duplicate privilege. Bind fresh proposal/approval to content/path/window generation at final dispatch to address TOCTOU independently of the ledger chain.

Keep the security repair minimal in product scope: one writer, one durable event transaction path, strict bounded loading, explicit migration, and a clearly specified restart/rollback model. A full distributed approval system or general event database is not required. Whether all tokens should die on broker restart is an OPEN DECISION with compatibility implications, not an unnoticed implementation shortcut.

## Existing offline repair candidate: not native qualification

The public [follow-up on the sentinel prototype](https://github.com/TheHalfMoon/Orcel/issues/278#issuecomment-6073712808) correctly distinguishes its Python behavior tests and synthetic patch-order checks from Rust/Windows qualification. The candidate archive is not available in this checkout; it was not independently compiled or accepted here. A create_new claim only serializes cooperating brokers reaching the same filesystem identity, and pathname cleanup can race replacement. Crashes leave stale claims; do not automatically steal/delete them. Require protected parent/ledger handle identity, ACL/reparse checks, bounded loading and explicit recovery.

Workspace Cargo.toml declares Rust MSRV 1.82; the actual reproduction host used 1.97.1. The issue notes std File::lock stabilized in 1.89, so native LockFileEx or a reviewed MSRV-compatible implementation is required unless a separate toolchain change is authorized. Running on the newer host does not qualify MSRV. Preserve candidate limitations instead of treating its model 8/8 or synthetic patch checks as a production fix.

## Qualification matrix still required

Existing tests plus all three regressions must pass after repair. Add out-of-order A/B consumption and repeated restart; revoke/restart/old token; expired/digest/workspace/revision mismatch; duplicate brokers/processes; path aliases and replaced ledger; empty/unreadable/malformed/truncated/valid-prefix-restored ledgers; mid-write and sync failure on issued/consumed/revoke events; crash after sync before response/dispatch; migration interruption; size limits; randomized interleavings. Verify no dispatch on persistence failure and no resume after poisoned state. Fault injection, disk durability, production reachability and repair tests have NOT been run here.

No issue closure until signed+DCO repair, independent code review (from 2026-11-23, replacing Jev) and Alibaba review with manual exclusions, exact-head required CI, independent non-admin Windows tests, resolved review threads, approved normal merge and post-merge evidence. Historical 9/9 text cannot substitute for live required contexts.

## Other material attack surfaces

- **Browser:** network egress enforcement must cover actual traffic, redirects/private addresses, downloads and uploads; a pipe removes exposed CDP ports but not browser privileges. Dedicated profile and no cookie export.
- **Cloud/model:** observations are untrusted data, never policy; per-tenant caches/queues and egress grants; schema/target/generation validation; no model-approved mutations. Reliance can abstain or strengthen checks, never authorize.
- **Privacy:** inspected private donor redaction filters registered secrets; it does not discover all secrets in arbitrary OCR/screenshots. Minimize/crop, suppress password/protected fields, permit explicit destinations and test known plus previously unknown canaries. Do not promise zero leakage from one detector.
- **UI:** authenticated private IPC, kernel-owned exact-action dialog, immediate authority-reducing stop without a network/Hello round trip, truthful unknown outcomes. Same-user spoofing remains residual risk.
- **Remote:** grants and epochs are target-specific; source egress and destination write approvals separate; relay TLS is not endpoint E2E; no credential inheritance or durable offline mutations.
- **Shell:** retain authorized SG096 lifecycle and executable identity checks. Job Objects supervise ownership; they are not a filesystem/network sandbox. Unproved termination must not be reported as completed cancellation.
- **Supply chain:** pinned signed/attested workers, SBOM/notices, bounded admission diff and Graft where imports merit it; no arbitrary runtime downloads or remotely activated instructions in tool results.

## Validation receipt

Candidate: public issue #278. Verdict: CONFIRMED ledger-level integrity/replay/concurrency behavior; current end-to-end unauthorized production actuation NOT DEMONSTRATED. Rubric criteria met: original-code reproduction and in-process negative control, source trace, constrained reachability assessment and repair challenge. Durability/fault/migration/full callsite tests remain prospective. Production diff: none. Artifacts: retained raw log and test-only patch. Workflow used: installed Codex Security validation skill; this receipt is not a repository-wide security audit.
