# SG-000132 slice 10: standing approvals (WP1-14)

Status: implemented and tested on branch `authority/wp1-14-standing`; not installed. Nothing in this slice was
installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry,
firewall or ACL setting changed. Earlier: [SG132_SLICE1.md](SG132_SLICE1.md) to [SG132_SLICE9.md](SG132_SLICE9.md).

**What this slice does:** the engineering of WP1-14 ([UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md)
section 8.2: "Standing approvals (4.15)", dependencies WP1-10 and WP1-12, `cargo test -p orcel-authority standing_`
(scope, client, expiry, stop)) in the authority service, the Full Control dispatcher and the owner CLI. No UI: the
indicator (WP1-12) belongs to the Design session and is not built here, and approvals stay with the service's own
confirmation box and Windows Hello.

Sources, as they bind this slice:

| Source | What it says |
| --- | --- |
| Spec 4.15 (FD-UP-10) | The `StandingApproval` shape (`lease_id`, `principal_id`, `task`, `executors` "never Admin", `roots`, `origins`, `commands`, an expiry "at most the lease's"). "Granted with STRONG presence for one identified client and one declared task; shown on the indicator; every dispatch it covers is authorized and audited individually with its id; ended by stop, lease end or expiry; never covers `Admin`, remote callers, out-of-scope targets or another client. Without one, each action keeps its own approval." |
| Spec 4.13 | Requests include `StandingBegin` and `StandingComplete`; the grant gate (intent, service-observed unlock, the service's `WTSSendMessageW` box, Hello); "Grants and renewals are refused while any Full Control lease is active"; `Authorize` checks "the standing approval (scope, task, expiry) or the action's own approval reference" |
| Spec 4.14 | The indicator's 1 s heartbeat; "The service refuses `Authorize` after 5 s without a heartbeat"; the heartbeat "proves nothing against a same-user agent (C-27 c)" |
| SG-000132 invariants | "Only the service issues leases and standing approvals, and only after a valid Windows Hello signature over its challenge; never while a lease is active in that session." "A lease alone never replaces an approval; only a standing approval for the same client, task and scope does." "The service never elevates; Admin is refused." |
| SG-000132 acceptance | "Grant, renewal and standing approval fail without a valid Hello signature, and while a lease is active." `Authorize` refuses an "out-of-scope standing approval" |
| SG-000132 amendment of 2026-11-19 | "a process run (fc_process_run) and the git mutations (fc_git_stage, fc_git_unstage, fc_git_commit, fc_git_branch_create) keep a fresh SOFT approval on every call (SG-000096 A3), unless a standing approval (spec 4.15) covers them; deletion keeps its own approval (SG-000097); remote callers stay excluded (SG-000105)" |
| SG-000132 amendment by SG-000135 | High-impact browser families "need an explicit narrow standing approval"; remote coverage of the `browser_full` profile is pending founder confirmation |
| SG-000096 A13 | A standing approval "out of scope (working directory or command pattern), expired, ended by stop, issued for another client, task or lease, or presented by a remote caller is refused before dispatch" |

## 1. Design

### 1.1 Issued together with its lease

A standing approval is bound to a lease, and the spec and the grain forbid any grant while a lease is active in the
session (spec 4.13, the SG-000132 invariant and acceptance above). A session lock also ends every lease (C-28), so a
standing approval cannot be added to a running lease through a fresh observed unlock either. The only reading that
satisfies all of these is that **a standing approval is issued with its lease, through the same intent**:

1. `orcel full-control standing grant` (the installed owner CLI) sends `StandingBegin` with the lease scope, the
   client reference, the task and the standing scope. The service applies every `GrantBegin` rule (owner CLI image,
   interactive console caller, enrolled key, no active lease, one intent per session, narrow fields) and then the
   standing rules (section 1.2) and the indicator check (section 2). The intent is the grant intent, with the
   standing scope in its digest and in Event Log 4102.
2. The first service-observed `WTS_SESSION_UNLOCK` opens the 120 s window, as for a grant.
3. The service's own box shows the lease scope, client, task and expiry, then a paragraph headed "STANDING
   APPROVAL" with the operations, folders, programs and the standing approval's expiry, and the limits (never Admin,
   remote callers, browser actions or another client; ended by Stop, lock, sign-out, revoke or the lease's end). The
   question is "Approve this grant and its standing approval?".
4. After Yes, Windows Hello signs the challenge bound to that exact text; `StandingComplete` (and only it: a
   `PresenceComplete` is refused for a standing intent, and `StandingComplete` for any other) issues the lease and the
   standing approval in one state write, audits both and writes both to Event Log 4101 (`orcel-grant/1|...` and
   `orcel-standing/1|...`).

### 1.2 What a standing approval covers

`crates/orcel-authority/src/standing.rs` (`StandingScope`, `StandingApproval`):

- **Client:** the lease's `principal_id`, which must be a `cl-` client reference (the one `fc_status` reports): "one
  identified client". A free label such as `orcel-owner` is refused.
- **Task:** the lease's declared task.
- **Executors:** `shell_process` only in this slice (process runs and Git changes), and only if the lease grants it.
  `admin` is refused (`CAPABILITY_DENIED`, "the authority service never elevates"), so is `remote`.
- **Operations** (an addition to the spec 4.15 struct, needed because one executor carries both a run and the Git
  changes): some of `run`, `git_add`, `git_unstage`, `git_commit`, `git_branch_create`, the operations that otherwise
  ask on every call (the 2026-11-19 amendment). Reads and the lease-covered writes never ask, and deletion does not
  exist; none of them can be named.
- **Folders** (`roots`): 1 to 8, each inside the lease's roots; every path a covered dispatch names must lie inside
  one of them.
- **Programs** (`commands`): optional, only with `run`; absolute `.exe` paths inside the folders. SG-000096's
  "command patterns" are read as exact program paths: no wildcard, no argument pattern.
- **Origins:** must be empty. High-impact browser actions keep their own approval in this slice (section 5).
- **Expiry:** at most the lease's; `--standing-minutes` shortens it.

The same rule, `StandingApproval::check_cover`, runs in orceld (to decide whether to ask) and in the service's
`Authorize` (which decides): same lease, client and task, a named executor and operation, the operation's own
capability (`fc.process` for `run`, `fc.git` for the Git changes), every path inside the folders, for a run its
program among the action's paths and, when programs are named, among them; no origin; not expired.

## 2. The indicator dependency: fail closed

Spec 4.15 says a standing approval is "shown on the indicator", and section 8.2 makes WP1-14 depend on WP1-12. The
indicator is not built (the Design session owns its visual design), and no request records a heartbeat yet
(`Heartbeat` stays unaccepted, as in slice 1). So the service fails closed:

- `StandingBegin` is refused with `INDICATOR_UNAVAILABLE` unless an indicator heartbeat of the caller's Windows user
  and logon session is under 5 s old (spec 4.14's threshold, `INDICATOR_HEARTBEAT_MS`); nothing is recorded.
- `StandingComplete` checks again before issuing; a heartbeat that went stale after the box issues nothing.
- `Authorize` naming a standing approval is refused with `INDICATOR_UNAVAILABLE` without a live heartbeat.
- `List` marks each standing approval `in_effect` only while it is in force and the heartbeat is live; orceld uses
  only those, so every action asks as before.

Today, therefore, **no standing approval can be issued or used**: the code path is complete and tested through a test
seam (`indicator_heartbeat_for_test`, compiled only into tests), and it starts working when WP1-12 adds the
indicator's `Heartbeat`. Spec 4.14's wider rule, that the service refuses every `Authorize` 5 s after the last
heartbeat, is WP1-12's and is not applied here: it would stop all Full Control until the indicator exists. The
heartbeat is disclosure only and proves nothing against a same-user agent (C-27 c); the gates are the owner CLI
image, the observed unlock, the service's box and Windows Hello.

## 3. Service

- **Protocol** (`protocol.rs`): `StandingBegin`, `StandingComplete`, `StandingRevoke`, and an optional `standing`
  claim on `Authorize` (`standing_id`, and for a run its `program`). Each is unknown to an older service, which
  refuses it (`deny_unknown_fields`), so the upgrade order is the service first; an `Authorize` without the claim is
  unchanged on the wire.
- **State** (`state.json`): `standing` records (the approval, the Windows user, logon and terminal-services
  session, state, end time and reason). The field is left out while empty, so a state without standing approvals is
  unchanged and still readable by an older service.
- **Authorize:** after the lease, executor, client, origin and roots checks of WP1-10, a named standing approval must
  be bound to the caller's user and logon session, in force, shown by a live indicator and cover the dispatch
  (section 1.2). The audit record carries the claim as session-asserted (`asserted.standing`) and the
  `standing_id` the service checked (`detail.standing_id`), written before the answer, which names it too. Every
  covered dispatch is authorized and audited individually, and gets its own Job Object, as any other.
- **Ending:** a standing approval ends with its lease (revoke, Stop from any process of the session, session lock,
  sign-out or disconnect, expiry, an epoch move, a re-enrollment), with its own expiry, and with `StandingRevoke`
  (any process of the same user and logon session; it only removes authority and adds one to the revocation
  counter; the lease stays). The service sweeps after every request and every tick, marks each ended approval with
  its reason (`revoked`, `stopped`, `expired`, `epoch_moved`, ...) and writes a `standing` audit record for it.
- **Status:** `standing_approvals` reports whether the caller's indicator is alive, the heartbeat threshold and the
  coverable operations; the `deferred` list says standing approvals are not in effect without the indicator.

## 4. Dispatcher and CLI

- `full_control_dispatch::run_in_worker` (WP1-10, SG132_SLICE8.md): for an operation that needs a per-action
  approval, it first asks the service for the standing approvals in effect (`AuthorityPort::standing`, from `List`)
  and looks for one that covers the operation for the chosen lease and the calling client
  (`covering_standing`); if one does, the person is not asked and `Authorize` names it; otherwise the person is asked
  through the Windows approval dialog, as before. A remote caller (the entry's own flag, now passed through
  `fc_requests::dispatch`) and a request with no identified client are never covered. A refused standing
  `Authorize` runs nothing and is not re-asked; an answer that does not name the same `standing_id` runs nothing
  either. Everything else (reads, lease-covered writes, desktop input, browser actions) is unchanged.
- `fc.status` lists this client's standing approvals in effect (operations, folders, programs, expiry), so the agent
  can tell the person which actions will not ask.
- `orcel full-control standing grant --client <cl-ref> --task <label> --root <path>... --operations <list>
  --folder <path>... [--program <exe>]... [--minutes <n>] [--standing-minutes <n>]`: the lease (filesystem and shells
  over the roots) and the standing approval, checked locally as the service checks them, then the grant gate.
  `orcel full-control standing revoke [--id <sa-...>]` and `orcel full-control standing status` reach only this
  logon session's approvals. Without the installed service, `standing` is refused (the deprecated store never issues
  one).

## 5. Threat rows

| Threat | Answer | Test |
| --- | --- | --- |
| An agent, MCP client, orceld or remote caller grants itself a standing approval | `StandingBegin` takes the grant gate: owner CLI image, interactive console caller, claimed origin owner CLI, intent, observed unlock, service box, Hello | `standing_is_issued_with_its_lease_through_the_owner_gate`; `console_harness::standing_requests_over_the_pipe_fail_closed` |
| A standing approval added to a running lease, or widened later | Refused while any lease is active; issued only with its lease, one state write | `standing_is_issued_with_its_lease_through_the_owner_gate` |
| A standing approval used or granted without disclosure | `INDICATOR_UNAVAILABLE` at `StandingBegin`, `StandingComplete` and `Authorize` without a live heartbeat; `in_effect` false | `standing_without_a_live_indicator_fails_closed`; `standing_survives_a_restart_only_as_its_lease_does_and_needs_the_indicator_again` |
| Admin or Remote through a standing approval | Refused at grant and at `Authorize` | `standing_admin_remote_and_browser_are_refused` |
| Browser actions through a standing approval | Origins refused; a browser lease cannot carry one; an `Authorize` with an origin is not covered | `standing_admin_remote_and_browser_are_refused`; `standing_covers_only_its_scope_client_and_task` |
| Out-of-scope program, folder, operation, capability, executor | `check_cover` refuses, at the service and at orceld (which then asks) | `standing_covers_only_its_scope_client_and_task`; `full_control_dispatch_tests::fc_dispatch_standing_mismatches_ask_as_before` |
| Another client, task or lease | Refused; the dispatcher asks | `standing_covers_only_its_scope_client_and_task`; `fc_dispatch_standing_mismatches_ask_as_before` |
| A scope wider than its lease, or an unidentified client | Refused at grant and by the CLI | `standing_scope_must_fit_its_lease_and_one_identified_client`; `orcel-lifecycle` `standing_grant_requests_are_checked_as_the_service_checks_them` |
| Expiry | Its own expiry and its lease's end it; the lease stays | `standing_expiry_ends_it_and_the_lease_stays` |
| Stop, lock, revoke, epoch move | Each ends it and is audited with its reason; another logon session cannot revoke or use it | `standing_stop_lock_revoke_and_epoch_end_it`; `standing_covers_only_its_scope_client_and_task` |
| A remote caller covered | orceld never names a standing approval for a remote request (and `fc.*` is local-only) | `fc_dispatch_standing_never_covers_a_remote_or_unidentified_caller`; `fc_requests_the_entry_refuses_remote_callers_before_dispatch` |
| orceld trusts a service answer for another approval | The answer must name the same `standing_id`; a refused standing `Authorize` runs nothing | `fc_dispatch_a_refused_or_unconfirmed_standing_authorize_runs_nothing` |
| A covered dispatch not audited | Each `Authorize` writes its record with the `standing_id` before answering | `standing_covers_only_its_scope_client_and_task`; `fc_dispatch_standing_covers_a_matching_run_and_commit_without_asking` |
| A restart keeps a standing approval in effect | The record persists with its lease; it needs a fresh heartbeat | `standing_survives_a_restart_only_as_its_lease_does_and_needs_the_indicator_again` |

## 6. UNVERIFIED (founder run)

All of these wait for WP1-12 (no heartbeat exists, so the installed service refuses every standing request today):

- a real `orcel full-control standing grant` through the installed service: the box shows the standing paragraph,
  Hello signs, Event Log 4101 has the `orcel-standing/1` entry beside the lease's;
- `fc_process_run` and `fc_git_commit` through a real MCP client running without a prompt inside the approval, and
  asking outside it;
- Win+L, Stop and `orcel full-control standing revoke` ending it on the installed service.

## 7. Residuals

1. **Nothing is in effect until WP1-12.** By design (section 2).
2. **Arguments are not bound.** A covered run may pass any arguments to a named program, and a covered commit or
   branch any message or name. Naming programs narrows a run; nothing narrows its arguments.
3. **orceld's claims.** Which path is the program, and whether the caller is remote, are orceld's claims (orceld is
   the configured trusted image, as for every `Authorize` claim); the service records them as session-asserted.
4. **Not signed.** A standing approval is held only by the service and named by id; orceld never presents it. Leases
   stay signed.
5. **Not built here:** standing approvals for desktop input (SG-000095's per-action approval stays), for high-impact
   browser actions (the SG-000135 amendment), and any remote coverage (pending founder confirmation).
6. **Tool descriptions.** The `fc_process_run` and `fc_git_*` MCP descriptions still say they ask on every call,
   which holds while nothing can be in effect; they change with WP1-12.
7. **Downgrade.** A service older than this slice refuses to start on a state that holds standing records (its
   state parse is strict); a state with none is unchanged.
8. **Same-user agent (C-27).** Once granted, a standing approval is used by whatever process speaks as its client
   reference inside its scope: that is its purpose. Its scope, client, task and expiry are what the owner approved in
   the service's box.

## 8. Tests

At head (Windows, unelevated):

- `cargo test -p orcel-authority`: 88 unit tests (8 `standing_`), 12 `console_harness` (1 for this slice), 7
  `dispatch_jobs`, 11 `install_script`.
- `cargo test -p orceld -- full_control_dispatch_ fc_requests_ fc_worker_ sg132`: 71 (4 new dispatcher tests);
  `ob04_shadow_scan`, `ob07b_vault_scan`, `dependency_direction`.
- `cargo test -p orcel-lifecycle` (`standing_grant_requests_are_checked_as_the_service_checks_them`) and
  `release_blocker_sweep`.
- `cargo clippy -p orcel-authority -p orceld -p orcel-lifecycle --all-targets -- -D warnings`; `cargo fmt`.

## 9. Next steps

1. WP1-12: the indicator and its `Heartbeat` (the Design session's visual design); then the founder runs of section 6.
2. The MCP descriptions of the asking tools once a standing approval can be in effect (residual 6).
3. Founder decisions if wanted: argument patterns (residual 2), high-impact browser standing approvals, remote
   coverage.
