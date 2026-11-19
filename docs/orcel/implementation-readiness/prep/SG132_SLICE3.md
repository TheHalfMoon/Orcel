# SG-000132 slice 3: the Full Control dispatcher, service-made Job Objects and `orceld fc-worker`

Status: implemented and tested on branch `authority/wp1-12-dispatcher`; not installed, not reviewed. Nothing in
this slice was installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no
system, registry, firewall or ACL setting changed. Slice 1 is [SG132_SLICE1.md](SG132_SLICE1.md), slice 2
[SG132_SLICE2.md](SG132_SLICE2.md), installing [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec:
`.specgrain/specs/SG-000132.json` (in scope: `crates/orceld/src/full_control_dispatch.rs` as the only path for
lease-gated executors; service-made named Job Objects; `orceld fc-worker`).

Naming: the slice 1 and 2 documents call this work WP1-12 ("Next slices" item 2 and 3, slice 2 section 5), and
the code and tests here follow them (`wp112_` test names). The work packet table of
[UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) puts the dispatcher, the service-owned Job Objects
and `fc-worker` under WP1-10 and names the indicator WP1-12 and standing approvals WP1-14. Same work, two labels;
nothing here is the indicator or standing approvals.

**What this slice makes possible:** every lease-gated Full Control executor goes through one dispatcher in
orceld. The service's `Authorize` now also checks paths against the lease's roots and, for filesystem and
shell/process work, makes a fresh named Job Object for that one dispatch before it writes its allow record. The
filesystem family runs end to end: Authorize, `orceld fc-worker` started suspended into the job, assigned,
resumed, the operation inside the roots, the outcome reported, and the job terminated by the service.

## 1. The dispatcher (`crates/orceld/src/full_control_dispatch.rs`)

One path for desktop input, filesystem, process and git:

1. **Family and digest.** `Family::{DesktopInput, Filesystem, Process, Git}`. Desktop input needs the
   `desktop_input` executor; filesystem `filesystem`; process and git run programs, so they need
   `shell_process` (granted only together with `shells`); filesystem and git name their paths, which must lie in
   the lease's roots. The action digest is length-prefixed SHA-256 over the family, workspace, capability,
   operation, target, arguments, the paths and the time (`orcel-full-control-action/1`); desktop input keeps
   slice 2's `orcel-desktop-lease-action/2`.
2. **Lease.** Only active leases of this user and logon session that the verified service listed and whose ECDSA
   signature verified with the service's key. A lease that does not admit the executor, names another client,
   or whose roots do not hold every path is not used (`LEASE_REQUIRED`, `CAPABILITY_DENIED` or `PATH_ESCAPE`).
3. **Authorize.** The service checks lease, epoch, binding, executor, client and (new) the paths against the
   roots again, makes the dispatch's job, and writes the allow record naming it before it answers. orceld
   refuses an answer without an authorization id, for another lease, or whose `job_name` is missing or malformed
   for a job family, or present for desktop input (`AUTHORITY_UNAVAILABLE`).
4. **Run.** Desktop input runs in orceld as before (the computer host; SG-000095's per-action approval
   unchanged). Filesystem operations run only in `orceld fc-worker` in the job. Process and git use the same
   launch and are the next step (section 7).
5. **Outcome.** `Outcome { authorization_id, outcome, code }` (orceld only, once per authorization, same user
   and logon session); the service terminates the job first, then records the outcome. A failure to report is
   written to orceld's error output (the action already ran); the job still ends with the lease or after its
   processes exit.

Fail closed: with the service installed, an unreachable service, a failed check or a missing job refuses; the
deprecated user-readable store is consulted only for desktop input and only when no service is installed at all
(slice 2 behaviour, unchanged). Filesystem, process and git refuse without the service.

Desktop input migration: `uia.rs`'s `require_full_user_desktop` still calls
`authority_link::desktop_input_gate`, which now is the dispatcher's desktop path with `ServicePort` (the verified
service). `dispatch_uia` wraps every desktop request so the outcome of each desktop authorization it took is
reported when it returns, including refusals after Authorize (a declined approval reports `failed` with
`APPROVAL_DENIED`). Nothing about the gate is weaker: the same lease checks, the same audit-first Authorize, no
fallback; the request id is now the request's own (bounded) id.

## 2. Service-made Job Objects (`crates/orcel-authority/src/dispatch_jobs.rs`, `win/jobs.rs`)

Decisions:

- **One job per dispatch, not per lease.** A dispatch's processes end with its outcome; one dispatch cannot add
  processes to another's job; a name is good for exactly one launch. A lease holds at most 16 jobs, the
  service 128; a job whose processes all exited is closed 60 s after it was made.
- **Name:** `Global\orcel-fc-<32 random hex>` for the installed service (it holds `SeCreateGlobalPrivilege`),
  `Local\orcel-fc-...` in console mode (a standard user cannot create `Global\` objects). `CreateJobObjectW`
  with `ERROR_ALREADY_EXISTS` is refused.
- **DACL (protected, exactly two entries):** the service SID `JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY`; the
  calling user's SID `JOB_OBJECT_ASSIGN_PROCESS` only. The owner is the service (its token's default owner), so
  the user has no implicit `READ_CONTROL` or `WRITE_DAC`. The service keeps the creating handle (every right).
- **Limits:** `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, at most 64 active processes; never
  `BREAKAWAY_OK` or `SILENT_BREAKAWAY_OK`, so `CREATE_BREAKAWAY_FROM_JOB` fails inside the job.
- **Ending:** revoke, Stop, session lock, sign-out, disconnect, expiry, an epoch move (every older lease), re-
  enrollment and reset end the lease's jobs with `TerminateJobObject` and close the handle, before the answer
  leaves (or within the one-second tick for expiry). A job that cannot be made refuses Authorize before any
  allow record; a job made before an allow record that then fails to write is terminated.
- **In memory only:** a restarted service holds no handle; kill-on-close has ended what ran in its jobs (orceld
  closes its own handle before it resumes the worker).
- The service holds jobs in a `BTreeMap`: std's `HashMap` seeds itself through `bcryptprimitives.dll`, which is
  not a KnownDLL, and `install_script::the_authority_image_resolves_its_imports_from_system32_only` refuses it.

`Status` reports `job_objects` (namespace, held, per-dispatch, limits, client access).

## 3. `orceld fc-worker` (`crates/orceld/src/fc_worker.rs`)

- **Launch:** open the job by name with `JOB_OBJECT_ASSIGN_PROCESS` only (gone: `LEASE_INVALID`, the lease
  ended after Authorize); with the installed service, check that this session cannot open it with
  `JOB_OBJECT_TERMINATE` (else it is not the service's job: `AUTHORITY_UNAVAILABLE`); `CreateProcessW` of
  orceld's own image as `orceld fc-worker`, suspended, `CREATE_NO_WINDOW`, inheritance limited by
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to its stdin, stdout and a `NUL` stderr; `AssignProcessToJobObject`; close
  the job handle; `ResumeThread`. A worker that runs past 60 s is ended.
- **IPC:** one JSON request on stdin, one JSON reply on stdout (anonymous pipes); no listener, no named pipe, no
  network. A per-launch 256-bit random token in the request must come back in the reply.
- **Worker:** refuses to act unless it is in a Job Object (`IsProcessInJob`); checks each path lexically against
  the roots, then resolves the path (or its parent for a new entry) and the roots (`canonicalize`, so
  junctions and links) and acts only inside; refuses to write over a link or junction. Operations: `stat`,
  `list` (at most 1000 entries), `read_text` (at most 256 KiB, UTF-8), `write_text` (at most 256 KiB,
  `create_new` or replace), `mkdir`.
- Residual: a same-user process can swap a path component between the worker's check and its open (TOCTOU);
  the effect stays a same-user effect and is recorded by the authorization's paths.

## 4. Protocol changes (compatible)

- `AuthorizeClaims.paths` (optional; at most 8 absolute drive paths, no `\\?\`, UNC, stream colon, dot or
  trailing-dot/space components). A filesystem dispatch must name one; every named path must lie in the
  lease's roots.
- `Authorize` returns `job_name` (a string for filesystem and shell/process, `null` otherwise).
- New request `Outcome` (op `outcome`).
- No new `FailureCode`.

## 5. Threat model additions (same-user agent with Full Control)

Test names: `core_tests` in `crates/orcel-authority/src/`, `dispatch_jobs` and `console_harness` in
`crates/orcel-authority/tests/`, `full_control_dispatch_tests` and `fc_worker_tests` in `crates/orceld/src/`.
"UNVERIFIED (founder run)" means only the installed service can show it.

| Attack | Claim | Evidence |
| --- | --- | --- |
| Run a Full Control file, process or git operation without the service | Refused: these families need the service; nothing falls back to the user-readable store | `full_control_dispatch_tests::fc_dispatch_without_a_service_only_desktop_keeps_the_deprecated_store`, `fc_dispatch_an_unreachable_service_refuses_and_never_uses_the_store` |
| Use a lease beyond its executor, client or roots | Refused in orceld and again by the service | `full_control_dispatch_tests::fc_dispatch_a_wrong_family_or_scope_is_refused_before_authorize`; `core_tests::wp112_filesystem_dispatches_name_paths_inside_the_roots` |
| Escape the roots lexically (`..`, streams, trailing dots, UNC, `\\?\`) | Refused by the dispatcher, the service and the worker | `core_tests::wp112_job_names_and_dispatch_paths_are_checked_lexically`, `core_tests::wp112_filesystem_dispatches_name_paths_inside_the_roots` |
| Escape the roots through a junction or link | The worker resolves path and roots and refuses; never writes over a link | `fc_worker_tests::windows::fc_worker_resolves_links_and_stays_inside_the_roots`. Residual: TOCTOU swap (section 3) |
| Make the audit name something other than what ran | The digest binds family, target, arguments, paths and time; the record names the paths and the job | `full_control_dispatch_tests::fc_dispatch_the_digest_binds_family_target_arguments_and_paths`, `core_tests::wp112_authorize_makes_a_job_for_filesystem_and_shell_and_none_for_desktop` |
| Run a job-family operation outside a job | No job name, nothing runs; the worker refuses outside a job | `full_control_dispatch_tests::fc_dispatch_a_job_family_needs_its_service_made_job`, `fc_worker_tests::fc_worker_acts_only_inside_a_job_and_echoes_the_token`, `core_tests::wp112_a_job_that_cannot_be_made_refuses_before_any_allow_record` |
| Terminate, query, re-limit or re-ACL the service's job from the session | The DACL gives the user assign-process only | `dispatch_jobs::wp112_the_job_dacl_gives_the_caller_assign_process_only` (the test process is the owner, so it shows the ACEs and refusals except the owner's implicit rights). On a `Global\` job owned by `NT SERVICE\OrcelAuthority`: UNVERIFIED (founder run) |
| Hand orceld a job the session made | With the installed service, orceld refuses a job it could terminate; names come only from the verified pipe; `Global\` needs `SeCreateGlobalPrivilege` | `fc_worker_tests::windows::fc_worker_refuses_a_job_this_session_could_terminate`; the `Global\` privilege: UNVERIFIED (founder run) |
| Break away from the job | Refused: no breakaway limit | `dispatch_jobs::wp112_the_job_kills_on_close_and_allows_no_breakaway` (`CREATE_BREAKAWAY_FROM_JOB` fails with access denied inside the job) |
| Keep a worker running after revoke, Stop, lock or expiry | The service ends the lease's jobs; terminate kills within 1 s; kill-on-close covers a service exit | `core_tests::wp112_revoke_stop_lock_and_expiry_terminate_the_dispatch_jobs`, `dispatch_jobs::wp112_the_service_terminates_a_dispatch_job_within_a_second`, `dispatch_jobs::wp112_the_job_kills_on_close_and_allows_no_breakaway`. Stop through the installed service killing an in-flight worker: UNVERIFIED (founder run) |
| Launch after a revoke that landed between Authorize and the launch | The job is gone: `LEASE_INVALID`, nothing runs, the outcome is recorded | `fc_worker_tests::windows::fc_worker_a_job_gone_before_the_launch_is_lease_invalid`, `full_control_dispatch_tests::fc_dispatch_a_revoke_between_authorize_and_run_refuses_and_is_recorded`, `core_tests::wp112_outcomes_are_orcelds_once_per_authorization_and_end_the_job` (late outcome) |
| Forge or replay an outcome | orceld role only, same user and logon session, once per authorization | `core_tests::wp112_outcomes_are_orcelds_once_per_authorization_and_end_the_job`, `console_harness::wp112_dispatch_jobs_need_a_live_lease_and_outcomes_are_orcelds` |
| Flood the service with jobs | 16 per lease, 128 in all; idle jobs closed after 60 s | `core_tests::wp112_idle_jobs_are_closed_and_a_lease_holds_a_bounded_number` |
| Reply for another launch or connect to the worker | Anonymous pipes only; the reply must echo the per-launch token | `fc_worker_tests::fc_worker_acts_only_inside_a_job_and_echoes_the_token` |
| Desktop input without an outcome record | Every desktop authorization's outcome is reported when the request returns | `full_control_dispatch_tests::fc_dispatch_desktop_requests_report_each_authorization_once`. Against the installed service: UNVERIFIED (founder run) |
| The whole filesystem path end to end | Authorize, job, suspended worker, assign, resume, operation in the roots, outcome | `fc_worker_tests::windows::fc_worker_runs_filesystem_operations_inside_the_service_job_end_to_end` (a stand-in service makes real `Local\` jobs). Through the installed service and a real grant: UNVERIFIED (founder run) |

## 6. Not done in this slice (recorded)

- **The deprecated store is not retired.** `authority.key` and `full_control_store` still serve desktop input
  where no service is installed (unchanged), and `orcel full-control revoke` still clears them. Retiring them
  removes desktop input on PCs without the service; that is safe only after the founder's first real desktop
  grant through the installed service (slice 2, section 7, step 5). Step: delete issuance in
  `orcel-lifecycle/src/full_control.rs`, make `deprecated_desktop_check` refuse, then remove the store.
- The desktop input host (`apps/orcel-computer-host`, spawned by `HostSession::spawn`) is not yet launched into
  a service-made job; desktop input still runs in orceld's host session (listed in the service's `deferred`).
- No request capability reaches `run_in_worker` yet: the filesystem, process and git capabilities under a Full
  User lease (SG-000097, SG-000096) need their policy shapes, MCP tools and per-action approvals.

## 7. Next steps

WP1-12 (as these documents name it):

1. Process and git operations in `fc-worker` (the `Process` and `Git` families; programs resolved by the worker,
   argv only, the repository path in the roots) and the SG-000097/SG-000096 capabilities that call
   `run_in_worker`, with their approvals.
2. The desktop input host started into a service-made job (suspended, assigned, resumed), so Stop kills it too.
3. Retire `authority.key` and the deprecated store (section 6) after the founder's first real desktop grant.
4. The real MCP client principal at the desktop gate (slice 2 residual).
5. Founder runs (UNVERIFIED rows above): a `Global\` job from the installed service opened from the user
   session; Stop through the installed service killing an in-flight `fc-worker`; a desktop action's outcome in
   the service's audit.

Then the indicator and its heartbeat (Authorize refusing `INDICATOR_UNAVAILABLE`) and standing approvals
(spec 4.15; WP1-14).

## Tests

At head (Windows, unelevated):

- `cargo test -p orcel-authority`: 73 unit tests (7 new `core_tests::wp112_*`), 10 `console_harness` (1 new),
  4 `dispatch_jobs` (new; real Job Objects in the test process), 11 `install_script`.
- `cargo test -p orceld full_control_dispatch_ fc_worker_ sg132`: 8 dispatcher tests with a fake service, 5
  `fc_worker` tests (4 Windows-only with real jobs and the built `orceld.exe`), the slice 2 `authority_link`
  tests.
- Some unrelated orceld tests fail on this PC because of its AppData permissions (`InsecureAcl`, before this
  slice); CI runs them.
