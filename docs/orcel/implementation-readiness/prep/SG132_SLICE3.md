# SG-000132 slice 3: the Full Control dispatcher, service-made Job Objects and `orceld fc-worker`

Status: implemented and tested on branch `authority/wp1-12-dispatcher`; not installed. Revision 2 answers the
independent security review of `291e045e` (one blocker, three lows, one documentation item; listed at the end).
Nothing in this slice was installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered,
and no system, registry, firewall or ACL setting changed. Slice 1 is [SG132_SLICE1.md](SG132_SLICE1.md), slice 2
[SG132_SLICE2.md](SG132_SLICE2.md), installing [SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec:
`.specgrain/specs/SG-000132.json` (in scope: `crates/orceld/src/full_control_dispatch.rs` as the only path for
lease-gated executors; service-made Job Objects; `orceld fc-worker`).

Naming: the work packet table of [UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) (section 8.2) is
authoritative: the dispatcher, the service-owned Job Objects and `fc-worker` are WP1-10; the indicator is WP1-12,
standing approvals WP1-14, and the executors (SG-000096 shells, SG-000097 filesystem, processes and apps) WP1-15.
Earlier revisions of these documents, the code comments and the test names (`wp112_`) called this work WP1-12;
slice 4 relabelled them to WP1-10 (`wp110_`). The branch name above is historical. Nothing here is the indicator
or standing approvals.

**What this slice makes possible:** every lease-gated Full Control executor goes through one dispatcher in
orceld. The service's `Authorize` now also checks paths against the lease's roots and, for filesystem and
shell/process work, makes a fresh unnamed Job Object for that one dispatch before it writes its allow record and
hands orceld an assign-only handle to it. The filesystem family runs end to end: Authorize, `orceld fc-worker`
started suspended, assigned to the job, the service asked whether the authorization still stands, resumed, the
operation inside the roots, the outcome reported, and the job terminated by the service.

## 1. The dispatcher (`crates/orceld/src/full_control_dispatch.rs`)

One path for desktop input, filesystem, process and git:

1. **Family and digest.** `Family::{DesktopInput, Filesystem, Process, Git}`. Desktop input needs the
   `desktop_input` executor; filesystem `filesystem`; process and git run programs, so they need
   `shell_process` (granted only together with `shells`); filesystem and git name their paths, which must lie in
   the lease's roots. The action digest is length-prefixed SHA-256 over the family, workspace, capability,
   operation, target, arguments, the paths and the time (`orcel-full-control-action/1`); desktop input keeps
   slice 2's `orcel-desktop-lease-action/2`. The worker operation that runs is parsed from the request's own
   arguments (`run_in_worker`), so the digest covers exactly what runs; arguments that are not one operation, or
   a request `operation` that names another one, are refused before Authorize.
2. **Lease.** Only active leases of this user and logon session that the verified service listed and whose ECDSA
   signature verified with the service's key. A lease that does not admit the executor, names another client,
   or whose roots do not hold every path is not used (`LEASE_REQUIRED`, `CAPABILITY_DENIED` or `PATH_ESCAPE`).
3. **Authorize.** The service checks lease, epoch, binding, executor, client and (new) the paths against the
   roots again, makes the dispatch's job, and writes the allow record naming it (`job_id`) before it answers.
   orceld refuses an answer without an authorization id, for another lease, or whose job is missing or malformed
   for a job family, or present for desktop input (`AUTHORITY_UNAVAILABLE`); a job handle that came with a
   refused answer is closed. (Slice 5 changed this: orceld leaves such a handle alone and the service, which
   never received its acknowledgement, closes it in orceld; [SG132_SLICE5.md](SG132_SLICE5.md) section 1.3.)
4. **Run.** Desktop input runs in orceld as before (the computer host; SG-000095's per-action approval
   unchanged). Filesystem operations run only in `orceld fc-worker` in the job, which runs only after
   `DispatchActive` confirmed the authorization (section 3). Process and git use the same launch and are the
   next step (section 7).
5. **Outcome.** `Outcome { authorization_id, outcome, code }` (orceld only, once per authorization, same user
   and logon session); the service terminates the job first, then records the outcome. A failure to report is
   written to orceld's error output (the action already ran); the job still ends with the lease or by age.

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

- **Unnamed jobs, handed over as a handle.** Revision 1 named jobs `Global\orcel-fc-<random>` and relied on a
  standard user being unable to create `Global\` objects. The review showed that is false on this PC (a standard
  medium-integrity user created one), and that any same-user process could hold a named job open past its end so
  a revoked job could be reused. Revision 2 creates every job without a name: no process can open, pre-create,
  squat or keep one by name.
- **Handle duplication.** For an `Authorize` request the connection opens the pipe client's process with
  `PROCESS_DUP_HANDLE` while impersonating it (the service account has no rights on user processes), and checks
  that its creation time is the one the service observed for that PID (no recycled PID). The service creates the
  job, keeps the creating handle (every right) and `DuplicateHandle`s one handle into that orceld process with
  exactly `JOB_OBJECT_ASSIGN_PROCESS`, not inheritable; the answer carries its value (`job_handle`) and the job's
  id (`job_id`, for the audit). If the allow record cannot be written, the service closes that handle in orceld
  again (the answer was never sent, so orceld never used the value) and terminates the job.
- **One job per dispatch, not per lease.** A dispatch's processes end with its outcome; one dispatch cannot add
  processes to another's job. A lease holds at most 16 jobs, the service 128.
- **Limits:** `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, at most 64 active processes; never
  `BREAKAWAY_OK` or `SILENT_BREAKAWAY_OK`, so `CREATE_BREAKAWAY_FROM_JOB` fails inside the job.
- **Ending:** revoke, Stop, session lock, sign-out, disconnect, expiry, an epoch move (every older lease), re-
  enrollment and reset end the lease's jobs with `TerminateJobObject` and close the service's handle, before the
  answer leaves (or within the one-second tick for expiry). A job whose processes all exited is closed 60 s after
  it was made, and every job is terminated 10 minutes after it was made whatever it holds (worker operations are
  bounded at 60 s; long-running work is SG-000134). A job that cannot be made refuses Authorize before any allow
  record.
- **`DispatchActive`:** orceld asks it after assigning the suspended worker and before resuming it; it answers
  only for orceld, for an open authorization of the same user and logon session whose lease is active and whose
  job the service still holds (`LEASE_INVALID` otherwise).
- **In memory only:** a restarted service holds no handle; once orceld closed its own handle (right after
  assigning) kill-on-close has ended what ran.
- **Open dispatches:** the service remembers at most 256 authorizations awaiting their outcome; evicting the
  oldest also terminates its job (it can no longer be confirmed or reported).
- **Residual, lost reply:** if an `Authorize` answer never reaches orceld (the pipe breaks after the service
  wrote it, or orceld's client times out waiting for it), the duplicated assign-only handle stays in orceld's handle table until orceld exits. Its job is
  terminated by the service (age limit, lease end); nothing can be resumed in it because `DispatchActive`
  refuses an authorization whose job the service no longer holds. Cost: one leaked handle per lost reply. Not
  fixed in this slice (an acknowledgement with the handle value, and terminating unacknowledged jobs after a
  short timeout, is recorded as a next step). **Closed in slice 5** ([SG132_SLICE5.md](SG132_SLICE5.md)
  section 1.3): orceld acknowledges each handle (`JobAck`) before using it, a job not confirmed within 15 s is
  ended, and the service closes an unacknowledged handle in orceld itself; what remains (an acknowledgement
  whose reply is also lost) is slice 5 residual 1.
- **Residual, service restart:** a same-user process that copied orceld's assign-only handle (it holds
  `PROCESS_DUP_HANDLE` on orceld) keeps the job object alive. If the service restarts while processes run in
  that job, the restarted service no longer knows the job, kill-on-close does not fire while that copy exists,
  and the processes keep running past the 10-minute limit. No new dispatch can use the job: jobs are per
  dispatch and unnamed, and the restarted service makes new ones. Leases themselves survive a service restart;
  a restart is not an emergency stop. The processes are same-user processes like any other the agent could
  start (spec C-27).
- **Not done:** orceld does not call `IsProcessInJob(worker, job)` after assigning: that needs
  `JOB_OBJECT_QUERY`, which its handle deliberately lacks. A successful `AssignProcessToJobObject` on the
  suspended worker is the evidence.
- The service holds jobs in a `BTreeMap`: std's `HashMap` seeds itself through `bcryptprimitives.dll`, which is
  not a KnownDLL, and `install_script::the_authority_image_resolves_its_imports_from_system32_only` refuses it.

`Status` reports `job_objects` (`named: false`, held, per-dispatch, limits, client access).

## 3. `orceld fc-worker` (`crates/orceld/src/fc_worker.rs`)

- **Launch:** `CreateProcessW` of orceld's own image as `orceld fc-worker`, suspended, `CREATE_NO_WINDOW`,
  inheritance limited by `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to its stdin, stdout and a `NUL` stderr;
  `AssignProcessToJobObject` with the duplicated handle; close that handle; `DispatchActive` (refused: terminate
  the suspended worker, which never ran); `ResumeThread`. A revoke, Stop or expiry after `DispatchActive` ends
  the job and the worker with it. A worker that runs past 60 s is ended.
- **IPC:** one JSON request on stdin, one JSON reply on stdout (anonymous pipes); no listener, no named pipe, no
  network. A per-launch 256-bit random token in the request must come back in the reply.
- **Worker:** refuses to act unless `IsProcessInJob(current, NULL)` says it is in some job. That is a sanity
  check, not a boundary: the boundary is orceld assigning it to the service's job before it ever runs. It checks
  each path lexically against the roots, then resolves the path (or its parent for a new entry) and the roots
  (`canonicalize`, so junctions and links) and acts only inside; it refuses to write over a link or junction and
  to read, write or describe a file that has more than one name (a hard link inside the roots can name a file
  outside them; the link count is read from the opened handle, before truncation for a write). Operations: `stat`, `list` (at most 1000
  entries), `read_text` (at most 256 KiB, UTF-8), `write_text` (at most 256 KiB, `create_new` or replace),
  `mkdir`.
- Residual: a same-user process can swap a path component between the worker's check and its open (TOCTOU),
  or create a hard link after the link count was read; the effect stays a same-user effect and the
  authorization records the paths.

## 4. Protocol changes (compatible)

- `AuthorizeClaims.paths` (optional; at most 8 absolute drive paths, no `\\?\`, UNC, stream colon, dot or
  trailing-dot/space components). A filesystem dispatch must name one; every named path must lie in the
  lease's roots.
- `Authorize` returns `job_id` and `job_handle` (set for filesystem and shell/process, `null` otherwise).
- New requests `DispatchActive` (op `dispatch_active`) and `Outcome` (op `outcome`), orceld only.
- No new `FailureCode`.

## 5. Threat model additions (same-user agent with Full Control)

Test names: `core_tests` in `crates/orcel-authority/src/`, `dispatch_jobs` and `console_harness` in
`crates/orcel-authority/tests/`, `full_control_dispatch_tests` and `fc_worker_tests` in `crates/orceld/src/`.
"UNVERIFIED (founder run)" means only the installed service can show it.

| Attack | Claim | Evidence |
| --- | --- | --- |
| Run a Full Control file, process or git operation without the service | Refused: these families need the service; nothing falls back to the user-readable store | `full_control_dispatch_tests::fc_dispatch_without_a_service_only_desktop_keeps_the_deprecated_store`, `fc_dispatch_an_unreachable_service_refuses_and_never_uses_the_store` |
| Use a lease beyond its executor, client or roots | Refused in orceld and again by the service | `full_control_dispatch_tests::fc_dispatch_a_wrong_family_or_scope_is_refused_before_authorize`; `core_tests::wp110_filesystem_dispatches_name_paths_inside_the_roots` |
| Escape the roots lexically (`..`, streams, trailing dots, UNC, `\\?\`) | Refused by the dispatcher, the service and the worker | `core_tests::wp110_job_ids_and_dispatch_paths_are_checked_lexically`, `core_tests::wp110_filesystem_dispatches_name_paths_inside_the_roots` |
| Escape the roots through a junction, link or hard link | The worker resolves path and roots, never writes over a link, never reads, writes or describes a file with more than one name | `fc_worker_tests::windows::fc_worker_resolves_links_and_stays_inside_the_roots`, `fc_worker_tests::windows::fc_worker_never_uses_a_hard_link`. Residual: TOCTOU (section 3) |
| Make the audit name something other than what ran | The operation is the request's arguments and the request's `operation` must name it; the digest binds family, target, arguments, paths and time; the record names the paths and the job | `full_control_dispatch_tests::fc_dispatch_the_operation_is_the_request_arguments_or_nothing`, `fc_dispatch_the_digest_binds_family_target_arguments_and_paths`, `core_tests::wp110_authorize_makes_a_job_for_filesystem_and_shell_and_none_for_desktop` |
| Run a job-family operation outside a job | No job, nothing runs; the worker is assigned before it ever runs | `full_control_dispatch_tests::fc_dispatch_a_job_family_needs_its_service_made_job`, `fc_worker_tests::windows::fc_worker_is_in_the_job_before_it_runs_and_a_refusal_ends_it`, `core_tests::wp110_a_job_that_cannot_be_made_refuses_before_any_allow_record`; the worker's own check: `fc_worker_tests::fc_worker_acts_only_inside_a_job_and_echoes_the_token` (sanity check, not a boundary) |
| Pre-create, squat or reopen a job by name (review blocker) | Jobs have no name; orceld uses only the handle the verified service duplicated into it | Structural (no name anywhere: `win::jobs::create_job` passes none; the dispatcher accepts only `job_handle`); `dispatch_jobs::wp110_the_duplicated_handle_carries_assign_process_only` |
| Terminate, query or re-limit the job from the session | orceld's handle carries assign-process only; nothing else exists outside the service | `dispatch_jobs::wp110_the_duplicated_handle_carries_assign_process_only` (terminate and query refused through it, not inheritable). From `NT SERVICE\OrcelAuthority` into a real orceld: UNVERIFIED (founder run) |
| Get a job made for another process or a recycled PID | The handle goes only to the process instance the service observed (PID and creation time), opened while impersonating it | `dispatch_jobs::wp110_a_job_is_made_only_for_the_observed_caller_instance`, `core_tests::wp110_authorize_makes_a_job_for_filesystem_and_shell_and_none_for_desktop` |
| Break away from the job | Refused: no breakaway limit | `dispatch_jobs::wp110_the_job_kills_on_close_and_allows_no_breakaway` (`CREATE_BREAKAWAY_FROM_JOB` fails with access denied inside the job) |
| Keep a worker running after revoke, Stop, lock or expiry | The service ends the lease's jobs; terminate kills within 1 s; kill-on-close covers a service exit | `core_tests::wp110_revoke_stop_lock_and_expiry_terminate_the_dispatch_jobs`, `dispatch_jobs::wp110_the_service_terminates_a_dispatch_job_within_a_second`, `dispatch_jobs::wp110_the_job_kills_on_close_and_allows_no_breakaway`. Stop through the installed service killing an in-flight worker: UNVERIFIED (founder run) |
| Launch after a revoke that landed between Authorize and the resume (review blocker) | `DispatchActive` refuses; the suspended worker is terminated without having run; the outcome is recorded | `fc_worker_tests::windows::fc_worker_a_revoke_before_the_resume_means_the_worker_never_runs`, `core_tests::wp110_dispatch_active_refuses_once_the_lease_or_job_ended`, `full_control_dispatch_tests::fc_dispatch_a_revoke_between_authorize_and_run_refuses_and_is_recorded` |
| Forge or replay an outcome or a DispatchActive | orceld role only, same user and logon session, once per authorization | `core_tests::wp110_outcomes_are_orcelds_once_per_authorization_and_end_the_job`, `core_tests::wp110_dispatch_active_refuses_once_the_lease_or_job_ended`, `console_harness::wp110_dispatch_jobs_need_a_live_lease_and_outcomes_are_orcelds` |
| Fill or pin jobs (review low 4) | 16 per lease, 128 in all; empty jobs closed after 60 s; every job terminated at 10 minutes, busy or not; an evicted open dispatch ends its job | `core_tests::wp110_idle_jobs_are_closed_and_a_lease_holds_a_bounded_number`, `core_tests::wp110_an_evicted_open_dispatch_ends_its_job`. Residual: a same-user process can duplicate orceld's assign-only handle out of orceld (it holds `PROCESS_DUP_HANDLE` on orceld) and put its own processes into a job, where the service terminates them; until then it can hold that dispatch's slot (denial of service only). Across a service restart such a copy keeps the job and its processes alive beyond 10 minutes (section 2) |
| Reply for another launch or connect to the worker | Anonymous pipes only; the reply must echo the per-launch token | `fc_worker_tests::fc_worker_acts_only_inside_a_job_and_echoes_the_token` |
| Desktop input without an outcome record | Every desktop authorization's outcome is reported when the request returns | `full_control_dispatch_tests::fc_dispatch_desktop_requests_report_each_authorization_once`. Against the installed service: UNVERIFIED (founder run) |
| The whole filesystem path end to end | Authorize, unnamed job, assign-only handle, suspended worker, assign, DispatchActive, resume, operation in the roots, outcome | `fc_worker_tests::windows::fc_worker_runs_filesystem_operations_inside_the_service_job_end_to_end` (a stand-in service makes real jobs and duplicates real handles into the test process). Through the installed service and a real grant: UNVERIFIED (founder run) |

**Escape residuals before the process and git families ship (review item 5).** A Job Object holds the processes
Orcel starts and their children, not effects made through other processes. A worker running as the user can ask
an out-of-job broker to start a process for it: COM servers (out-of-process activation), WMI
`Win32_Process.Create`, Task Scheduler (`schtasks`, the Task Scheduler COM API), the shell (`explorer.exe`,
`ShellExecute` through an existing shell window or DDE), services it may control, and any other process that
launches programs on request. Those processes are not in the job and survive Stop (spec C-27). The filesystem
operations in this slice start no program. Before the process and git families ship, their workers must not be
able to reach these brokers (argv-only launches of resolved programs, no shell, no COM activation in the worker),
and the grant prompt's C-27 text already says effects made through the OS outside Orcel's process trees can
persist.

## 6. Not done in this slice (recorded)

- **The deprecated store is not retired.** `authority.key` and `full_control_store` still serve desktop input
  where no service is installed (unchanged), and `orcel full-control revoke` still clears them. Retiring them
  removes desktop input on PCs without the service; that is safe only after the founder's first real desktop
  grant through the installed service (slice 2, section 7, step 5). Step: delete issuance in
  `orcel-lifecycle/src/full_control.rs`, make `deprecated_desktop_check` refuse, then remove the store.
- The desktop input host (`apps/orcel-computer-host`, spawned by `HostSession::spawn`) is not yet launched into
  a service-made job; desktop input still runs in orceld's host session (listed in the service's `deferred`).
  **Done in slice 5** ([SG132_SLICE5.md](SG132_SLICE5.md)): a lease-lifetime job per desktop Full User lease;
  desktop input admitted under a lease runs only in a host inside it.
- No request capability reaches `run_in_worker` yet: the filesystem, process and git capabilities under a Full
  User lease (SG-000097, SG-000096) need their policy shapes, MCP tools and per-action approvals.

## 7. Next steps

WP1-10 and WP1-15 (the step numbers below are referred to by slice 4):

1. Process and git operations in `fc-worker` (the `Process` and `Git` families; programs resolved by the worker,
   argv only, the repository path in the roots, the broker residuals of section 5 closed) and the
   SG-000097/SG-000096 capabilities that call `run_in_worker`, with their approvals.
2. The desktop input host started into a service-made job (suspended, assigned, confirmed, resumed), so Stop
   kills it too. Done in slice 5 ([SG132_SLICE5.md](SG132_SLICE5.md)).
3. Retire `authority.key` and the deprecated store (section 6) after the founder's first real desktop grant.
4. The real MCP client principal at the desktop gate (slice 2 residual). Done in slice 6 ([SG132_SLICE6.md](SG132_SLICE6.md)).
5. An acknowledgement of each job handle by orceld, with unacknowledged jobs terminated (and their handles
   closed in orceld) after a short timeout, for the lost-reply residual of section 2. The acknowledgement names
   the `authorization_id` and the handle value, is accepted only from the same user, logon session and orceld
   instance (PID and creation time) the handle went to, and the timeout fires only before that authorization's
   `DispatchActive`. Done in slice 5 ([SG132_SLICE5.md](SG132_SLICE5.md) section 1.3).
6. Founder runs (UNVERIFIED rows above): a handle duplicated by the installed service into a real orceld after
   impersonating it; Stop through the installed service killing an in-flight `fc-worker`; a desktop action's
   outcome in the service's audit.

Then the indicator and its heartbeat (WP1-12; Authorize refusing `INDICATOR_UNAVAILABLE`) and standing approvals
(spec 4.15; WP1-14).

## Review of `291e045e` and the answers

| Finding | Answer |
| --- | --- |
| Blocker: orceld trusted a named job it could assign but not terminate; a standard user can create `Global\` objects; a held-open named job outlives revoke; names can be squatted | Unnamed jobs; one assign-only handle duplicated into the observed orceld instance; `DispatchActive` between assign and resume; the false `Global\` statements removed (`win/jobs.rs`, `dispatch_jobs.rs`, `runtime.rs`, this document) |
| Low 2: the digest covered the request's arguments, not the operation run | The operation is parsed from the arguments; anything else is refused before Authorize |
| Low 3: a hard link inside the roots could name a file outside | Writes refuse a file with more than one name (checked on the opened handle before truncation); TOCTOU residual documented |
| Low 4: the assign right let the user stuff jobs and pin the reaper | No named job to open; jobs terminated at 10 minutes regardless; the remaining handle-theft denial of service documented |
| Doc: escape residuals and `IsProcessInJob(NULL)` | Section 5 lists COM, WMI, Task Scheduler and shell launches; section 3 calls the worker's job check a sanity check |

Re-review of `073b7fee` (pass, with lows):

| Finding | Answer |
| --- | --- |
| `read_text` and `stat` followed hard links | Both refuse a file with more than one name, as writes do |
| An evicted open dispatch kept its job | Eviction terminates the evicted dispatch's job (`core_tests::wp110_an_evicted_open_dispatch_ends_its_job`) |
| The request's `operation` could differ from the operation run | Refused (`full_control_dispatch_tests::fc_dispatch_the_operation_is_the_request_arguments_or_nothing`) |
| Optional: `IsProcessInJob(worker, job)` after assigning | Not done: it needs `JOB_OBJECT_QUERY`, which orceld's handle deliberately lacks (section 2) |
| Residuals: a lost Authorize reply leaks the handle in orceld; a same-user copy keeps a job alive across a service restart | Documented in section 2 and the threat model; the acknowledgement is next step 5 (done in slice 5; the restart residual stands) |

## Tests

At head (Windows, unelevated):

- `cargo test -p orcel-authority`: 75 unit tests (9 `core_tests::wp110_*`), 10 `console_harness` (1 for this
  slice), 5 `dispatch_jobs` (real unnamed jobs and duplicated handles in the test process), 11 `install_script`.
- `cargo test -p orceld full_control_dispatch_ fc_worker_ sg132`: 9 dispatcher tests with a fake service, 6
  `fc_worker` tests (5 Windows-only with real jobs and the built `orceld.exe`), the slice 2 `authority_link`
  tests.
- Some unrelated orceld tests fail on this PC because of its AppData permissions (`InsecureAcl`, before this
  slice); CI runs them.
