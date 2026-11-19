# SG-000132 slice 5: the desktop input host in a service-made Job Object, and job handle acknowledgement

Status: implemented and tested on branch `authority/desktop-host-job`; not installed. Nothing in this slice was
installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry,
firewall or ACL setting changed. No test drives real input: the tests check Job Objects, handles and processes,
never the desktop. Earlier slices: [SG132_SLICE1.md](SG132_SLICE1.md), [SG132_SLICE2.md](SG132_SLICE2.md),
[SG132_SLICE3.md](SG132_SLICE3.md), [SG132_SLICE4.md](SG132_SLICE4.md); installing:
[SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Spec: `.specgrain/specs/SG-000132.json` (service-made Job
Objects; the dispatcher as the only path for lease-gated executors).

Naming: [UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) section 8.2 is authoritative. Everything here is
WP1-10 (the authority service, the dispatcher, the service-owned Job Objects); test names keep the `wp110_` prefix
on the service side and `fc_dispatch_`/`fc_worker_` in orceld.

**What this slice makes possible:** a desktop input action that the authority service admitted under a lease runs
only in a computer host (`apps/orcel-computer-host`) inside that lease's service-made Job Object, so revoke, Stop,
session lock, sign-out, disconnect and expiry end the host, and every per-request worker it started, through the
service. And every job handle the service duplicates into orceld is acknowledged before it is used; a handle whose
`Authorize` reply was lost is closed in orceld by the service, which closes slice 3's lost-reply residual.

## 1. Design decisions

### 1.1 The desktop host's job is per lease, not per dispatch

The computer host is long-lived: one process serves many requests, keeps the window bindings that later actions
name, and starts a short-lived worker (`--worker`) per request. A job per dispatch would mean a new host per action
and lost bindings. So:

- **One job per desktop Full User lease** (`JobProfile::DesktopHost`). The service makes it on orceld's request
  (`DesktopHostJob { lease_id }`), only for an active lease of the caller (user and logon session) whose scope is
  desktop Full User and admits `desktop_input`, writes a `desktop_host_job` record before answering, and duplicates
  an assign-only handle into the observed orceld instance (PID and creation time, opened while impersonating it,
  exactly as for `Authorize`). Asking again for the same lease from the same orceld instance ends that instance's
  earlier job first; another orceld instance under the same lease gets its own job and never ends this one's host.
  A job whose orceld exited is closed by the 60-second idle rule.
- **Lifetime: the lease.** The job is ended whenever its lease stops being active (revoke, Stop, lock, sign-out,
  disconnect, expiry, an epoch move, re-enrollment, reset): the same `sweep_jobs` path as dispatch jobs, before the
  answer leaves or within the one-second tick for expiry. Dispatch jobs' 10-minute age limit does not apply; the
  60-second idle rule (a job whose processes all exited is closed) does.
- **orceld's side** (`full_control_dispatch::ensure_lease_host`, `desktop_host_job.rs`): after the service admitted
  a desktop action under lease L (`desktop_gate` now returns L), and when the computer host is selected
  (`ORCEL_COMPUTER_HOST_BIN`), orceld keeps the running host only if it is in L's job and still running. Otherwise it
  asks `DesktopHostJob`, acknowledges the handle (`JobAck`), starts the host with `CreateProcessW` suspended (the
  same launch as `orceld fc-worker`: inheritance limited to its pipes and a `NUL` stderr; the host's scrubbed
  environment, `computer_host_environment`; orceld's console kept, as the standard library's start did), assigns
  it with the duplicated handle, closes that handle, asks `DispatchActive` with the job's authorization id, and
  resumes it only if that succeeds (terminating the suspended host otherwise). The adapter then negotiates with the
  new host and ends the old one (`ComputerHostAdapter::adopt_host`). A new lease therefore always gets a fresh host.
- **No fallback.** For the rest of a request admitted under L, `uia::computer_host` hands out only L's host; if it
  ended (the service ended L's job) the action refuses with `LEASE_INVALID` instead of starting a host outside the
  job. Any failure to get the job, acknowledge it, start, assign, confirm or negotiate refuses the desktop action
  (fail closed); the previous host and state stay as they were.
- **Observation is unchanged.** Safe-mode observation has no lease and uses whatever host runs. When the leased host
  ended with its lease, the next observation starts a plain host again (outside any job, as before this slice;
  Windows only, `ComputerHostAdapter::restart_host`). Previously a host that died stayed dead until orceld
  restarted; now ending it is routine.
- **Window bindings survive a host switch.** The host's window nonce is derived from the window's process and class
  (`windowNonce` in `apps/orcel-computer-host`), so the new host checks the adapter's bindings the same way. Host
  snapshot ids and any armed approval are dropped with the old host; a semantic action that named the old host's
  snapshot is refused as stale and needs a fresh observation.
- **Where no service is installed**, the deprecated store's desktop input keeps the plain host (slice 2 behaviour;
  it goes with the store, slice 3 section 6). On macOS and Linux nothing changes: there is no service.

### 1.2 The desktop host job's limits (desktop input must keep working)

The Full User model runs desktop input on the user's own desktop with the user's token (FD-UP-9). The host lists
windows of other processes, reads their UI Automation trees (window messages to them), brings a window to the
front, posts `WM_CLOSE`, captures windows and synthesizes input.

| Limit | Desktop host job | Dispatch job | Why |
| --- | --- | --- | --- |
| `KILL_ON_JOB_CLOSE`, `DIE_ON_UNHANDLED_EXCEPTION`, 64 active processes | yes | yes | the host plus one worker per request fit easily |
| `BREAKAWAY_OK`, `SILENT_BREAKAWAY_OK` | never | never | nothing the host or its workers start can leave |
| `UILIMIT_HANDLES` | **no** | yes | it refuses every USER handle of a process outside the job: the host could not see or act on any window it is meant to drive |
| `UILIMIT_GLOBALATOMS` | **no** | yes | UI Automation and OLE in the host are not verified to work with a private global atom table; nothing in the host needs DDE |
| `UILIMIT_DESKTOP`, `EXITWINDOWS`, `SYSTEMPARAMETERS`, `DISPLAYSETTINGS`, `READCLIPBOARD`, `WRITECLIPBOARD` | yes | yes | the host never makes or switches desktops, logs off, changes system parameters or display settings, or uses the clipboard |

No job restriction covers synthesized input; that is what the host is for. The test
`dispatch_jobs::wp110_the_desktop_host_job_keeps_desktop_input_working_and_allows_no_breakaway` reads the
restrictions back from the kernel and shows, read-only (window titles, no input), that a process in the desktop host
job still sees other processes' windows while one in a dispatch job sees none.

### 1.3 Job handle acknowledgement (slice 3 next step 5)

- **`JobAck { authorization_id, job_handle }`.** orceld sends it right after an answer that carried a handle
  (`Authorize` for filesystem, process and git; `DesktopHostJob`) and before it uses the handle. The service accepts
  it only from the orceld role, the user and logon session, and the orceld process instance (PID and creation time;
  an unreadable creation time never matches) the handle was duplicated into, only with the exact value it
  duplicated, and once.
- **`DispatchActive` needs the acknowledgement** for an authorization that holds a job, and from the same instance;
  its answer confirms the job.
- **Timeout:** a job that `DispatchActive` has not confirmed `JOB_ACK_TIMEOUT_MS` (15 s) after it was made is ended
  (the one-second tick and every request check). orceld acknowledges, starts its process suspended, assigns it and
  asks `DispatchActive` within milliseconds; the approval prompt comes before `Authorize`, so it never runs inside
  this window. The timeout never touches a confirmed job: a confirmed dispatch keeps running until its outcome, the
  lease's end or the 10-minute limit, a confirmed desktop host until the lease ends.
- **Who closes orceld's handle.** orceld uses and closes only a handle whose acknowledgement the service accepted
  (it closes it right after assigning). A handle whose acknowledgement failed, or that came with an answer orceld
  refused (malformed, another lease, unexpected for the family), is neither used nor closed by orceld. Whenever the
  service ends a job whose handle was never acknowledged (timeout, lease end, eviction, outcome) it withdraws it:
  `DuplicateHandle(..., DUPLICATE_CLOSE_SOURCE)` closes the value in orceld. Closing it in orceld as well, as slice
  3 did, could close a handle value orceld had meanwhile reused. A refused acknowledgement is reported as a failed
  outcome.
- **Only an orceld that acknowledges gets a job.** An orceld from before this slice closes its handle itself (after
  the assign, or when it refuses an answer), so if the service closed that value in it later it could close a
  handle orceld had reused for something else. So orceld declares that it acknowledges handles: `job_ack: true` on a
  job-family `Authorize` (filesystem, shell/process; absent on desktop and browser `Authorize`, which make no job,
  so those stay exactly as an older service accepts them). The service refuses a job-family `Authorize` without it
  (`INVALID_REQUEST`) before any job exists; `DesktopHostJob` is new, so every caller of it acknowledges. The
  service therefore never closes a value in an orceld that closes its own handles.
- **Older peers fail closed.** An older orceld at a newer service: job-family dispatches refused at `Authorize`
  (no job, no handle); desktop and browser `Authorize` unchanged; desktop input refused only where it needs the
  desktop host job, which an older orceld never asks for (it keeps its plain host, as before this slice). A newer
  orceld at an older service: `job_ack` on `Authorize`, `job_ack` the request and `desktop_host_job` are refused as
  unknown, so job-family dispatches and leased desktop input refuse and orceld uses nothing; browser `Authorize`
  works. No new `FailureCode`.
- **Upgrade order.** Install the service and orceld together (one installer, as the runbook does), or the service
  first. Neither order runs anything outside a job or closes a handle the service does not own; the order only
  decides which actions refuse until both are updated.

## 2. Protocol changes

- `Authorize` gains `job_ack` (optional, default false; orceld sends `true` for the executors that run in a job,
  and the service refuses a job-family `Authorize` without it).
- New requests `JobAck` (op `job_ack`: `authorization_id`, `job_handle`) and `DesktopHostJob` (op
  `desktop_host_job`: `lease_id`; the answer carries `authorization_id`, `lease_id`, `epoch`, `job_id`,
  `job_handle`), orceld only.
- `DispatchActive` also confirms a desktop host job by its authorization id; it refuses an unacknowledged job
  (`INVALID_REQUEST`) and another instance (`CAPABILITY_DENIED`).
- `Status.job_objects` gains `acknowledgement` (required, timeout, what it binds) and `desktop_host` (per lease,
  lease lifetime, held, restrictions). `deferred` no longer lists the desktop input host's job.
- `JobHost::create` takes a `JobProfile`; `win::jobs::create_job_for`, `DESKTOP_HOST_UI_LIMITS`.

## 3. Threat model additions (same-user agent with Full Control)

Test names: `core_tests` in `crates/orcel-authority/src/`, `dispatch_jobs` and `console_harness` in
`crates/orcel-authority/tests/`, `full_control_dispatch_tests` and `fc_worker_tests` in `crates/orceld/src/`. The
Windows `fc_worker_tests` here start the built `orceld.exe fc-worker` as a stand-in host (it waits on its stdin like
the computer host) with the production launch into real unnamed jobs made the way the service makes them. "UNVERIFIED
(founder run)" means only the installed service can show it.

| Attack | Claim | Evidence |
| --- | --- | --- |
| Keep the desktop input host running after revoke, Stop, lock or expiry | The host is in the lease's job; the service ends the job with the lease; the host and its workers end within a second | `core_tests::wp110_the_desktop_host_job_lives_with_its_lease` (revoke, Stop, lock, expiry), `fc_worker_tests::windows::fc_worker_the_desktop_host_runs_in_its_leases_job_and_ends_with_it`. Through the installed service with a real host in the founder's session: UNVERIFIED (founder run) |
| Run a desktop action in a host outside the lease's job | After the service admits the action, only that lease's host serves it; a host that ended is not replaced by one outside the job (`LEASE_INVALID`); every failure to arrange the job refuses | `full_control_dispatch_tests::fc_dispatch_the_desktop_host_fails_closed_without_its_job`, `fc_dispatch_the_desktop_host_runs_in_its_leases_job_and_a_new_lease_gets_a_fresh_one`. The `uia::computer_host` check itself: structural (no unit test drives the native host). Residual 4 |
| Carry a host (and its state) from one lease to the next | A new lease, or a host that ended, gets a fresh host in a fresh job; asking again ends the earlier job | `full_control_dispatch_tests::fc_dispatch_the_desktop_host_runs_in_its_leases_job_and_a_new_lease_gets_a_fresh_one`, `core_tests::wp110_the_desktop_host_job_lives_with_its_lease` |
| A plain host started after the lease's host (an observation restart racing a new lease's start) is taken for the lease's | The lease's record names the host generation it started; the adapter moves the generation on every host replacement, and the lease's host is used only while its generation is current and running | `full_control_dispatch_tests::fc_dispatch_the_desktop_host_runs_in_its_leases_job_and_a_new_lease_gets_a_fresh_one` (a replaced host is not kept); `uia::computer_host` uses `ComputerHostAdapter::host_running_at` (structural). Residual 4 |
| One orceld instance ends another's desktop host under the same lease | Asking again replaces only the caller's own job (user, logon session, PID and creation time) | `core_tests::wp110_the_desktop_host_job_lives_with_its_lease` |
| The service closes a handle value in an orceld from before this slice (which closed it itself, so the value may be reused) | Such an orceld gets no job: a job-family `Authorize` without `job_ack` is refused before any job exists, so nothing is ever withdrawn from it | `core_tests::wp110_unconfirmed_jobs_end_after_the_ack_timeout_and_confirmed_ones_stay` (refused, no job made, nothing withdrawn or terminated; desktop `Authorize` without `job_ack` still answered; `job_ack` absent on the wire parses as false); the newer peer's withdraw path in the same test |
| Resume the host after a revoke that landed between the answer and the resume | `DispatchActive` refuses; the suspended host is terminated without having run | `fc_worker_tests::windows::fc_worker_a_desktop_host_whose_job_ended_before_the_resume_never_runs`, `full_control_dispatch_tests::fc_dispatch_the_desktop_host_fails_closed_without_its_job` |
| The host runs before it is in the job | Assigned while suspended; the job already holds it when the service is asked | `fc_worker_tests::windows::fc_worker_the_desktop_host_runs_in_its_leases_job_and_ends_with_it` (one process in the job at the confirmation) |
| The host or its workers break away | No breakaway limit on the desktop host job either | `dispatch_jobs::wp110_the_desktop_host_job_keeps_desktop_input_working_and_allows_no_breakaway` (`CREATE_BREAKAWAY_FROM_JOB` refused inside it) |
| Terminate, query or re-limit the desktop host job from the session | orceld's handle carries assign-process only | `dispatch_jobs::wp110_a_desktop_host_job_handle_carries_assign_process_only`. From `NT SERVICE\OrcelAuthority` into a real orceld: UNVERIFIED (founder run) |
| Get a desktop host job without a covering lease, for another session, or as another process | orceld role, an active desktop Full User lease of the caller that admits desktop input; the handle goes only to the observed instance | `core_tests::wp110_the_desktop_host_job_lives_with_its_lease`, `console_harness::wp110_desktop_host_jobs_and_acknowledgements_need_orceld_and_a_held_job`, `dispatch_jobs::wp110_a_desktop_host_job_handle_carries_assign_process_only` (recycled PID refused) |
| The job's limits break legitimate desktop input | `HANDLES` and `GLOBALATOMS` are left out; a process in the desktop host job sees other processes' windows | `dispatch_jobs::wp110_the_desktop_host_job_keeps_desktop_input_working_and_allows_no_breakaway` (read-only). Real input through the computer host inside the job on the founder's desktop: UNVERIFIED (founder run) |
| Acknowledge someone else's handle: another authorization, another value, another orceld instance (PID, creation time, unreadable creation time), another logon session, a second time | Refused | `core_tests::wp110_a_job_ack_binds_authorization_handle_and_orceld_instance`, `console_harness::wp110_desktop_host_jobs_and_acknowledgements_need_orceld_and_a_held_job` |
| Confirm (and so resume into) a job whose handle was not acknowledged, or from another instance | `DispatchActive` refuses | `core_tests::wp110_a_job_ack_binds_authorization_handle_and_orceld_instance`, `core_tests::wp110_dispatch_active_refuses_once_the_lease_or_job_ended` |
| Lost `Authorize` reply leaks a handle in orceld (slice 3 residual) | The unconfirmed job ends after 15 s and its unacknowledged handle is closed in orceld by the service; a late acknowledgement or confirmation is refused | `core_tests::wp110_unconfirmed_jobs_end_after_the_ack_timeout_and_confirmed_ones_stay`. The handle actually closed inside a real orceld by the installed service: UNVERIFIED (founder run); `DUPLICATE_CLOSE_SOURCE` into this process: slice 3's `withdraw` path |
| The timeout kills a running dispatch | Never a confirmed one | `core_tests::wp110_unconfirmed_jobs_end_after_the_ack_timeout_and_confirmed_ones_stay`, `core_tests::wp110_the_desktop_host_job_lives_with_its_lease` (no age limit while the lease lives) |
| orceld uses a handle it could not acknowledge, or closes one the service will close | Neither: a refused acknowledgement runs nothing, closes nothing and is reported failed; a refused answer's handle is left to the service | `full_control_dispatch_tests::fc_dispatch_acknowledges_the_job_handle_before_using_it`, `fc_dispatch_a_job_family_needs_its_service_made_job` |
| A peer from before this slice | Refused, nothing used: unknown requests and fields at an older service; an older orceld gets no job | Structural: `Request` is `deny_unknown_fields` with a closed set of ops (`protocol::tests::requests_are_strict`); `core_tests::wp110_unconfirmed_jobs_end_after_the_ack_timeout_and_confirmed_ones_stay`, `core_tests::wp110_a_job_ack_binds_authorization_handle_and_orceld_instance` (no `DispatchActive` without the acknowledgement) |

## 4. Residuals

1. **Double loss.** If the service accepts an acknowledgement but its reply never reaches orceld, orceld neither uses
   nor closes the handle and the service (which saw it acknowledged) does not close it either: one handle stays in
   orceld until it exits. The job is ended by the timeout (never confirmed); nothing can run in it because
   `DispatchActive` refuses an ended job.
2. **Service restart.** A restarted service knows no job; an acknowledgement of a handle the earlier service sent
   is refused and orceld leaves the handle alone (one handle per such dispatch). Slice 3's restart residual stands: a
   same-user copy of orceld's handle keeps a job alive past a restart. For the desktop host job, kill-on-close fires
   when the service exits, so the host ends with the service; the next desktop action asks the restarted service for
   a fresh job.
3. **Handle copies.** A same-user process can still duplicate orceld's assign-only handle out of orceld (it holds
   `PROCESS_DUP_HANDLE` on orceld) before orceld closes it and put its own processes into a job. In a desktop host
   job, which has no age limit, they stay until the lease ends (they still end with it).
4. **A narrow window at the lease's end.** `uia::computer_host` checks, under the adapter's session lock, that the
   host in use is the one started into the lease's job (its generation) and still running; a host replaced before
   that check is never taken for the lease's. What remains is the gap between that check and the action's first
   request to the host: if the lease ends (the service kills the host) in that gap and an observation on another
   thread restarts a plain host before the request, that request can reach the plain host. Before this slice the
   action would have run regardless; the gap is between two in-process calls. Checking the generation on every host
   request would close it. **Closed in slice 6** ([SG132_SLICE6.md](SG132_SLICE6.md) section 1.2): every message a
   leased action sends is checked against the lease's host generation under the session lock.
5. **What the job does not contain.** Synthesized input, and effects through out-of-job brokers (COM, WMI, Task
   Scheduler, the shell), are not limited by any job (slice 4 section 5, C-27). The desktop host job leaves out
   `HANDLES` and `GLOBALATOMS` by design (section 1.2), so the host can use any window on the user's desktop, as
   desktop input must.
6. **Observation outside a job.** Safe-mode observation, and desktop input where no service is installed (the
   deprecated store), still use a host outside any job, as before.
7. **Snapshots after a host switch.** The first semantic action after a new host started can be refused as stale
   (host snapshot ids belong to the old host); a fresh observation fixes it.
8. **The 15-second window.** An orceld that stalls (a debugger, a suspended process) for longer than the timeout
   between the answer and `DispatchActive` has its dispatch refused; that fails closed.
9. **Founder runs (UNVERIFIED rows):** the installed service making a desktop host job for a real orceld after
   impersonating it; real desktop input through the computer host inside the job on the founder's desktop (UI
   Automation, focus, window actions, capture); Stop through the installed service ending the host in the middle of
   an action; the service closing an unacknowledged handle inside a real orceld.

## 5. Not done; next steps

1. Founder runs for the UNVERIFIED rows above and slices 3 and 4.
2. Retire `authority.key` and the deprecated store after the founder's first real desktop grant through the
   installed service (slice 3 section 6); the plain host for desktop input goes with it.
3. The real MCP client principal at the desktop gate (slice 2 residual). Done in slice 6
   ([SG132_SLICE6.md](SG132_SLICE6.md) section 1.1), which also made the service require paths for every
   `shell_process` dispatch.
4. Request capabilities and MCP tools for the filesystem, process and git operations (slice 4 section 6, step 1).
5. Possibly a private global atom table for the desktop host job (`GLOBALATOMS`), once UI Automation inside such a
   job is verified on a real desktop.
6. Then the indicator and its heartbeat (WP1-12) and standing approvals (WP1-14).

## Tests

At head (Windows, unelevated):

- `cargo test -p orcel-authority` (all targets): unit tests (3 new `core_tests::wp110_*` for this slice, 2 updated for
  the acknowledgement), `console_harness` (1 new), `dispatch_jobs` (2 new: the desktop host profile read back,
  breakaway refused, windows of other processes visible from it and not from a dispatch job, the handle's rights),
  `install_script`. All pass.
- `cargo test -p orceld --bin orceld -- fc_worker full_control_dispatch`: 3 new dispatcher tests with a fake service
  and a fake host launcher, 1 updated; 2 new Windows `fc_worker_tests` with the production launch of a real process
  into real jobs. All 32 pass, the existing `fc_worker` tests included.
- `cargo clippy -p orcel-authority -p orcel-provider-uia -p orceld --all-targets -- -D warnings` on Windows: clean.
  The Linux and macOS builds, the workspace-wide clippy and the remaining feature combinations are left to CI (this
  PC has no other targets installed and little free disk). Some unrelated orceld tests fail on this PC because of its
  AppData permissions (`InsecureAcl`, before this slice), so the whole orceld suite is also left to CI.
