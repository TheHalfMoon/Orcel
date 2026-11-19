# SG-000132 slice 4: process and git operations in `orceld fc-worker`, and the escape routes

Status: implemented and tested on branch `authority/fc-worker-process-git`; not installed. Nothing in this slice was
installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry,
firewall or ACL setting changed. Earlier slices: [SG132_SLICE1.md](SG132_SLICE1.md),
[SG132_SLICE2.md](SG132_SLICE2.md), [SG132_SLICE3.md](SG132_SLICE3.md); installing:
[SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Specs: `.specgrain/specs/SG-000132.json` (dispatcher, jobs,
`fc-worker`), `SG-000097.json` (filesystem, processes, "git through the existing provider", every operation in the
`fc-worker` inside a service-owned job), `SG-000096.json` (processes and shells, fresh per-action approval, scrubbed
environment, no shell fallback, bounded output, typed timeouts).

Naming (fixed in this slice): the work packet table of
[UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) section 8.2 is authoritative. WP1-10 is the authority
service, the dispatcher, the service-owned Job Objects and `fc-worker`; WP1-12 is the indicator; WP1-14 standing
approvals; WP1-15 the executors (SG-000096 shells, SG-000097 filesystem, processes, apps). Slices 1 to 3, the code
comments and the test names called the dispatcher work WP1-12 (`wp112_`); they now say WP1-10 (`wp110_`). The
indicator comment in `orcel-contracts/src/indicator.rs` already named WP1-12 correctly and is unchanged. The
process and git operations of this slice are WP1-15 executors running on WP1-10's launch.

**What this slice makes possible:** the dispatcher can run a program or a git operation for a Full User lease
that names the shell/process executor, only inside `orceld fc-worker` in that dispatch's service-made job, after
the person's fresh approval of that exact action. No request capability or MCP tool reaches it yet (section 6).

## 1. The operations (`crates/orceld/src/fc_worker.rs`, `fc_worker_exec.rs`)

`WorkerOp` gains one process operation and seven git operations. Every one is a closed JSON shape
(`deny_unknown_fields`): there is no free argument list for Git, no `shell`, no environment, no command string.

**Process, `run`** (`Family::Process`, executor `shell_process`): `program`, `args`, `cwd`, `timeout_ms`,
`max_output_bytes`.

- **Program.** An absolute drive path that the worker resolves (`canonicalize`, so junctions and links are
  followed) and that must lie inside the resolved lease roots; no program search through PATH or the working
  folder, ever. It must be a `.exe` (no `.bat`, `.cmd`, `.ps1`, `.com`, shortcut or extensionless file: batch files
  run through `cmd.exe`, which re-parses the command line), have exactly one name (a hard link inside the roots can
  name a file outside them; in-box Windows programs also carry WinSxS names, so they are refused too), and not be in
  `REFUSED_PROGRAMS` by file name, checked on the requested and the resolved path: shells and script hosts (`cmd`,
  `powershell`, `pwsh`, `wsl`, `bash`, `sh`, `wscript`, `cscript`, `mshta`), programs that start other programs
  outside the job on request (`schtasks`, `at`, `wmic`, `explorer`, `rundll32`, `regsvr32`, `bitsadmin`, `dllhost`,
  `sc`, `runas`, `pcalua`, `forfiles`, `cmstp`, `wt`, `winrs`, `conhost`), and `git` (Git runs only through the
  hardened git operations, so `-c core.sshCommand=...` or `--upload-pack` can never reach it through `run`).
  Allowlist decision: the specs name no fixed program list for one-shot processes (SG-000096 lets a Full User run
  "ordinary user-token commands"; SG-000097 adds application launch), so the allowlist is by location, the roots the
  person authorized at grant, plus the refused names as a cheap extra. When the roots include a whole drive, the
  name list is the only filter; it is a mitigation, not a boundary (section 5).
- **Arguments.** An argument vector (at most 64, each at most 8192 characters, no NUL; the worst-case command line
  at most 32000 characters), quoted for `CreateProcessW` by the standard library. No shell is involved, so no string
  is ever interpolated into a command.
- **Working folder.** An existing folder inside the resolved roots.
- **Environment.** Cleared, then only `CHILD_ENVIRONMENT` copied from orceld's: `SystemRoot`, `SystemDrive`,
  `windir`, `PATH`, `PATHEXT`, `TEMP`, `TMP`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `APPDATA`, `LOCALAPPDATA`,
  `ProgramData`, the Program Files and Common Files variables, `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`,
  `OS`, `USERNAME`. Nothing else: no tokens or keys, no `GIT_*`, `SSH_*`, proxy or Orcel variables, no `ComSpec`
  (no hint towards a shell). The caller cannot add variables.
- **I/O and bounds.** stdin is the null device; stdout and stderr are captured separately, each up to
  `max_output_bytes` (at most 64 KiB) with the total byte count and a `truncated` flag; `timeout_ms` is 1 to 50000
  (the worker itself is ended at 60 s). The reply carries `exit_code` (a non-zero exit is reported, not turned into
  a failure), and `output_complete: false` when a descendant still held the output pipes 2 s after the program
  exited. A timeout ends the program and fails with `PROCESS_TIMEOUT`; the program's descendants are ended with the
  job when the outcome is reported.
- `CREATE_NO_WINDOW`; never `CREATE_BREAKAWAY_FROM_JOB` (the job refuses it anyway).

**Git** (`Family::Git`, executor `shell_process`): `git_status`, `git_diff` (`staged`), `git_log` (`max_count`
1 to 100), `git_add` (`paths`), `git_unstage` (`paths`), `git_commit` (`message`), `git_branch_create` (`branch`),
each with `repository`, an existing folder inside the roots. Not offered: fetch, push, pull, clone, remote, config,
credential, submodule, gc, checkout or switch to another commit, restore of the working tree, merge, rebase, apply,
hooks installation. Checkout and working-tree restore are left out because they write many files whose names come
from the repository (links, case-folding) and need their own root checks.

The git operations reuse the existing, reviewed provider (`orcel-provider-git`), as SG-000097 asks:

- The provider's workspace root is the lease root holding the repository, so the repository's top level, its Git
  directory and its common directory must all resolve inside that root (a `.git` file pointing outside is
  refused), and a repository that borrows objects (`objects/info/alternates`) is refused.
- **Program.** `GitProvider::with_program` (new) runs an absolute Git path, so there is no program search. The
  worker resolves it from fixed install locations: `%ProgramW6432%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`
  `\Git\cmd\git.exe` (administrator-installed), then `%LOCALAPPDATA%\Programs\Git\cmd\git.exe` (per-user install);
  the variables are orceld's own, never the request's.
- **Environment.** Cleared except `PATH`, `PATHEXT`, `SystemRoot`, `WINDIR`, `TEMP`, `TMP`; `GIT_CONFIG_NOSYSTEM=1`
  and `GIT_CONFIG_GLOBAL` the null device (no system or user configuration, so no credential helper, alias or
  `safe.directory` from there); `GIT_TERMINAL_PROMPT=0`; `GCM_INTERACTIVE=Never`; no `GIT_ASKPASS` or
  `SSH_ASKPASS` (cleared), and mutations add `-c core.askPass=` and `-c credential.helper=`;
  `GIT_ALLOW_PROTOCOL` empty (no transport at all); `GIT_EDITOR` and `GIT_SEQUENCE_EDITOR` the null device;
  `GIT_PAGER=cat`; `GIT_NO_LAZY_FETCH=1`; `GIT_OPTIONAL_LOCKS=0`.
- **Repository configuration.** `-c core.hooksPath=<an empty folder the provider just made>` on every command (the
  repository's own `core.hooksPath` and `.git/hooks` are never used), `--no-verify` and `--no-gpg-sign` on commit,
  `commit.gpgSign=false`, `log.showSignature=false`, `core.fsmonitor=false`, `core.pager=cat`, `gc.auto=0`,
  `maintenance.auto=false`, `core.alternateRefsCommand=`, `--no-ext-diff` and `--no-textconv` on diff, and every
  configured filter driver's `clean`, `smudge` and `process` emptied with `required=false`; adding a file that a
  filter attribute names is refused. `safe.directory` is never set: Git's ownership check stays on, so a repository
  owned by another account is refused.
- **Arguments.** Structured only. Paths are repository-relative, at most 128, no `.git` component, no `..`, no
  pathspec magic (a leading `:` is refused) and passed after `--` as `:(literal)` pathspecs; a branch name may not
  start with `-` and must pass `git check-ref-format --branch`; the commit message is the value of `-m` (a message
  such as `--upload-pack=x` is only a message).
- **Mutations** read the repository's state and act only if it is still that state (the provider's check). A
  commit needs a repository-local `user.name` and `user.email` (global configuration is never read).

The worker's own stdin, stdout and stderr are made non-inheritable before it acts, so a program it starts (or that
program's descendants) never holds orceld's request or reply pipe; the reply limit is now 4 MiB (a diff is up to
2 MiB), and a larger reply becomes `OUTPUT_LIMIT`.

## 2. Escape routes (decisions)

| Route | Decision |
| --- | --- |
| A child or grandchild leaves the job (`CREATE_BREAKAWAY_FROM_JOB`) | Closed: dispatch jobs never set `BREAKAWAY_OK` or `SILENT_BREAKAWAY_OK`; children inherit the job; nothing in the worker asks for breakaway |
| Too many processes | `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` 64 (slice 3), unchanged |
| Window messages, hooks and DDE to processes outside the job; desktops; clipboard; log off and shutdown; system parameters; display settings | Closed by UI restrictions the service now sets on every dispatch job (`win::jobs::JOB_UI_LIMITS`): `HANDLES`, `GLOBALATOMS`, `DESKTOP`, `EXITWINDOWS`, `SYSTEMPARAMETERS`, `DISPLAYSETTINGS`, `READCLIPBOARD`, `WRITECLIPBOARD`. The worker and the programs it runs are headless, so this costs them nothing (the tests run real programs and real Git under these limits) |
| Shell, script host or launcher started directly | Refused by name and kind (`.exe` only, `REFUSED_PROGRAMS`) |
| Git run outside the hardened operations | Refused: `git.exe` is a refused program name |
| Restricted token, low integrity or a separate desktop for process-family workers | Not done. C-26 replaced the revision 4 and 5 restricted-token profiles with the authority service, FD-UP-9 says executors run on the user's desktop with the user's token, and SG-000096 asks for an ordinary current-user token (not `apps/orcel-contain`'s AppContainer mode). Low integrity would also stop Full User programs writing the user's files. Recorded, not contradicted |
| COM activation, WMI `Win32_Process.Create`, Task Scheduler (API or `schtasks`), the shell (`ShellExecute` through `explorer.exe`), BITS, services, any other out-of-job broker | Residual (section 5): cannot be closed for a process running as the user |

## 3. Request-side wiring in this slice

- `Family::Process` now names its paths (the working folder and the program), like filesystem and git; the
  dispatcher and the service check them against the lease's roots before anything runs.
- `ActionApproval` (new): before `Authorize`, once a lease covers the action, a `run` and the git mutations
  (`git_add`, `git_unstage`, `git_commit`, `git_branch_create`) need the person's fresh per-action approval of the
  action digest the service then records (SG-000096 A3). A refusal authorizes nothing, runs nothing and reports no
  outcome. Without a covering lease the person is never asked. Git reads and filesystem operations do not ask in
  this slice. The production adapter (orceld's `ApprovalBroker`, whose prompt is the Windows approval dialog,
  never an in-app control) arrives with the request capabilities (section 6).
- Leases cover only what the spec says: `shell_process` for process and git (granted only with `shells`), the
  lease's roots for every path, the lease's client and task. Standing approvals (WP1-14) do not exist yet, so every
  covered action asks.

## 4. Threat model additions

Test names: `fc_worker_tests` and `full_control_dispatch_tests` in `crates/orceld/src/`, `dispatch_jobs` in
`crates/orcel-authority/tests/`. The Windows `fc_worker_tests` launch the built `orceld.exe` as the worker into real
unnamed jobs made in the unelevated test process the way the service makes them (limits and UI restrictions
included); the program they run is a copy of the test binary inside the roots, told what to do by a mode file in
its working folder (its environment is scrubbed). "UNVERIFIED (founder run)" means only the installed service can
show it.

| Attack | Claim | Evidence |
| --- | --- | --- |
| A started program, or its grandchild, leaves the job | Children inherit the job; a grandchild is still in it after the program and the worker exited, and terminating the job ends it before it can act | `fc_worker_tests::windows::fc_worker_descendants_stay_in_the_job_and_end_with_it`; breakaway refused: `dispatch_jobs::wp110_the_job_kills_on_close_and_allows_no_breakaway` |
| A descendant holds orceld's reply pipe so the dispatch hangs | The worker's standard handles are not inheritable; the reply arrives while the grandchild runs (`output_complete: false`) | `fc_worker_tests::windows::fc_worker_descendants_stay_in_the_job_and_end_with_it` |
| Reach out-of-job windows, DDE, desktops or the clipboard | The service's dispatch jobs carry all eight UI restrictions | `dispatch_jobs::wp110_the_job_kills_on_close_and_allows_no_breakaway` (restrictions read back from the kernel); every Windows `fc_worker_tests` run is under them. A job made by `NT SERVICE\OrcelAuthority`: UNVERIFIED (founder run) |
| Leak orceld's secrets to a program | Only `CHILD_ENVIRONMENT` reaches it; a token variable orceld holds does not | `fc_worker_tests::windows::fc_worker_runs_a_program_in_the_job_with_a_scrubbed_environment` |
| Run forever or flood orceld | Timeout ends the program (`PROCESS_TIMEOUT`, outcome failed, job terminated); output bounded per stream with counts | `fc_worker_tests::windows::fc_worker_a_run_has_a_timeout_and_bounded_output` |
| Run a program outside the roots, through a junction or a hard link, or from a working folder outside them | Refused (`PATH_ESCAPE`) by the dispatcher, the service (lexical) and the worker (resolved, link count) | `fc_worker_tests::windows::fc_worker_runs_only_resolved_exe_programs_inside_the_roots`, `full_control_dispatch_tests::fc_dispatch_process_and_git_paths_stay_in_the_roots_and_take_no_free_arguments` |
| Run a shell, script host, launcher, batch file or Git through `run` | Refused (`CAPABILITY_DENIED`) before anything starts | `fc_worker_tests::windows::fc_worker_runs_only_resolved_exe_programs_inside_the_roots` |
| A repository's hooks, `core.hooksPath`, fsmonitor, pager, external diff, textconv, filter drivers, signing program, ssh command, askpass or credential helper run a program | None runs through status, add, diff, commit, branch, unstage or log; a filter-attributed file is refused; the same repository with plain Git does run its hook (control) | `fc_worker_tests::windows::fc_worker_git_honors_no_hook_or_hostile_configuration` |
| Argument injection into Git (`-c core.sshCommand=...`, `--upload-pack`, options as paths, pathspec magic, `.git` paths) | No free arguments exist; branch names starting with `-` refused; paths go after `--` as literal pathspecs; a message is only a message | `fc_worker_tests::windows::fc_worker_git_refuses_injected_options_and_repositories_outside_the_roots`, `full_control_dispatch_tests::fc_dispatch_process_and_git_paths_stay_in_the_roots_and_take_no_free_arguments` |
| A repository outside the roots, or a `.git` file pointing out of them | Refused (`PATH_ESCAPE`) | `fc_worker_tests::windows::fc_worker_git_refuses_injected_options_and_repositories_outside_the_roots` |
| Run a process or change a repository without the person's approval, or with an approval for another action | The approval comes before `Authorize` and is bound to the digest the service records; a refusal authorizes and runs nothing; no lease, no prompt | `full_control_dispatch_tests::fc_dispatch_process_and_git_mutations_need_a_fresh_approval_bound_to_the_digest`. The Windows approval dialog for these actions: arrives with section 6 |
| Stop, revoke or expiry during a run | The service terminates the job (slice 3); the process tree goes with it | Slice 3 rows; through the installed service with a real run in flight: UNVERIFIED (founder run) |

## 5. Residuals (recorded honestly)

- **Out-of-job brokers (C-27 a).** A program running as the user can ask a process outside the job to start
  programs or act for it: COM out-of-process activation (including the Task Scheduler and WMI COM APIs), WMI
  `Win32_Process.Create`, the Task Scheduler, BITS notification commands, services the user may control, the shell
  through `ShellExecute` or an existing shell window, and any other program that launches programs on request. Those
  processes are not in the job and survive Stop. The UI restrictions close the window-message, hook, DDE and
  clipboard routes; they do not close RPC, ALPC or COM. Refusing `schtasks`, `wmic`, `explorer`, `rundll32`, `mshta`
  and the shells by name only stops the obvious direct launches: a renamed copy passes the name check (its single
  name and location in the roots are still required), and any program that can run code (an interpreter, a build
  tool, a program the agent wrote into the roots) can call those brokers itself. This cannot be closed for a
  same-user process without the restricted-token profiles C-26 replaced; the grant prompt's C-27 text says effects
  made through the OS outside Orcel's process trees can persist.
- **Descendants after a timeout or exit** keep running in the job until the outcome is reported (the service then
  terminates it) or, if reporting fails, until the job's 10-minute limit. They cannot leave the job.
- **TOCTOU.** A same-user process can swap the program or a path component between the worker's checks and the
  start, as for filesystem operations (slice 3).
- **Git's own inputs.** Git reads `include.path` files the repository names, which may lie outside the roots (read
  only; every program-running key is overridden). Git searches `PATH` for its helpers and Git for Windows' launcher
  adjusts it; no hook, alias or transport is reachable. A per-user Git install under `%LOCALAPPDATA%` is
  user-writable, so a same-user agent could replace it; that is a same-user effect like running any program.
- **Approval binding.** The per-action approval binds the request (paths, message, branch), not the file contents
  staged at that moment (the Safe-mode git mutation binds that material); the worker's own state check still
  refuses a repository that changed between its read and its write.
- **The service does not require paths for `shell_process` dispatches.** orceld does (process and git name their
  paths), and the service checks every named path; requiring them at the service is left for the shell-session
  slice, whose sessions also name a working folder.
- Founder runs (UNVERIFIED rows): the UI restrictions on a job made by the installed service; Stop through the
  installed service ending an in-flight `run` and its descendants.

## 6. Not done in this slice; next steps

1. **Request capabilities and MCP tools** for `run` and the git operations (and slice 3's filesystem operations):
   the capability names, the tool shapes and their documentation are product decisions the specs leave open
   (SG-000097 and SG-000096 name the behaviour, not the tools), so this slice stops at the dispatcher. That slice
   adds the production `ActionApproval` over orceld's `ApprovalBroker` (Windows dialog, digest-bound, SOFT class),
   the MCP client principal, and the contract tests.
2. Checkout and switch to other commits, and working-tree restore, with root and link checks on every file they
   write.
3. SG-000096 interactive shells (ConPTY, PowerShell, cmd, Git Bash, WSL) in service-made jobs: they need a job
   profile and a shell allowlist of their own; the `run` operation's refused names do not apply there.
4. SG-000097 application launch and close: GUI programs need a job profile without the UI restrictions, and the
   residuals above apply to them in full.
5. The service requiring paths for every `shell_process` dispatch.
6. Slice 3 next steps 2 to 6 (desktop host in a job, retiring the deprecated store, the MCP principal at the
   desktop gate, the job handle acknowledgement, founder runs) are unchanged.

## Tests

At head (Windows, unelevated):

- `cargo test -p orceld --bin orceld -- fc_worker full_control_dispatch`: 11 dispatcher tests (2 new) with a fake
  service, launcher and approval; 13 `fc_worker` tests (7 new: 6 Windows-only with real jobs, real programs and real
  Git, plus the helper entry point).
- `cargo test -p orcel-authority`: unit, `console_harness`, `dispatch_jobs` (UI restrictions read back) and
  `install_script` suites; `cargo test -p orcel-provider-git` (the provider with an explicit program).
- Some unrelated orceld tests fail on this PC because of its AppData permissions (`InsecureAcl`, before this
  slice); CI runs them.
