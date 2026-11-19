# SG-000132 slice 4: process and git operations in `orceld fc-worker`, and the escape routes

Status: implemented and tested on branch `authority/fc-worker-process-git`; not installed. Revision 2 answers the
independent security review of `b79a8599` (one high, one medium, two lows; listed at the end). Nothing in this slice was
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
  `sc`, `runas`, `pcalua`, `forfiles`, `cmstp`, `wt`, `winrs`, `conhost`), the shells and tools Git for Windows
  ships (`dash`, `env`, `perl`, `busybox`, `mintty`, `winpty`, `scalar`, `tig`), and every name starting with `git`
  (`git`, `gitk`, `git-gui`, `git-upload-pack`, ...: Git runs only through the hardened git operations, so
  `-c core.sshCommand=...` or `--upload-pack` can never reach it through `run`). Nothing under a Git installation
  (the `...\Git` folder above each `cmd\git.exe` candidate) runs through `run`, whatever its name.
- **The program started is the one checked (review low 3).** The worker opens the program without write or delete
  sharing and holds it from its checks until it has started, so the file cannot be written, renamed, deleted or
  replaced meanwhile; right before the start it resolves the path again and requires the same path and the same
  file identity (volume serial number and file index), which catches a folder on the path swapped since the checks.
  The reply names the identity (`program_identity`). The identity is not in the action digest: orceld does not
  open the user's files before `Authorize` (only the worker does, inside the job); the digest binds the path.
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

The git operations reuse the existing provider (`orcel-provider-git`), as SG-000097 asks; the review's fixes below
are in the provider, so the Safe-mode git capabilities get them too:

- **Configuration gate (review high 1 and medium 2; `orcel-provider-git/src/repo_config.rs`).** Before any Git
  command runs, the provider reads the repository's files itself, without Git: from the working folder up to the
  workspace root, the nearest `.git`; for a `.git` file its `gitdir:`, and the `commondir` of the folder it names;
  then the `config` and `config.worktree` files they lead to. It refuses a `.git`, `gitdir:` target, `commondir`
  target or configuration file that is a link or junction; a `gitdir:` or `commondir` naming a network share or a
  device (`\\host\share`, `//host/share`, `\\?\UNC\...`, `\\.\`); a working folder inside a `.git` folder; and any
  configuration entry that can make Git run a program, follow an include or use a transport: the whole `hook`
  section (hooks defined in configuration, `hook.<name>.command` with `hook.<name>.event`, which Git 2.36 and later
  run despite `core.hooksPath` and `--no-verify`; the review reproduced them on 2.56 from `diff`, `add`,
  `restore --staged`, `commit --no-verify` and branch creation), `alias`, `include`, `includeIf`, `credential`,
  `protocol`, `url`, `http`, `uploadpack`, `receivepack`, `sequence`, `gpg`, `pager`, `difftool`, `mergetool`,
  `guitool`, `browser`, `man`, `instaweb`, `sendemail`, `trace2`; `core.sshCommand`, `gitProxy`, `fsmonitor`,
  `editor`, `pager`, `askPass`, `hooksPath`, `alternateRefsCommand`, `worktree`; `diff.external`,
  `diff.<driver>.command` and `.textconv`, `merge.<driver>.driver`, `remote.<name>.uploadpack`, `.receivepack`,
  `.vcs`, `.proxy`, `submodule.<name>.update`; and any value naming a share or a device (`core.excludesFile`,
  `core.attributesFile`, `mailmap.file` and the like, which Git would open: an SMB connection sends the user's NTLM
  credentials). With includes refused and system and global configuration never read, those files are the whole
  repository configuration. The parser follows Git's syntax (quotes, escapes, `\` continuations, comments, the old
  `[section.subsection]` form, a byte-order mark) and refuses what it cannot parse. Git's own listing
  (`config --list --show-scope --no-includes`) is checked against the same rules before every command: a backstop
  for hooks and command-valued keys if the two ever read a file differently, but not for includes. Git still
  follows `include.path` while it starts up (`--no-includes` only changes what the listing prints; the re-review
  confirmed it), so for a path an include names, including a share, the hand-written parser's refusal of
  `include` and `includeIf` is the only defence. Decision: filter drivers stay neutralized rather than refused (every driver's
  `clean`, `smudge` and `process` emptied on every command, and adding a file a filter attribute names is
  refused), so repositories set up for Git LFS keep working; the review listed `filter` among sections to deny.
- **Submodules fail closed (re-review).** A submodule's own configuration (`.git/modules/<name>/config`) and its
  filters are outside the gate, and raw Git runs a submodule's clean filter from `git add -- sm` and from `commit`.
  A repository with a `.gitmodules` entry or a `modules` folder in its Git directory (or common directory) is
  refused before Git runs. A gitlink to a nested repository without them is never entered: every command carries
  `-c diff.ignoreSubmodules=all`, `-c status.submoduleSummary=false` and `-c submodule.recurse=false`, status and
  diff pass `--ignore-submodules=all`, and the mutations accept file paths only (a directory is refused).
- **Discovery.** `GIT_CEILING_DIRECTORIES` is the workspace root's parent, so Git never looks for a repository or
  its configuration above the root, and `-c safe.bareRepository=explicit` refuses a bare repository found by
  discovery (where the gate does not look). `GIT_DISCOVERY_ACROSS_FILESYSTEM` stays unset (Git's default: no
  crossing of file system boundaries).
- **Full Control writes into `.git` (review high 1).** The worker's `write_text` and `mkdir` refuse any path whose
  resolved parent, or whose existing entry, has a `.git` component (case-insensitive, so `.GIT` and the short name
  `GIT~1` are caught), so Full Control's filesystem operations cannot plant a configuration, hook or `.git` pointer.
  Decision: `.gitattributes` and `.gitmodules` stay writable (a filter attribute only makes the add refuse; a
  `.gitmodules` file makes the gate refuse the whole repository); reads inside `.git` stay allowed.
- **Safe mode's network commands.** The fetch and push transports start their own Git processes (with
  `neutralizing_args`); the gate now runs right before each of them as well (`fetch.rs`, `push.rs`).

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
| Window messages, hooks and DDE to processes outside the job; desktops; clipboard; log off and shutdown; system parameters; display settings | Reduced, not closed (review low 4): the service now sets UI restrictions on every dispatch job (`win::jobs::JOB_UI_LIMITS`): `HANDLES`, `GLOBALATOMS`, `DESKTOP`, `EXITWINDOWS`, `SYSTEMPARAMETERS`, `DISPLAYSETTINGS`, `READCLIPBOARD`, `WRITECLIPBOARD`. No job restriction covers synthesized input (`SendInput`), and a `run` program is not necessarily headless (`CREATE_NO_WINDOW` only hides a console; a GUI program can still make windows on the user's desktop). The tests run real programs and real Git under these restrictions. Residual in section 5 |
| Shell, script host or launcher started directly | Refused by name and kind (`.exe` only, `REFUSED_PROGRAMS`) |
| Git run outside the hardened operations | Refused: names starting with `git` and everything under a Git installation (its shells, Perl, `scalar`, the pack programs) are refused |
| A repository's configuration runs a program (hooks defined in configuration, aliases, command-valued keys) or names a share | Closed: the configuration gate refuses the repository before any Git command (section 1), in the shared provider |
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
| A repository's `.git/hooks` or filter drivers run a program | None runs through status, add, diff, commit, branch, unstage or log; a filter-attributed file is refused; the same repository with plain Git does run its hook (control) | `fc_worker_tests::windows::fc_worker_git_honors_no_hook_or_hostile_configuration` |
| Hooks defined in configuration (`hook.<name>.command` and `.event`: post-index-change from a diff, reference-transaction, post-commit), `core.hooksPath`, fsmonitor, pager, external diff, textconv, signing program, ssh command, askpass or credential helper (review high 1) | The repository is refused before any Git command runs, for reads and mutations; one configured hook is enough; Git on this PC (2.56) and the CI runners does run such hooks (control printed by the provider test) | `fc_worker_tests::windows::fc_worker_git_refuses_a_repository_whose_configuration_runs_programs`; `review824_config_gate::review824_config_defined_hooks_refuse_the_repository_before_git_runs`, `review824_hooks_in_the_worktree_config_and_old_section_forms_are_refused`, `review824_command_valued_keys_and_includes_are_refused` (Linux, macOS and Windows); parser and rules: `repo_config::tests` |
| A repository with submodules, or a gitlink to a nested repository with its own filter (re-review) | Submodules refused before Git runs; a nested repository is never entered, and its filter does not run through status, diff, add or commit | `review824_config_gate::review824_submodules_are_refused_and_nested_repositories_never_entered`; `tests::a_submodules_filters_never_run` in `orcel-provider-git` (now refused) |
| A `.git` file, `commondir` or configuration value names a network share or device (NTLM leak; review medium 2) | Refused from the files themselves before Git could open anything | `review824_config_gate::review824_a_git_file_naming_a_share_is_refused_before_git_opens_it`, `review824_command_valued_keys_and_includes_are_refused`, `repo_config::tests::command_valued_and_share_valued_keys_are_refused` |
| Plant a hook, configuration or `.git` pointer through Full Control's filesystem writes | Refused (`CAPABILITY_DENIED`) | `fc_worker_tests::windows::fc_worker_filesystem_never_writes_into_git_folders` |
| Swap the program between its checks and its start (review low 3) | The file is held without write or delete sharing; the path is resolved again and its identity compared right before the start | `fc_worker_tests::windows::fc_worker_holds_the_checked_program_and_refuses_the_git_installation` |
| Run Git for Windows' bundled programs (`scalar`, `git-upload-pack`, `usr\bin` shells and tools) through `run` (review low 4) | Refused by name and by location | `fc_worker_tests::windows::fc_worker_holds_the_checked_program_and_refuses_the_git_installation`, `fc_worker_runs_only_resolved_exe_programs_inside_the_roots` |
| Argument injection into Git (`-c core.sshCommand=...`, `--upload-pack`, options as paths, pathspec magic, `.git` paths) | No free arguments exist; branch names starting with `-` refused; paths go after `--` as literal pathspecs; a message is only a message | `fc_worker_tests::windows::fc_worker_git_refuses_injected_options_and_repositories_outside_the_roots`, `full_control_dispatch_tests::fc_dispatch_process_and_git_paths_stay_in_the_roots_and_take_no_free_arguments` |
| A repository outside the roots, or a `.git` file pointing out of them | Refused (`PATH_ESCAPE`) | `fc_worker_tests::windows::fc_worker_git_refuses_injected_options_and_repositories_outside_the_roots` |
| Run a process or change a repository without the person's approval, or with an approval for another action | The approval comes before `Authorize` and is bound to the digest the service records; a refusal authorizes and runs nothing; no lease, no prompt | `full_control_dispatch_tests::fc_dispatch_process_and_git_mutations_need_a_fresh_approval_bound_to_the_digest`. The Windows approval dialog for these actions: arrives with section 6 |
| Stop, revoke or expiry during a run | The service terminates the job (slice 3); the process tree goes with it | Slice 3 rows; through the installed service with a real run in flight: UNVERIFIED (founder run) |

## 5. Residuals (recorded honestly)

- **Out-of-job brokers (C-27 a).** A program running as the user can ask a process outside the job to start
  programs or act for it: COM out-of-process activation (including the Task Scheduler and WMI COM APIs), WMI
  `Win32_Process.Create`, the Task Scheduler, BITS notification commands, services the user may control, the shell
  through `ShellExecute` or an existing shell window, and any other program that launches programs on request. Those
  processes are not in the job and survive Stop. The UI restrictions reduce the window-message, hook, DDE and
  clipboard routes; they do not close synthesized input, RPC, ALPC or COM. Refusing `schtasks`, `wmic`, `explorer`, `rundll32`, `mshta`
  and the shells by name only stops the obvious direct launches: a renamed copy passes the name check (its single
  name and location in the roots are still required), and any program that can run code (an interpreter, a build
  tool, a program the agent wrote into the roots) can call those brokers itself. This cannot be closed for a
  same-user process without the restricted-token profiles C-26 replaced; the grant prompt's C-27 text says effects
  made through the OS outside Orcel's process trees can persist.
- **Input and windows (review low 4).** A program started by `run` can synthesize input (`SendInput`) and, if it
  is a GUI program, make windows on the user's desktop; no Job Object restriction covers synthesized input. The UI
  restrictions stop it from using window handles of processes outside the job and from the clipboard, atoms,
  desktops and system settings, not from typing into the focused window. Same-user residual (C-27), like any
  program the agent could start.
- **Descendants after a timeout or exit** keep running in the job until the outcome is reported (the service then
  terminates it) or, if reporting fails, until the job's 10-minute limit. They cannot leave the job.
- **TOCTOU.** The program itself cannot change while held, and its path is re-resolved and its identity compared
  right before the start; a same-user process can still swap a folder on the path in the instant between that
  re-check and `CreateProcessW` (the standard library cannot start a process suspended to compare afterwards). For
  filesystem operations the slice 3 residual stands. The configuration gate reads files that a same-user process
  could change between the gate and Git's own read; Git's listing is checked again before every command, which
  narrows but does not close that window.
- **Git's own inputs.** Git searches `PATH` for its helpers and Git for Windows' launcher adjusts it; no hook,
  alias or transport is reachable. A per-user Git install under `%LOCALAPPDATA%` is user-writable, so a same-user
  agent could replace it; that is a same-user effect like running any program. Command-valued keys Git adds in a
  future version are not on the refused list until added; the list is a denylist of known keys (the review's
  preferred allowlist of tolerated keys would refuse ordinary repositories whose configuration carries editor or
  tool settings, and is recorded as a possible tightening).
- **Untracked nested `.git` files (follow-up to #824; fixed, `orcel-provider-git/src/nested.rs`).** Git's
  untracked-file walk reads the `.git` file of every untracked nested folder and checks the folder its `gitdir:`
  names, so `gitdir: \\host\share` would have opened SMB (NTLM leak) from a plain `git_status`, which needs no
  approval. Experiment, local folders only (a nested `.git` file pointing at an existing repository versus a
  missing folder): the results of `status -uall`, `status -unormal` (shown with a folder holding only the `.git`
  file) and `ls-files --others` change with the target, so all three follow it; `status -uno` and a commit with
  `status.showUntrackedFiles=no` read nothing. Fix: every provider command now runs with
  `-c status.showUntrackedFiles=no` (so a commit's own status walks nothing), and before any operation (every one
  resolves its repository first) the provider walks the working tree itself the way Git does: from the
  repository root, never following links or junctions, skipping folders the exclude rules ignore
  (`git check-ignore --stdin`, which reads paths and never walks) unless the index tracks something under them
  (`git ls-files`, index only; Git walks those). The walk still checks an ignored folder's own `.git`, because Git
  asks whether the ignored folder itself is a repository before it skips it. For each nested `.git`, the walk
  refuses (`PATH_ESCAPE`) a link or junction, and a `gitdir:` or `commondir` naming a share, a device, a link, or a
  place outside the workspace. It also refuses a nested Git folder (or its common folder) whose `HEAD`, `objects` or
  `refs` is a link or any reparse point, since Git opens them when it validates the nested repository (review of
  #825). It does not descend below a nested repository. It fails closed (`CAPABILITY_DENIED`)
  past 200 000 entries or 64 levels. Only then does `git_status` run with `--untracked-files=all`. `git add` walks
  towards each path it is given, so a path under an ignored folder the index tracks nothing in is refused
  (`CAPABILITY_DENIED`, same `check-ignore` and index answers) in both the add preview and the add (review of
  #825). Tests with real Git: `orcel-provider-git/tests/nested_gitfile.rs`. Cost: every operation's repository
  resolution walks the working tree (outside ignored folders) and asks `check-ignore` once per folder level, so a
  large tree costs time on every call; a walk that runs into the provider's 30 s per-command limit or the worker's
  60 s limit fails closed, as do the entry and depth caps. Residuals: very large working trees outside ignored
  folders are refused rather than walked. A same-user process could add a nested `.git` file between the walk and Git's own walk
  (the same TOCTOU class as the configuration gate).
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
  service, launcher and approval; 16 `fc_worker` tests (10 new: 9 Windows-only with real jobs, real programs and
  real Git, plus the helper entry point).
- `cargo test -p orcel-authority`: unit, `console_harness`, `dispatch_jobs` (UI restrictions read back) and
  `install_script` suites; `cargo test -p orcel-provider-git`: the provider with an explicit program, the
  configuration gate (`repo_config::tests`, `tests/review824_config_gate.rs`), and the existing suites, of which
  three now expect the gate's earlier refusal (a signing program, an include, URL and HTTP keys at push preview).
- `cargo test -p orceld --bin orceld -- git_`: the Safe-mode git capabilities on the gated provider.
- Some unrelated orceld tests fail on this PC because of its AppData permissions (`InsecureAcl`, before this
  slice); CI runs them.

## Review of `b79a8599` and the answers

| Finding | Answer |
| --- | --- |
| High 1: hooks defined in configuration (`hook.<name>.command` and `.event`) run despite `core.hooksPath` and `--no-verify`, from a diff (no approval) and from mutations; `.git/config` writable through `write_text`; same flaw in the Safe-mode provider | The configuration gate in the shared provider refuses the `hook` section and the other command-valued, include, credential, transport and rewrite keys before any Git command, and Git's own listing is checked again before each command; Full Control's filesystem writes refuse `.git` paths; regression tests with real Git, including post-index-change from a diff and reference-transaction (sections 1 and 4). Filter drivers stay neutralized, not refused (Git LFS), recorded as a deviation |
| Medium 2: `config --list` and `rev-parse` ran before the in-roots check, so a share in `gitdir:` or a path-valued key could make Git open SMB (NTLM leak) | The gate reads the `.git` pointer, `commondir` and configuration files without Git and refuses shares, devices and links; includes are refused; `GIT_CEILING_DIRECTORIES` stops discovery at the root; `safe.bareRepository=explicit` |
| Low-medium 3: the program could change between the checks and the start | Held without write or delete sharing from the checks to the start; re-resolved with its identity compared right before the start; identity reported. Not in the digest (orceld does not open the user's files before `Authorize`); the remaining instant is in section 5 |
| Re-review low: Git's listing is no backstop for includes | Documented: the parser's refusal of `include` and `includeIf` is the only defence for include-named paths |
| Re-review low: submodule configuration and filters | Submodules refused; nested repositories never entered (`diff.ignoreSubmodules=all`, `submodule.recurse=false`) |
| Re-review low: Safe-mode fetch and push started Git without the gate | The gate runs right before each fetch and push transport command |
| Low 4: Git's bundled programs; "Closed" overclaimed for window routes | Names starting with `git`, Git for Windows' shells and tools, and everything under a Git installation are refused; the window row now says reduced, with `SendInput` and GUI windows as residuals |
