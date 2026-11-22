# SG-000132 slice 8: the Full Control request capabilities (`fc.fs`, `fc.process`, `fc.git`, `fc.status`)

Status: implemented and tested on branch `authority/fc-request-capabilities`; not installed. Nothing in this slice was
installed or run elevated, no UAC, Windows Hello or Orcel dialog was shown or answered, and no system, registry,
firewall or ACL setting changed. No test shows a real approval dialog or runs a real program through these
capabilities. Earlier slices: [SG132_SLICE1.md](SG132_SLICE1.md) to [SG132_SLICE7.md](SG132_SLICE7.md); installing:
[SG132_INSTALL_RUNBOOK.md](SG132_INSTALL_RUNBOOK.md). Specs: `.specgrain/specs/SG-000132.json` (dispatcher, jobs,
`fc-worker`), `SG-000097.json` (filesystem, processes, Git), `SG-000096.json` (processes, fresh per-action approval).

Naming: [UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) section 8.2 is authoritative. The operations are
WP1-15 executors on WP1-10's dispatcher. Test names: `fc_requests_` (new) and `fc_dispatch_` (existing) in orceld.

**What this slice does:** the orceld half of the founder's choice of option B in
`docs/orcel/implementation-readiness/prep/FC_TOOL_SURFACE_OPTIONS.md` (the decision brief of PR #829), which is item
(1) of that option's effort and [SG132_SLICE4.md](SG132_SLICE4.md) section 6 step 1. A request can now reach the
Full Control worker: the request capabilities, the production per-action approval over the Windows approval dialog,
the calling client as the principal, the remote refusal before dispatch, and contract tests. The MCP tools
(`fc_fs_stat` ... `fc_status` in `apps/orcel-mcp`, the contract entries and the regenerated
[docs/p16/TOOL_CONTRACT.md](../../../p16/TOOL_CONTRACT.md)) are slice 2 of option B and are not in this slice; until
they exist no agent tool sends these requests.

## 1. Founder decisions (2026-11-19), as built

The authority is the spec amendment in `.specgrain/specs/SG-000132.json` (`amendments`: "SG-000132 amendment: Full Control file writes covered by the lease, and the fc_* tool surface",
created 2026-11-19, PR #829), which records the founder's answers in
[FC_TOOL_SURFACE_OPTIONS.md](FC_TOOL_SURFACE_OPTIONS.md) section 8. Answering the four questions of the brief:

1. **Option B:** separate local-only tools, one per worker operation (`WorkerOp`), plus a read-only `fc_status`. The
   tool names and their operations: `fc_fs_stat` (`stat`), `fc_fs_list` (`list`), `fc_fs_read` (`read_text`),
   `fc_fs_write` (`write_text`), `fc_fs_mkdir` (`mkdir`), `fc_process_run` (`run`), `fc_git_status`, `fc_git_diff`,
   `fc_git_log`, `fc_git_stage` (operation `git_add`), `fc_git_unstage`, `fc_git_commit`, `fc_git_branch_create`.
2. **Approvals, with the founder's amendment for file writes:** the brief recommended a fresh Windows approval on
   every Full Control file write. **The founder decided otherwise for `fc_fs_write` and `fc_fs_mkdir` only: they are
   covered by the lease and ask nothing per call.** `fc_process_run` and the four Git changes (`git_add`,
   `git_unstage`, `git_commit`, `git_branch_create`) keep a fresh SOFT Windows approval on every call (SG-000096 A3).
   Reads ask nothing. Every worker call, asked or not, still gets the service's audit-first `Authorize` first.
3. **Where the tools appear:** in the normal local tool list (`desktop_structured`), refusing with `LEASE_REQUIRED`
   until a lease exists. orceld admits `fc.*` only from a local request naming `desktop_structured` or naming no
   tool surface (section 2).
4. **`fc_status`:** read-only; shows the active lease's executors, roots and expiry and this client's reference
   (`client_ref(client_session_id)`); grants nothing.

**The exception, as the SG-000132 amendment states it.** The amendment makes an exception to the invariant "A lease
alone never replaces an approval": under a Full User lease that names the filesystem executor, the fc-worker
operations `write_text` (tool `fc_fs_write`) and `mkdir` (tool `fc_fs_mkdir`) inside the lease's roots are covered by
the lease and ask no per-action approval. Each still has a service `Authorize` and audit record first, stays inside
the roots, refuses `.git` paths, keeps spec 4.14's refusal of the authority state and of writes to the user-session
Orcel state root, and is ended by Stop, revoke and expiry. No other operation is covered by this exception: a program
run and the Git changes keep a fresh SOFT approval on every call (SG-000096 A3) unless a standing approval (spec 4.15)
covers them, deletion keeps its own approval (SG-000097), and remote callers stay excluded (SG-000105). Safe-mode
writes are unchanged and still ask SOFT. In code the exception is cited at `WorkerOp::needs_approval`
(`crates/orceld/src/fc_worker.rs`) and in the module header of `crates/orceld/src/fc_requests.rs`.

**Spec 4.14's state refusal, enforced in this slice.** Before this slice the worker refused `.git` writes but not
writes to Orcel's own state inside a broad root (a lease on `C:\Users\<name>` covered `%USERPROFILE%\.orcel`,
where the approval ledger, trust records and audit chain live). Since the amendment makes these writes prompt-free,
the worker now refuses (`CAPABILITY_DENIED`) any `write_text` or `mkdir` whose resolved target is in the authority's
state folder (`...\Orcel\authority`) or in a protected state root (`orcel_policy::protected_state`: the per-OS
state root, the earlier `%LOCALAPPDATA%\Orcel` and every `ORCEL_*` override, read from the environment the worker
inherits from orceld). It fails closed: a per-OS state root that cannot be established
(`orcel_policy::protected_state::protected_write_roots`, unlike the policy's own list, which skips it) or a protected
root that cannot be resolved refuses every write.

The authority-state rule is deliberately broad: any target with two adjacent path components `Orcel` and `authority`
(case-insensitive) is refused, wherever it is, matching the lease root check (`check_root` refuses `\orcel\authority`
in a root). A user folder that happens to be named `...\Orcel\authority\...` inside the roots is therefore refused
too (a false refusal, by design: the rule cannot be fooled by where the service's state folder lives).

**The target is checked again by its handle (Windows).** The path checks run before the open, so a folder inside the
roots could be swapped for a junction (into Orcel's state, or out of the roots) between the checks and the open. After
opening, the worker reads where the handle really is (`GetFinalPathNameByHandleW`) and checks it again: inside the
resolved roots, outside any `.git` folder, outside Orcel's state; on a mismatch it refuses with
`PATH_RACE_DETECTED` before writing a byte. A file this call created is opened with delete access and removed by its
handle (never by a name that could now point elsewhere); an existing file is left untouched. For `mkdir` (since the
follow-up of residual 7), the parent folder is opened by its handle, refused if it is now a reparse point, and checked
the same way; the new folder is created relative to that handle (`NtCreateFile` with `RootDirectory`) and its own
handle is checked the same way; on a mismatch it is removed by that handle, which succeeds only while it is empty.
Nothing is reopened by name. Outside Windows there is no authority service, no lease and no
worker dispatch (the dispatcher refuses before any launch), so only the path checks exist there.

## 2. What changed

- **`crates/orceld/src/fc_requests.rs` (new):**
  - Request shapes (`FC_SHAPES`): `fc.fs` with `stat`, `list`, `read_text`, `write_text`, `mkdir`; `fc.process` with
    `run`; `fc.git` with `git_status`, `git_diff`, `git_log`, `git_add`, `git_unstage`, `git_commit`,
    `git_branch_create`; `fc.status` with `get`. The operation is the `WorkerOp` name and the arguments are that
    operation as the worker reads it (`{"op": "write_text", "path": ..., "text": ..., "create_new": ...}`), so the
    action digest is over exactly what runs. No `target` (every path is in the operation); the status takes no
    arguments. A shape outside the table (another `fc.*` name, an operation of another family) is
    `CAPABILITY_DENIED`; a malformed operation, a mismatch between operation and arguments, a target or an old
    protocol is `INVALID_REQUEST`.
  - `dispatch`: the status, or, after the operation's own argument checks (`WorkerOp::check_arguments`: the run's
    timeout, output, argument count, length and NUL bounds shared with the worker (`exec::check_run_arguments`); the
    list, read and log bounds; the write size; the Git provider's own path, commit message and branch input checks,
    now public in `orcel-provider-git`), so a malformed request is refused before the lease is used or the person is
    asked, `full_control_dispatch::run_in_worker` with the calling client's reference
    (`orcel_policy::browser_lease::client_ref(client_session_id)`) as `principal_id`, as `desktop_gate` names it since
    slice 6. `run_in_worker` was built in slices 3 and 4 and is unchanged: lease (executor, client, roots), the
    approval where `needs_approval`, `Authorize` (audit first), the job, the worker, the outcome.
  - `BrokerApproval`: the production `ActionApproval`, over orceld's `ApprovalBroker` (`LocalApprovalBroker`, whose
    SOFT prompt is the Windows approval dialog; approvals stay with Windows, never an in-app control). One
    `ApprovalPrompt` per call: SOFT, single-operation, bound to the action digest the service then records, naming the
    program or the repository as the target, and a summary that starts with the asking client's reference
    (`asked by client cl-...`, the same reference `fc.status` gives the agent) and then the working folder before the
    arguments, or the paths, message or branch. Every argument, path, message and branch is shown as JSON text, so an
    embedded quote, backslash or line break cannot make one argument look like several. Approved runs;
    No or no answer is `APPROVAL_DENIED`; a prompt that cannot be shown is the broker's error
    (`APPROVAL_UNAVAILABLE`).
  - `status`: with the service installed, the active `DesktopFullUser` leases of this Windows user and logon session
    the verified service reported that this client can use: bound to its reference, or unbound (not granted to a client
    reference; such a lease admits it for desktop input only). Another client's lease, browser leases and expired
    leases are not listed. For each: lease id, executors,
    roots, shells, task, expiry, whether it is bound to this client, and which `fc.*` capabilities this client can
    use under it. Without the service: `"authority": "not_installed"` and the client's reference. It calls no
    `Authorize`, makes no job and asks nothing. An installed service that does not answer is `AUTHORITY_UNAVAILABLE`.
- **`crates/orceld/src/sg000039_main.rs`:** `handle_envelope` sends every `fc.*` request to `handle_full_control`
  right after the SG-000108 profile gate, before the remote-session lease gate, the policy and any dispatcher. It
  refuses, in order: a remote request (`CAPABILITY_DENIED`, audit `REMOTE_DENIED`, the new check before dispatch); a
  tool surface other than `desktop_structured` (`CAPABILITY_DENIED`, audit `PROFILE_DENIED`); the request's own form;
  an unconfigured workspace (`WORKSPACE_DENIED`; the workspace only fills the envelope, as for the desktop tools).
  Then orceld's dispatch record (WP1-03), the dispatch, and the outcome record. No `fc.*` request can reach the Safe
  dispatcher.
- **`crates/orcel-policy/src/remote_session.rs`:** `fc.` joins the remote gate's local-only prefixes, so the gate's
  own answer for an `fc.*` request is `CAPABILITY_DENIED` too (a second layer; orceld refuses first).
- **`crates/orceld/src/fc_worker.rs`:** `WorkerOp::needs_approval` is unchanged in behaviour (it already asked for
  `run` and the four Git changes only), records the founder's amendment, and is now an exhaustive match over every
  variant, so a future operation (a delete, a move) does not compile until someone decides whether it asks. New
  `WorkerOp::check_arguments` (above). The tests derive their operation list from an exhaustive match over the enum,
  so a new variant also fails them until it has a sample. The `dead_code` allowances that
  existed only because nothing called the worker path outside tests are gone (`Family`'s variants, `ActionApproval`,
  `run_in_worker`, `WorkerOp`'s methods).
- **`crates/orceld/src/full_control_dispatch.rs`:** comments only (the production adapter and caller now exist).

Refusals, as the brief's table lists them, all existing `FailureCode`s:

| Situation | Code |
| --- | --- |
| No active lease, or the lease does not include the executor (files: `filesystem`; programs and Git: `shell_process`, granted only with `shells`) | `LEASE_REQUIRED` |
| A lease bound to another client | `CAPABILITY_DENIED` |
| Lease revoked, stopped or expired between `Authorize` and the start | `LEASE_INVALID` |
| A path outside the roots, a share or device path; in the worker also a link, a hard link, a `.git` write | `PATH_ESCAPE` / `CAPABILITY_DENIED` |
| The person said No or did not answer; the dialog could not be shown | `APPROVAL_DENIED` / `APPROVAL_UNAVAILABLE` |
| Service not installed or not answering | `AUTHORITY_UNAVAILABLE` |
| Program timed out; output over the limit | `PROCESS_TIMEOUT` / `OUTPUT_LIMIT` |
| Bad arguments, operation and arguments disagree, a target | `INVALID_REQUEST` |
| An unknown `fc.*` shape, an operation under the wrong family | `CAPABILITY_DENIED` |
| A remote caller (whatever its remote-session lease) | `CAPABILITY_DENIED` |

The brief lists `REMOTE_SESSION_INACTIVE` "or the tool is simply not served remotely" for a remote caller. orceld
refuses every remote `fc.*` request before the remote-session lease is looked at, with `CAPABILITY_DENIED`, the code
Full User desktop shapes and `browser_full` shapes already use for "local-only"; so the answer does not depend on
whether a remote-session lease exists, and `REMOTE_SESSION_INACTIVE` (which means "no remote-session lease") is never
used for it.

**Which lease works.** The service admits a client principal other than the lease's own only for desktop input
(`LeaseBody::admits_client`). For files, programs and Git the lease must be granted to this client's reference
exactly: `orcel full-control grant --client <client_ref> --executors filesystem,shell_process --root <folder>
--shells`. A lease granted to the default `orcel-owner` refuses these capabilities (`CAPABILITY_DENIED`, fail closed).
`fc.status` is how the client learns its reference to show the person.

## 3. Protocol changes

New orceld request shapes only (`fc.*`, section 2). No new field, no new `FailureCode`, no service change: the
service's `Authorize` already takes any bounded capability and operation name and checks the lease, executor, client,
roots and paths itself (slices 3, 4 and 6). **Older peers:** an older orceld refuses every `fc.*` request at its policy
(`CAPABILITY_DENIED`, not in the policy's table), so a newer MCP module at an older orceld fails closed. A newer orceld
at an older service sends the same `Authorize` slice 4's tests send for filesystem, process and Git dispatches; a
service without the slice 5 job acknowledgement or the slice 6 path requirement refuses them as it did. **Upgrade
order** as before: the service first, then orceld, then the MCP module (slice 2).

## 4. Threat model additions (same-user agent with Full Control)

Test names: `fc_requests_tests` and `full_control_dispatch_tests` in `crates/orceld/src/`, against the dispatcher's
fake service, launcher and approval (every OS). "UNVERIFIED (founder run)" marks what only the installed service on a
real desktop shows.

| Attack | Claim | Evidence |
| --- | --- | --- |
| A remote caller (relay, tunnel, ChatGPT connector) uses Full Control | Every `fc.*` request with a remote context, any profile, any shape (an unknown `fc.*` name included), is refused before the remote-session lease, the policy, the workspace and any approval; the remote gate also treats `fc.` as local-only | `fc_requests_the_entry_refuses_remote_callers_before_dispatch` (through `handle_envelope`, a broker that fails the test if asked, an unconfigured workspace); `fc_requests_a_remote_caller_and_other_surfaces_are_refused`; `fc_requests_every_worker_operation_has_exactly_one_shape` (`is_local_only_capability`); `fc_requests_the_entry_routes_fc_before_the_remote_gate` (structural) |
| Another tool surface (`browser_full`, `browser_structured`, the remote `core`) reaches the worker | Only `desktop_structured` or no surface is admitted | `fc_requests_the_entry_refuses_remote_callers_before_dispatch`; `fc_requests_a_remote_caller_and_other_surfaces_are_refused` |
| An `fc.*` request reaches the Safe dispatcher, or a Safe tool reaches the worker | `fc.*` is routed to its own handler before the Safe path; no Safe shape changed | `fc_requests_the_entry_routes_fc_before_the_remote_gate`; Safe suites unchanged |
| A request smuggles an operation of another family, free arguments, or a target | Only the table's shapes; the arguments must be exactly one worker operation whose name is the request's operation | `fc_requests_shapes_are_validated_before_anything_is_asked` (nothing authorized, asked or run); `fc_requests_the_entry_checks_form_and_workspace_locally`; `fc_dispatch_the_operation_is_the_request_arguments_or_nothing` |
| A tool runs without a lease, or a files-only lease runs a program or Git | `LEASE_REQUIRED` for every tool without a lease; a lease without `shell_process` covers files only; the person is never asked without a covering lease; no service is `AUTHORITY_UNAVAILABLE` | `fc_requests_without_a_lease_every_tool_refuses_lease_required` |
| One MCP client uses a lease granted to another | The principal is the caller's `client_ref`; a lease bound to another client refuses before `Authorize` (and the service checks it again) | `fc_requests_the_principal_is_the_calling_clients_reference`; `fc_dispatch_the_desktop_gate_names_the_calling_client` (same binding) |
| **SG-000132 amendment (2026-11-19):** a file write or folder creation runs without a per-call approval | By the amendment: the lease covers `write_text` and `mkdir`. What still holds: the lease's executor, client and roots; the service's audit-first `Authorize` and its record; the dispatch job; the worker's root, link, hard link and `.git` checks; the outcome record | `fc_requests_file_writes_are_lease_covered_and_ask_nothing` (no approval asked; `Authorize`, executor `filesystem`, paths and outcome present); the worker's checks: `fc_worker_tests` (slice 3) |
| A lease-covered write inside a broad root overwrites Orcel's own state (approval ledger, trust records, audit chain, the authority's state) without a prompt | Spec 4.14, kept by the amendment: the worker refuses writes and folder creation in the authority's state folder and in every protected state root, after resolving the target; an unresolvable protected root refuses all writes | `fc_requests_file_writes_never_reach_orcel_state` (every OS); `fc_requests_the_worker_refuses_writes_into_orcel_state` (Windows, real folders, a case variant included); `fc_requests_junctions_and_short_names_into_state_are_refused` (Windows: a junction inside the roots into the state folder, and the state folder's 8.3 short name, skipped with a message on a volume without short names); fail closed without a state root: `orcel-policy` `write_roots_fail_closed_without_a_state_root` |
| A folder inside the roots is swapped for a junction (into Orcel's state or out of the roots) after the path checks and before the open | The opened handle's final path is checked again; a mismatch is `PATH_RACE_DETECTED`, nothing is written, and a file or (empty) folder this call created is removed by its handle | `fc_requests_a_junction_swapped_in_after_the_checks_is_caught` (Windows: a real swap between the checks and the open, for a file and for a folder's parent and an ancestor of it); `fc_requests_mkdir_creates_relative_to_the_checked_parent_handle` (Windows: the parent moved and replaced by a junction after its open; the folder is made in the held parent); `fc_requests_the_opened_target_is_checked_again` (every OS, the check itself) |
| A program or a Git change runs without the person's fresh approval, or one approval covers two actions | `run`, `git_add`, `git_unstage`, `git_commit`, `git_branch_create` ask on every call; each approval is bound to that call's digest, which the service records; a No authorizes and runs nothing | `fc_requests_process_and_git_mutations_ask_every_call` (two rounds, every digest distinct and equal to an `Authorize` digest); `fc_dispatch_process_and_git_mutations_need_a_fresh_approval_bound_to_the_digest` |
| The approval is an in-app control, or not SOFT, or not bound to the action | `BrokerApproval` asks orceld's broker for a SOFT, single-use prompt with the action digest, the program or repository, and a local origin; No and unavailable refuse | `fc_requests_the_windows_approval_is_soft_and_bound_to_the_digest` (scripted brokers); that the broker's SOFT prompt is the Windows dialog: `orcel-approval`'s own suites; the dialog itself on a real desktop: **UNVERIFIED (founder run)** |
| `fc.status` grants or leaks authority | Read-only: no `Authorize`, no job, no approval; lists only desktop Full User leases this client can use (bound to it, or unbound); another client's lease is not listed | `fc_requests_status_shows_the_lease_scope_and_grants_nothing` |
| An argument forges the dialog text (an embedded quote or line break makes one argument read as several), or the person cannot tell which agent asks | Arguments, paths, message and branch are JSON text; the working folder is shown before the arguments; the summary starts with the asking client's reference | `fc_requests_the_dialog_text_escapes_arguments_and_names_the_folder_first`; `fc_requests_the_windows_approval_is_soft_and_bound_to_the_digest` |
| A malformed request costs the person a prompt (prompt fatigue), or reaches the worker | The worker's and the Git provider's argument rules run in orceld first: out-of-range timeouts, output limits, counts, too many or NUL arguments, absolute, `..`, `.git`, `.gitmodules`, magic or duplicate Git paths, empty or oversized messages, unsafe branch names, oversized writes; nothing is authorized, asked or run | `fc_requests_bad_arguments_are_refused_before_the_prompt` |
| A future worker operation (a delete, a move) is added without an approval decision | `needs_approval` is an exhaustive match; the tests' operation list comes from an exhaustive match over the enum | compile-time; `fc_requests_every_worker_operation_has_exactly_one_shape` |
| The installed service admits an `fc.*` dispatch it should not, or the worker runs outside the dispatch job | The service checks the lease, executor, client, roots and paths and makes the job (slices 3 to 6); orceld runs the worker only in it | Slice 3 to 6 tests with the console harness and real jobs (`fc_worker_tests`); end to end with the installed service and these capabilities: **UNVERIFIED (founder run)** |

## 5. Residuals

1. **Other spec texts are not edited.** `SG-000097.json` and the unified spec section 4.15 still state the general
   rule (each action keeps its own approval without a standing approval). The SG-000132 amendment of 2026-11-19
   ("SG-000132 amendment: Full Control file writes covered by the lease, and the fc_* tool surface") governs for `write_text` and `mkdir` under a Full Control lease, and only for them.
2. **File writes inside the roots need no per-call approval** (by decision). An agent holding a lease can overwrite
   any text file up to 256 KiB inside the roots without a prompt, within the lease's time. There is no preview or
   hash binding (unlike Safe-mode `fs_write`), no Recycle Bin copy of the overwritten content, and no undo. The
   person's protection is the narrowness of the roots, the lease's expiry and Stop, and the refusal of Orcel's own
   state (section 1). Other programs' configuration inside the roots (a shell profile, a Git global configuration
   in a home-folder root) is not protected beyond the `.git` rule.
3. **Git changes have no `expected_head`.** The approval names the exact request (repository, paths, message or
   branch), not the repository's state (slice 4, "Approval binding").
4. **The approval is asked before `Authorize`.** As in slice 4: a covering lease is found first, so the person is not
   asked without one, but a service that then refuses (revoked in between) costs a prompt, not authority.
5. **The client reference is session-asserted, and a bound lease stops at an MCP restart** (slice 6 residuals 1
   and 2). For files, programs and Git a lease must be bound to the reference (section 2), so a restarted MCP server
   (a new session, a new reference) is refused until the person grants a lease to the new reference. `fc.status`
   shows the reference; the grant confirmation showing the client is still the service's text. The reference the
   approval dialog names is the same session-asserted one: it tells the person which client session asks, not
   which program is behind it.
6. **Long arguments are shortened in the dialog.** The dialog bounds its fields; the approval is bound to the digest
   over the whole operation, so a long argument list the person did not see in full is still the one that runs.
7. **The handle re-check has one small window left.** Since the slice 8 follow-up (branch
   `authority/fc-mkdir-relative`), `mkdir` creates nothing by path and reopens nothing by name: it opens the checked
   parent folder by its handle without following a reparse point at the parent's own name (and refuses one there,
   since the path checks resolved it to a plain folder), checks where that handle really is (inside the roots,
   outside `.git` and Orcel's state), creates the new folder relative to it (`NtCreateFile` with `RootDirectory`,
   `FILE_CREATE`, `FILE_DIRECTORY_FILE` and `FILE_OPEN_REPARSE_POINT`), and re-checks the handle that call returns,
   which is exactly the folder it created (`opened::make_folder`; test
   `fc_requests_mkdir_creates_relative_to_the_checked_parent_handle`). That closes both earlier cases: a name swapped
   back before the by-name reopen (the check passed while the folder was made elsewhere), and the converse, a racer
   moving a parent junction between `create_dir` and the reopen so that the re-check saw, and the cleanup deleted, a
   different empty folder that already existed. What remains: if the held parent folder itself is moved out of the
   roots (or into Orcel's state) after its check and before the create, the new folder is made there, refused by its
   re-check and removed by its own handle only while still empty (another writer could fill it first; it is then
   left, and the call is still refused). A file write is unchanged: it is checked and, if this call created it,
   removed through the one handle it writes with, and an existing file is opened without delete access and never
   removed. Outside Windows there is no re-check (no Full Control dispatch exists there).
8. **No MCP tool yet.** Until option B's slice 2, only a local process that writes orceld's request line can send
   these requests (the same exposure as every other local shape).
9. Slice 4 residuals (the program between check and start, window routes, Git's bundled programs) and slice 5 and 6
   residuals stand unchanged.

## 6. Not done; next steps

1. Option B slice 2: the MCP module (patterned on `apps/orcel-mcp/src/desktop.ts`), 14 contract entries with
   `remote: "local_only"` in `desktop_structured`, descriptions that say each tool needs a lease and which ones ask,
   the regenerated [docs/p16/TOOL_CONTRACT.md](../../../p16/TOOL_CONTRACT.md) and its tests. Done in
   [SG132_SLICE9.md](SG132_SLICE9.md).
2. Founder runs for this slice's UNVERIFIED rows: with the installed service and a lease granted to the client's
   reference, `fc.status`, a file write without a prompt, a program run with the Windows dialog (Yes and No), a Git
   commit with the dialog.
3. Slice 6 section 5 steps 1, 2 and 5 to 6 stand; its step 4 is done for orceld here and for MCP in step 1.

## Tests

At head (Windows, unelevated):

- `cargo test -p orceld --bin orceld -- fc_requests full_control_dispatch fc_worker`: 15 new `fc_requests_` tests,
  the 20 `fc_dispatch_` tests and the `fc_worker` tests. All pass. `cargo test -p orcel-provider-git --lib`: pass.
- `cargo test -p orceld --test ob04_shadow_scan --test ob07b_vault_scan`: pass.
- `cargo test -p orcel-policy remote_session`: pass. Other `orcel-policy` and orceld tests fail on this PC because of
  its AppData permissions (`InsecureAcl`, before this slice); CI runs them.
- `cargo clippy -p orceld -p orcel-policy -p orcel-provider-git --all-targets -- -D warnings` on Windows: clean. Linux and macOS builds and
  the workspace-wide clippy are left to CI.
