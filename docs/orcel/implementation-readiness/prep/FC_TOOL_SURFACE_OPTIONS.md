# Full Control tools for files, programs and Git: options for the founder

Status: decided. The founder chose option B on 2026-11-19 (section 8). Docs only; nothing here changes code.
Written 2026-11-19 against `main` at `f22247a3` (#828).

## 1. What is built, and what is missing

"Full Control" is the mode in which the person grants Orcel a time-limited **lease** (a signed permission issued by the
Orcel authority service after Windows Hello) to act with the person's own rights inside folders the person names at
grant (the lease's **roots**).

Built (SG-000132 slices 1 to 7, merged through #828):

- `orceld`'s Full Control dispatcher (`crates/orceld/src/full_control_dispatch.rs`) and the `orceld fc-worker` child
  process (`crates/orceld/src/fc_worker.rs`). Every operation runs in the worker, inside a Job Object the service
  creates, so Stop kills it.
- 13 worker operations (`WorkerOp`): files `stat`, `list`, `read_text`, `write_text`, `mkdir`; programs `run`; Git
  `git_status`, `git_diff`, `git_log`, `git_add`, `git_unstage`, `git_commit`, `git_branch_create`.
- A per-action approval hook (`ActionApproval`) that asks before `run` and the four Git changes
  (`WorkerOp::needs_approval`). Its production version, the Windows approval dialog, is not wired yet
  ([SG132_SLICE4.md](SG132_SLICE4.md) section 3).

Missing: **no MCP tool and no request capability reaches the worker.** An agent cannot use any of this. The slices
stop here on purpose: the specs say what the operations must do, not what the tools are called or how they look
([SG132_SLICE4.md](SG132_SLICE4.md) section 6 step 1; [SG132_SLICE5.md](SG132_SLICE5.md) next step 4;
[SG132_SLICE6.md](SG132_SLICE6.md) residual 2 and next step 4). That is the decision this brief asks for.

## 2. Spec rules every option must keep

These are quoted or closely paraphrased; nothing below adds a rule.

| Rule | Source |
| --- | --- |
| "A lease alone never replaces an approval; only a standing approval for the same client, task and scope does." | `.specgrain/specs/SG-000132.json`, invariants |
| Without a standing approval, "each action keeps its own approval". | [UNIFIED_INTEGRATION_SPEC.md](UNIFIED_INTEGRATION_SPEC.md) section 4.15 |
| Every new process (and every shell input or termination) needs Full User **and** a fresh SOFT approval bound to the exact action, unless a standing approval covers it. | `.specgrain/specs/SG-000096.json`, acceptance A3 and A13; scope include |
| "With no lease, every Safe request and response is unchanged." "Any change to Safe-mode rules or approvals" is out of scope. | `SG-000132.json`, invariants; scope exclude |
| No remote use: "Remote Full Control (SG-000105)" and "Remote use (SG-000105)" are excluded; SG-000105 must not ship before the grant window and Event Log scope record are qualified. | `SG-000132.json` scope exclude and successor `remote`; `SG-000097.json` scope exclude; spec section 4.13 |
| Standing approvals never cover remote callers. | Spec section 4.15; `SG-000096.json` A13 |
| No filesystem action outside the lease's roots; Safe-mode path rules not weakened; deletion to the Recycle Bin unless permanent deletion is separately approved. | `SG-000097.json`, invariants |
| Approvals are Windows dialogs, never an in-app control. | Founder decision 2026-11-18 (project memory "Approvals stay with Windows"); `full_control_dispatch.rs` header |

**SOFT** approval is the ordinary Windows "Allow / Deny" dialog for one action. **STRONG** adds Windows Hello.

## 3. Why the existing Safe-mode tools do not fit as they are

The Safe-mode tools (`fs_*`, `git_*`, `process_spawn` in `apps/orcel-mcp/src/server.ts`, `fs_mutation.ts`,
`git_mutation.ts`; contract in `tool_contract.ts`, generated as [docs/p16/TOOL_CONTRACT.md](../../../p16/TOOL_CONTRACT.md))
differ from the worker in ways that matter:

| | Safe-mode tools | Full Control worker |
| --- | --- | --- |
| Where | one trusted workspace, **relative** paths, `workspace_id` | any folder inside the lease's roots, **absolute** paths |
| File write | `fs_write_preview` then `fs_write` bound to the current SHA-256; SOFT | `write_text { path, text, create_new }`, no hash; no approval today |
| Git change | needs `expected_head`; SOFT | no `expected_head`; SOFT via `ActionApproval` |
| Program | `process_spawn`: a **registered** executable, `stdin_policy`, `network_class` | `run`: any `.exe` inside the roots, argv only, at most 50 s and 64 KiB output |
| Remote | remote-mappable (`orcel.read`, `orcel.write`, `orcel.execute` OAuth scopes) | must be local only (section 2) |

`tool_contract.ts` gives each tool name exactly one entry (one approval class, one remote rule). One name cannot be
both remote-mappable in Safe mode and local-only in Full Control without a second contract table, which is what
`browser_full` did for its four shared names (`BROWSER_FULL_CONTRACT`; "the two profiles never serve each other's
form", `crates/orceld/src/profile_gate.rs`).

## 4. Options

All options share: the tool forwards one request to `orceld`; `orceld` passes it to `run_in_worker` with the calling
client's reference as the principal (as `desktop_gate` does since slice 6); refusals arrive as the existing MCP error
envelope (`isError: true`, `{ "error": { "code", "message" } }`, `apps/orcel-mcp/src/result.ts`) with existing
`FailureCode`s only (`crates/orcel-contracts/src/error.rs`):

| Situation | Code the client sees |
| --- | --- |
| No active lease, or the lease does not include this executor (files; or programs and Git, which need `shells`) | `LEASE_REQUIRED` / `CAPABILITY_DENIED` |
| Lease revoked, stopped or expired (also between authorize and start) | `LEASE_INVALID` |
| Path outside the roots, a link, a hard link, a `.git` write | `PATH_ESCAPE` / `CAPABILITY_DENIED` |
| The person said No, or the dialog could not be shown | `APPROVAL_DENIED` / `APPROVAL_UNAVAILABLE` |
| Service not installed or not answering (later, once WP1-12 checks the indicator heartbeat: indicator not alive) | `AUTHORITY_UNAVAILABLE` (later also `INDICATOR_UNAVAILABLE`) |
| Program timed out; output over the limit | `PROCESS_TIMEOUT` / `OUTPUT_LIMIT` |
| Bad arguments | `INVALID_REQUEST` |
| A remote caller | `REMOTE_SESSION_INACTIVE` (no remote lease) or the tool is simply not served remotely |

### Option A: reuse the Safe-mode tool names, switched by the lease

Same 13 names (`fs_stat`, `fs_list`, `fs_read`, `fs_write`, `fs_mkdir`, `process_spawn`, `git_status`, `git_diff`,
`git_log`, `git_stage`, `git_unstage`, `git_commit`, `git_branch_create`). Each gains an optional
`mode: "safe" | "full_control"` (default `safe`); with `full_control` the path is absolute and `orceld` routes to the
worker.

- Approval: Safe classes as today; under `full_control`, `process_spawn` and the four Git changes SOFT per action;
  reads none; writes per decision question 2.
- Remote: the same names are remote today, so every `full_control` call needs a new remote refusal inside each
  handler and a second contract table.
- Risks: the highest. It changes the published schema of 13 Safe tools (the spec puts Safe changes out of scope);
  one bug in the switch could send a Safe or remote call to the worker; the argument meanings differ (relative vs
  absolute, preview hash, `expected_head`, registered vs any program), so one name would mean two different tools.
- Effort: large. Contract table split, remote scope table, parity inventory, golden Safe pairs re-qualified;
  about three slices.

### Option B: separate `fc_*` tools, one per worker operation (recommended; CHOSEN by the founder 2026-11-19)

13 new local-only tools, plus `fc_status` (section 8). Capability per family (`fc.fs`, `fc.process`, `fc.git`); the operation is the `WorkerOp`
name, which `run_in_worker` already requires. Paths are absolute and must be inside the lease's roots.
`workspace_id` is optional and only fills the request envelope, as the `desktop_*` tools do.

| Tool | Arguments (limits are the worker's) | Approval |
| --- | --- | --- |
| `fc_fs_stat` | `path` | none (lease) |
| `fc_fs_list` | `path`, `max_entries` 1..1000 | none (lease) |
| `fc_fs_read` | `path`, `max_bytes` 1..262144 | none (lease) |
| `fc_fs_write` | `path`, `text` (at most 256 KiB), `create_new` | none (lease; founder decision 2026-11-19) |
| `fc_fs_mkdir` | `path` | none (lease; founder decision 2026-11-19) |
| `fc_process_run` | `program` (absolute `.exe` in the roots), `args` (at most 64), `cwd`, `timeout_ms` 1..50000, `max_output_bytes` 1..65536 | SOFT, every call |
| `fc_git_status` | `repository` | none (lease) |
| `fc_git_diff` | `repository`, `staged` | none (lease) |
| `fc_git_log` | `repository`, `max_count` 1..100 | none (lease) |
| `fc_git_stage` | `repository`, `paths` (operation `git_add`) | SOFT, every call |
| `fc_git_unstage` | `repository`, `paths` | SOFT, every call |
| `fc_git_commit` | `repository`, `message` | SOFT, every call |
| `fc_git_branch_create` | `repository`, `branch` | SOFT, every call |
| `fc_status` | none | none (read-only; shows the active lease's executors, roots and expiry and this client's reference; added by founder decision 2026-11-19) |

"None (lease)" means the lease covers it and the person is not asked, matching the Safe-mode read tools, which ask
nothing (`approval: "none"` in `tool_contract.ts`). Every call, asked or not, still gets the service's own
authorize and audit record first (`SG-000132.json` invariants).

- Remote: every entry `remote: "local_only"`, so no OAuth scope maps it and the `core` (remote) profile never lists
  it; `orceld` would also refuse a remote request to `fc.*` before dispatch (a new check, part of slice 1 below).
- Where it appears: decision question 3.
- Risks: 13 more tools in the list (models may pick `fs_write` when they meant `fc_fs_write`; the descriptions say
  which needs a lease); the tools fail with `LEASE_REQUIRED` until the person grants one. Git changes have no
  `expected_head` (the approval names the exact request, not the file contents; [SG132_SLICE4.md](SG132_SLICE4.md),
  "Approval binding").
- Effort: medium, about two slices: (1) `orceld` request capabilities, the production `ActionApproval` over the
  Windows approval dialog, the remote refusal and contract tests (already listed as the next step in
  [SG132_SLICE4.md](SG132_SLICE4.md) section 6); (2) the MCP module (patterned on `apps/orcel-mcp/src/desktop.ts`),
  contract entries, the regenerated TOOL_CONTRACT.md and its tests.

### Option C: a minimal read-only set first

The six read tools of option B only: `fc_fs_stat`, `fc_fs_list`, `fc_fs_read`, `fc_git_status`, `fc_git_diff`,
`fc_git_log`. No approvals involved; local only; same refusals.

- Risks: the lowest. But it does not move journey J-3b ("edits files across an authorized drive", spec section 10
  table), and the approval dialog wiring is deferred, so the riskiest part ships later.
- Effort: small, about one slice; option B's remainder follows as a second.

## 5. Recommendation: option B

1. **It keeps Safe mode untouched.** No existing tool's schema, approval or remote rule changes, which is what
   `SG-000132.json` requires ("with no lease, every Safe request and response is unchanged").
2. **Local-only is structural, not a runtime switch.** A tool that is `local_only` in the contract is never offered
   remotely and has no OAuth scope; option A would rely on a check inside every shared handler.
3. **It matches what is already built.** One tool per `WorkerOp`, so the tool, the approval digest and the audit
   record all name the same thing; the dispatcher already requires the operation name.
4. **It follows a pattern the project already ships.** `desktop_input_execute` is a lease-gated, local-only tool with
   its own name that refuses without a lease; `browser_full` added its own tools rather than switching old ones.
5. **It is the only option that can carry J-3b's file editing** without first rewriting the Safe contract.

If the founder prefers the smallest first step, option C is option B's first half, not a different design.

## 6. Decisions needed (at most 4)

1. **Which option?** Pick one: A (reuse Safe names), **B (separate `fc_*` tools, recommended)**, or C (read-only
   `fc_*` tools first, the rest later).
2. **Should Full Control file writes (`fc_fs_write`, `fc_fs_mkdir`) ask a fresh Windows approval on every call until
   standing approvals (WP1-14) exist?** Yes / no. Recommended: **yes**. The specs say a lease alone never replaces
   an approval and each action keeps its own (section 2); Safe-mode writes ask SOFT; today's dispatcher does not ask
   for file writes ([SG132_SLICE4.md](SG132_SLICE4.md) section 3), so "no" would make Full Control writes ask less
   than Safe-mode writes.
3. **Where should the `fc_*` tools appear?** Pick one: **in the normal local tool list (`desktop_structured`), like
   `desktop_input_execute`, refusing until a lease exists (recommended)**, or only when the local MCP configuration
   selects a new `full_control` profile. A local client serves one profile at a time
   (`localProfileFromConfig`), so a separate profile could not be combined with `browser_full`.
4. **Add a read-only `fc_status` tool** that shows the agent the active lease's scope (executors, roots, expiry) and
   this client's reference, so the person can name that client at grant? Yes / no. Recommended: **yes**. Without
   it, the client cannot learn its reference before a grant, and a lease bound to a client stops working when the
   MCP server restarts with a new session ([SG132_SLICE6.md](SG132_SLICE6.md) residual 2). It changes nothing and
   grants nothing.

## 7. Not in this decision

Interactive shells (SG-000096 ConPTY sessions), app launch and close, process listing and termination, copy, move,
rename, delete to the Recycle Bin and large or binary files (SG-000097) need worker operations that do not exist yet;
they get tools when they are built, under whichever naming the founder picks here. Standing approvals are WP1-14.

## 8. Founder decision (2026-11-19)

The founder answered the four questions of section 6 on 2026-11-19 (relayed to this engineering session the same
day):

1. **Option B**: separate `fc_*` tools.
2. **No**: Full Control file writes (`fc_fs_write`, `fc_fs_mkdir`) are covered by the lease, with no per-call Windows
   prompt. This is a founder decision that knowingly departs from the SG-000132 invariant "a lease alone never
   replaces an approval", for these two file operations only. `fc_process_run` and the four Git changes
   (`fc_git_stage`, `fc_git_unstage`, `fc_git_commit`, `fc_git_branch_create`) keep a SOFT approval on every call.
3. **The normal local tool list** (`desktop_structured`), refusing with `LEASE_REQUIRED` until a lease exists.
4. **Yes**: add the read-only `fc_status` tool (the active lease's executors, roots and expiry and this client's
   reference; no approval).

Recorded as an amendment in `.specgrain/specs/SG-000132.json` (`amendments`, 2026-11-19). Each covered write still
has the service's authorize and audit record first, stays inside the lease's roots and is ended by Stop, revoke and
expiry. The next step is option B's two slices (section 4), with `fc_status` in the MCP slice.
