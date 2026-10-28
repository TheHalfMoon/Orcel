# F4 slice 5 proposal: a local, task-scoped, authority-reducing stop

**Status: PROPOSAL ONLY.** This document adds no method, tool or state. It
does not amend the code-identity rule in `protocol/ORCEL_APP_API_1.md`
("The first method that changes state or carries authority must add a
first-party code requirement before it ships"). Shipping any stop surface
needs one of the founder decisions recorded on #446. **Takeover is out of
scope and treated separately (section 8).**

## 1. What stop means

Stop ends one report task (SG-000126) so that it can never write. It:

- applies to one task, in one workspace, of the current orceld run;
- only removes the ability to commit; it never grants, approves or
  writes anything, and never deletes a report already written;
- is final: a stopped task is never resumed or reopened;
- is idempotent: stopping a stopped task answers with the same result.

## 2. Kernel state machine (`crates/orceld/src/report_task.rs`)

Today: `Observed → Proposed → (ApprovalDenied | Committing) → (Verified |
VerificationFailed | Failed)`, plus `Stale`.

Proposed:

- A new final state `Stopped` (`"stopped"`). `is_final()` includes it, so
  `open_task` already refuses every later `preview` and `commit` with
  "the task is finished (stopped)".
- Stop is allowed from `Observed`, `Proposed` and `ApprovalDenied`.
- Stop is refused from `Committing` ("the task is committing; it will
  finish or fail on its own") and from every final state other than
  `Stopped`, which answers idempotently.

### The races this must close

Every request copies the task in `open_task`, does its work without the
registry lock, and then changes the state in `tasks.update(..)`
**unconditionally**. A stop that lands in that window would be overwritten.
These are the writers of `task.state` that can run while a task is
stoppable:

| Writer | Window | Effect if a stop lands in it |
|---|---|---|
| `preview` → `Proposed` | after `open_task` and `check_current` | stop erased; a later commit is allowed |
| `commit` → `Committing` after approval | the approval prompt, which can take minutes | stop erased; the approved report is written |
| `commit` → `ApprovalDenied` on denial | the approval prompt | stop erased |
| `blocked()` → `Stale` (preview and commit) | `check_current` | stop erased from state and history (still final, so no authority gain) |

Writers that run only from `Committing` (the reopen path,
`destination_exists`, `Failed`, `Verified`) are unaffected, because stop is
refused in `Committing`.

The fix is one primitive and four uses:

1. `TaskRegistry::transition(task_id, from: &[TaskState], to, kind,
   outcome) -> Transition`, which runs under one registry lock acquisition.
   It applies the change, records the step and publishes `task.updated`
   only if the task exists and its current state is in `from`. Otherwise
   it returns `Transition::Refused(found)`, or `Transition::Missing` if the
   task is gone.
2. Preview: `transition(id, &[Observed, Proposed, ApprovalDenied],
   Proposed, ..)`, carrying the new proposal in the same change.
3. Commit after approval: `transition(id, &[Proposed, ApprovalDenied],
   Committing, ..)`. **Any** other outcome means write nothing:
   - a found `Stopped`;
   - a found `Committing` or `Verified` (a concurrent commit of the same
     task won);
   - `Missing` (the task was evicted while the prompt was open; `insert()`
     evicts finished tasks).

   In each case the approval token stays spent, because it is single use.
   The journal intent is closed as `abandoned` (the effect never started,
   as `ReportJournal::abandoned` records today). The caller gets
   `TARGET_STALE` "the task was stopped" or "the task changed during
   approval".
4. Commit on denial: `transition(id, &[Proposed, ApprovalDenied],
   ApprovalDenied, ..)`, so a denial never overwrites `Stopped`.
5. `blocked()` stale branch: `transition(id, &[Observed, Proposed,
   ApprovalDenied], Stale, ..)`, so a stop is never rewritten as `Stale`.
6. Stop itself: `transition(id, &[Observed, Proposed, ApprovalDenied],
   Stopped, "stop", "stopped")`.

The check and the change happen under one lock acquisition, so no window
remains between "still stoppable" and the state change.

### Journal (SG-000120)

- A commit that finds the task stopped, changed or gone after approval
  closes its intent as `abandoned` (outcome `stopped` or `task_changed`).
  Resume classification already treats an abandoned commit as "not run",
  so it needs no new outcome.
- Task state reaches the journal only through the best-effort
  `snapshot()`, and the proposal adds no per-task stop line. Durability is
  not needed for safety: on restart `restored_task` turns every task that
  is not final (or `ApprovalDenied`) into `Failed`, so a stop lost in a
  crash still cannot lead to a commit.
- If "resume reports `stopped`" is wanted, the snapshot carries
  `stopped`. An older binary reads an unknown state as `Failed` through
  the `from_str` fallback, which is also final.

## 3. Surfaces: the choice is the founder's

| Surface | What it needs | Notes |
|---|---|---|
| A. App API method `task.stop` (Control Room) | **Founder decision**: option 1 (signing, then a publisher check per the code-identity rule) or option 2 (a governed amendment admitting this one authority-reducing method with peer identity only) | The natural place for the timeline's Stop button |
| B. Local MCP tool `report_stop` | A governed MCP contract change (additive tool) | An agent could stop its own task; not a user control |
| C. orceld-local CLI (`orcel task stop <id>`) through the stdio entry | Same governance as B; same-user only | Useful for tests and recovery |
| D. None in F4 (option 3) | Record stop and takeover as an open F4 gate | The kernel work below can still land, unexposed and tested |

**Recommendation for engineering (not a decision):** land the kernel
state, transition and journal work (section 2) with tests first. It is
unexposed and reachable only from tests, and it closes the race before any
surface exists. Then add surface A behind whichever founder option is
chosen.

## 4. Security review

| Threat | Analysis | Treatment |
|---|---|---|
| Stop used to gain authority | Stop only removes the ability to commit; it never mints approvals, writes or deletes | By construction; tests assert nothing is written after a stop |
| Stop raced against an approval | Closed by the conditional transition (section 2) | The test "approval granted after stop writes nothing" |
| Stop raced against preview or a stale check | Both writers become conditional transitions | Tests 9 and 13 |
| Two concurrent commits of one task | Both can pass `open_task` and prompt; only one transition to `Committing` succeeds | Test 10: at most one write |
| Same-user process stops a task (surface A under option 2) | Denial of progress, not an authority gain; the same user can already kill orceld | Residual risk the founder accepts under option 2; option 1 narrows it to signed clients |
| Cross-workspace or cross-run stop | `open_task`-style lookup by id **and** workspace **and** run seed | Refused `TARGET_STALE`, as for preview and commit |
| Replay or spoofed stop | Idempotent and final; replay changes nothing | No nonce needed; the audit records every attempt |
| Stop during `Committing` | The write is in flight; interrupting it could leave a partial file | Refused; create-only writes plus the independent checker cover the outcome |
| Stop lost in a crash | Not durable before it is answered | Safe without durability: restart turns every non-final task into `Failed` (section 2) |
| Information leak through stop errors | Errors name states, not contents | Same error vocabulary as `open_task` |
| UI spoofing (a fake Stop that does nothing) | The Control Room shows the state from `task.updated`, not its own optimistic state | The timeline reflects the kernel only |

## 5. Tests to write (kernel slice)

1. Stop from `Observed`, `Proposed` and `ApprovalDenied` gives `Stopped`;
   `preview` and `commit` are then refused; nothing is written.
2. Stop during an open approval prompt, then the scripted SOFT answer
   `Approved`: nothing is written, the token is spent (a second consume
   fails), and the journal intent is `abandoned` (outcome `stopped`).
3. A denial after a stop leaves `Stopped`.
4. Stop during `Committing` is refused, and the commit completes or fails
   as before.
5. Stop is idempotent; stopping an unknown task, another workspace's task
   or an earlier run's task is refused `TARGET_STALE`.
6. Crash after the stop line: the resume summary reports `stopped`.
7. `task.updated` publishes the `stopped` state and its step.
8. Property test: random interleavings of stop, preview, commit, approve
   and deny never end with a written report for a task whose stop
   succeeded.
9. A stop between preview's `open_task` and its state change: the task
   stays `Stopped`, and a later commit is refused.
10. Two concurrent commits of one task, one prompt approved and one
    refused: at most one write, and the loser's intent is `abandoned`.
11. The task is evicted while its commit prompt is open; approval then
    writes nothing and the intent is `abandoned`.
12. A stop while `check_current` runs after approval is refused, because
    the task is already `Committing`.
13. A stale check after a stop leaves `Stopped`.
14. A stop of an evicted task answers `TARGET_STALE`. This is acceptable:
    it is final and nothing is left to stop.

## 6. Acceptance (kernel slice)

All tests above on Windows, macOS and Linux CI at the exact head. No
change to `ORCEL_APP_API_1.md` methods, MCP tool lists or approval classes.

## 7. Founder decisions needed

1. Which option on #446: signing (1), a governed amendment for this
   method (2), or no stop surface in F4 (3).
2. If 1 or 2: whether surface A (Control Room) is the only surface, or B
   and C are also wanted.
3. Whether a stop may cancel an open approval prompt in the OS dialog
   itself, beyond refusing the commit after it. Cancelling the dialog
   would be platform-specific UI work.

## 8. Takeover (separate)

Takeover means the person continues a task by hand from the point it
reached. It is not authority-reducing: it hands the task's context (its
observed sources and proposal) to another actor, and it may need its own
approval semantics (who may take over, and whether the original approval
scope carries over). It therefore needs its own design, its own security
review and its own governance step. Stop must not be extended into
takeover.
