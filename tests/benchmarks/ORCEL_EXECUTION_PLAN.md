# BM-02: driving benchmark tasks through Orcel

The oracle runner and the pinned taskpack (#484, #486) solve tasks *without*
Orcel. This plan adds the layer that solves them *through* Orcel's real
public interface, so a report measures Orcel.

## Interface

The planner speaks orceld's stdio protocol, the same JSON-lines protocol the
MCP edge uses (`{version, request_id, client_session_id, workspace_id,
capability, operation, target, arguments}` → `{ok, result | error,
evidence}`). The runner starts the **real `orceld` binary** for each episode
with an isolated state directory and the episode's disposable workspace as
`ORCEL_WORKSPACE_ROOT`, and stops it at the end. Nothing is mocked.

## Approvals: three tiers, never faked

| Tier | What | Approval | Where it runs |
| --- | --- | --- | --- |
| A | Read-only tasks: observe the workspace with `fs.list`, `fs.read`, `fs.find`, `fs.stat`, `fs.read_range`, derive the answer, and meet Orcel's refusals (`PATH_ESCAPE`) | none needed: these operations need no approval | real `orceld` binary, every OS, CI |
| B | Mutating tasks (`fs.write`, `fs.move`, `fs.mkdir`, report tasks) | **orceld's real broker** with the scripted SOFT consent its own test builds use (`orcel-approval` `test-support`); reports label it `scripted-consent`, never a human approval | orceld's test build, in-process |
| C | GUI taskpack tasks (cua-driver-bench) | the real platform dialog, answered in an isolated GUI environment | needs an isolated VM per OS (not available yet) |

The shipped `orceld` binary has no scripted approval and this plan adds none:
a mutation sent to it raises the real approval dialog, which only a person can
answer. Tier B therefore runs where Orcel's own approved journeys run.

## Episode

1. A fresh `FileSession` workspace; the task's `setup_task` builds it.
2. `orceld` starts on it (isolated state, audit log kept as evidence).
3. The task's deterministic `orcel_plan(task, orcel)` observes and acts only
   through the client; every call is traced (capability, operation, target,
   outcome, latency, error code).
4. `orceld` stops; Tier A requires the workspace to be byte-identical to its
   state after setup (a read-only task that changed anything fails).
5. The task's `evaluate_task` scores the planner's answer.
6. A report row (`orcel-benchmark-report/1`, planner `deterministic` /
   `orcel-fs-planner`): status, a fixed observed code, latency, steps (Orcel
   calls), zero model calls.

Failure classes: `solved`, `unsolved`, `workspace-changed`, `orcel-refused`
(an unexpected refusal), `orcel-crash`, `orcel-timeout`, `<phase>-error`.
Each run also writes a JSONL trace and the orceld audit path.

## Slices

1. **Tier A (this slice):** the orceld client, the Orcel runner and CLI, a
   20-variant read-only Orcel task set, and a cross-OS CI test that runs the
   real binary on ubuntu, windows and macos and checks the report.
2. **Tier B:** an orceld test-build benchmark driver for the mutating tasks
   (`hello-file`, `report-rename`, report journeys) on the real broker with
   scripted consent.
3. **Tier C:** the cua-driver-bench GUI tasks in an isolated VM per OS, when
   one is available; until then recorded as blocked.
