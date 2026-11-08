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
   through the client. It sees the task's description and declared
   `metadata["inputs"]`, never the ground truth, and a client whose only
   member is `call`. Every call is traced (capability, operation, outcome,
   latency, error code; never the target or file contents).
4. `orceld` stops; Tier A requires the workspace to be byte-identical to its
   state after setup (a read-only task that changed anything fails), at
   least one Orcel call, and at least one orceld audit record per call.
5. The task's `evaluate_task` scores the planner's answer.
6. A report row (`orcel-benchmark-report/1`, planner `deterministic` /
   `orcel-fs-planner`): status, a fixed observed code, latency, steps (Orcel
   calls), zero model calls.

Failure classes: `solved`, `unsolved`, `workspace-changed`, `no-orcel-call`,
`unaudited`, `orcel-refused` (an unexpected refusal), `orcel-crash`,
`orcel-timeout` (one call, 15 s), `orcel-protocol` (a response that is not
JSON, is for another request, or is over 8 MiB), `timeout` (a phase, 30 s),
`<phase>-error`. Each run also writes a JSONL trace; orceld's audit records
are counted per episode, and its first stderr line stays in the trace (CI
logs print fixed codes only).

## Slices

1. **Tier A (#499):** the orceld client, the Orcel runner and CLI, a
   20-variant read-only Orcel task set, and a cross-OS CI test that runs the
   real binary on ubuntu, windows and macos and checks the report.
2. **Tier B:** `crates/orceld/src/bm02_tier_b_tests.rs`, 21 mutating
   variants (hello-file, overwrite, report-rename, mkdir, edit-config,
   remove-needs-presence, denied, stale-target, escape-refused) through
   orceld's own request entry (`handle_envelope`: profile gate, policy,
   dispatch, audit) and the real approval broker over its own ledger. Two
   things differ from the shipped orceld, and the report's planner version
   names both (`orcel-fs-mutation-planner` `1-scripted-consent-unjournaled`):
   the SOFT consent is scripted, and the SG-000120 mutation journal is not
   started in a unit-test build, so no journal records are written (the
   journal has its own tests). Each episode checks the whole workspace
   against the expected tree, every prompt's exact action and target, the
   refusal the plan ended on, one audit record per call and nothing changed
   outside the workspace. 12 variants are solved with approval and 9 are
   expected refusals (denied, stale target, path escape, removal without
   presence); the evidence prints the two counts separately. `fs.remove` is
   STRONG: with the `NoPresenceVerifier` stub the broker refuses it, which
   shows the fail-closed rule, not how Windows Hello, Touch ID or polkit
   behave; a solved removal is a founder acceptance test. The Rust CI job's
   `BM-02 evidence` step prints both tiers' per-case lines on every OS and
   schema-checks both reports.
3. **Tier C:** the pinned cua-driver-bench GUI tasks (`cdb-s02`,
   `cdb-s03`, `cdb-s04`: long multi-app tasks over mail, chat, calendar
   and a spreadsheet, each with reset `setup`/`verify` scripts, per-OS
   launch descriptors and an evaluator) through Orcel's real GUI
   interfaces. Never on a person's desktop.

   **Isolated environments (free).** Each episode runs on a hosted CI
   runner VM, which is disposable and has its own session:
   - `windows-latest`: orceld's UIA shapes (`uia.*`, `desktop.*`).
   - `macos-latest`: the native host; the hosted runner grants
     Accessibility and Screen Recording to the host only, as XP-08 records.
   - `ubuntu-latest`: the native host over AT-SPI under Xvfb with Openbox,
     as XP-08 already runs.

   A local disposable VM qualifies the same way; the founder's machines
   never do.

   **Slices:**
   - **C1, the harness.**
     - Fetch and verify the taskpack (`fetch-taskpack`, file by file).
     - Run the task's reset `setup` and `verify` into a fresh workspace.
     - Launch the app from the task's own `launch.<os>.json`.
     - Drive it only through Orcel (orceld request entry or the native
       host), with the real approval broker.
     - Score with the task's evaluator, then run the reset `verify`.
     - Capture the audit and a trace of call shapes, outcomes and latency
       (no screenshots or text in reports).
     - Tear down: the app's process tree is gone and the workspace is
       removed.
     - Report rows use `orcel-benchmark-report/1`.
   - **Done so far.** C1's no-op baseline (#509): reset and evaluator on
     every OS. C2a (`orcel_bench/tierc_gui.py`, `tierc-observe`): on the
     Rust job's Windows runner, cdb-s02's three Electron surfaces (mail,
     chat, calendar) launched from the task's own descriptor, each window
     found and observed only through the real orceld's read-only UIA shapes,
     the evaluator still rejecting the untouched workspace, and every process
     tree stopped with the windows confirmed gone through orceld. Nothing is
     clicked or typed and no approval is involved.
   - **C2, scripted-plan qualification.** A deterministic per-task plan
     written for these three tasks drives C1 end to end, to prove the
     harness, interfaces, approvals, reset and evaluation. Its report is
     labelled `scripted-plan` with `scripted-consent` and is **not** an
     agent result: it shows Orcel can carry the task, not that an agent
     can solve it.
   - **C3, agent runs (blocked).** Solving these tasks needs a capable
     planner model. Paid inference is excluded (zero cost), and the local
     d1 model is a 600M advisory classifier, not a planner. Agent results
     wait for a founder decision on a model and budget, or a free local
     model that can be qualified.

   **Consent.** Approvals in C1 and C2 come from the real broker with
   scripted SOFT consent, labelled in the report as in Tier B. Real human
   consent is never scripted. On hosted macOS the runner image's own
   pre-configured Accessibility and Screen Recording grants are used, as
   XP-08 records. Orcel never scripts, forges or pre-grants an OS
   permission, and never runs on a person's machine. A runner where a
   prompt would still appear refuses the step.
