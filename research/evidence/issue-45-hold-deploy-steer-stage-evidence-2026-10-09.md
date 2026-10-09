---
issue: https://github.com/TheHalfMoon/Orcel/issues/45
status: diagnostic-candidate
last_updated: "2026-10-09"
---

# Bounded hold-deploy.steer timeout-stage diagnostics

## Observed failure, not resolved

In [PR #44](https://github.com/TheHalfMoon/Orcel/pull/44) exact-head PostgreSQL [E2E workflow 37976167047, attempt 1](https://github.com/TheHalfMoon/Orcel/actions/runs/37976167047/attempts/1), the existing `hold-deploy.steer` eval returned `The operation was aborted due to timeout` after approximately 120 seconds. The job recorded **29 passed / 1 failed / 1 skipped** of 31 evaluations and **261 passed gates**; the aggregate PostgreSQL gate failed. The separately implemented `sleep.steer` eval passed 6/6 in the same job. The PR that exposed this signal changed only a Local World force-claim integration research test and Markdown evidence, not these E2E files or production tool runtime. This does not establish whether the observed failure is a harness issue, server deadlock, scheduling delay or a true product race.

The current uninstrumented eval awaits creation of a session, start of a held `hold_deploy` tool call, the first `actions.requested` event, a `turnPolicy: "steer"` second turn, the original result and then the update result. Without stage boundaries, the failure does not tell us which operation consumed the deadline.

Read-only analysis of original failed GitHub artifact ID `11639367444` (run 37976167047 attempt 1) confirms JUnit `hold-deploy.steer` lasted **120.419 seconds**, while `hold-deploy.cancel` passed in 0.754 seconds and `sleep.steer` passed in 0.407 seconds. The timeout comes from existing `e2e/fixtures/agent-workflow-tools/evals/evals.config.ts` `timeoutMs: 120_000` via `AbortSignal.timeout` in the eval runner. The aborted eval captured **zero event rows** and an empty log array, but that does **not prove** zero server events: abort-time collection may be incomplete. No raw session identifiers or payloads from the artifact are included here. The same-SHA failed-jobs rerun, attempt 2, **PASSED** (`hold-deploy.steer` 6/6, `sleep.steer` 6/6, 30 passed / 1 skipped, 267 gates, 40.9 seconds). This remains an intermittent signal, not a confirmed root cause.

## Deliberately narrow change

Insert simple monotonic stage elapsed time through the existing eval `t.log` for: `session.create`, `initial-turn.start`, `hold-action.wait`, `steering-turn.start`, `initial-turn.result.wait`, and `steering-turn.result.wait`, including start/done boundaries. Preserve **all** request text, tool names, `turnPolicy`, assertions, original test deadline and production code. No retries, sleeps, bypasses or global timeout changes. Logs intentionally contain only the fixed stage name and integer monotonic elapsed milliseconds (no session/run IDs, private messages, secrets, raw model results or event payloads). On a repeat failure, the last observed stage may narrow the blocked await; this alone cannot prove causality.

A same-SHA rerun of the previously failed PR #44 workflow was requested separately from GitHub; record its result explicitly. A successful rerun does not cancel the original timeout signal.

## Limits and merge gates

- The diagnostic can be qualified with exact-head PostgreSQL CI and additional fresh, independent runs; do not claim a root cause, a flake cure, or improved latency from stage logs.
- Keep issue #45 **OPEN** while awaiting repeatable evidence. Issue #41 concerns the distinct `sleep.steer` case; issue #32 remains production successor **NO-GO**.
- Require authentic GitHub-verified SSH signature, DCO, formatting, invariant guard, actual available review tools, exact-head CI and normal merge only after genuine governance authorization. A native Alibaba OCR independent model review must **not** be inferred from a delegated preview (both touched paths are excluded by default).

## Completed Mac-local static qualification and advisory

With pinned Node v24.15.0, `pnpm --filter agent-workflow-tools exec tsc --noEmit`, changed-file Oxlint/Oxfmt, `node scripts/guard-invariants.mjs`, and `git diff --check` all **PASS**. A deterministic `executeTask` unit regression also confirms a completed stage log is preserved in `result.logs` and forwarded to `onLog` when an eval body remains pending until timeout; **27/27 existing-plus-new unit tests PASS**. The implementation of JUnit and saved-artifact reporters includes the same `result.logs`. This establishes runner log preservation in the isolated unit case, not that the future PostgreSQL trace will necessarily capture or explain the server state. Genuine Graft 0.21.1 indexed 4,536 files and 24,718 nodes with 61,800 edges (wiring-only, not deep semantic). Genuine Jev CLI `jev noul` against a short explicit test-only diagnostic-risk question returned `ok=true`, `model=jev-1.13.0`, `noul=0.87`; this is **probabilistic design triage**, not an independent detailed code review or correctness certificate. The Alibaba OCR native model review is **NOT RUN** because its default path rule excludes this E2E fixture and Markdown is unsupported. No public API credentials or secrets are used in this evidence.
