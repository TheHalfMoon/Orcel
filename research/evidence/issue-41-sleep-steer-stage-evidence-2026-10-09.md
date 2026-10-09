---
issue: https://github.com/TheHalfMoon/Orcel/issues/41
status: diagnostic-candidate
last_updated: "2026-10-09"
---

# Issue #41: bounded `sleep.steer` stage diagnostics (2026-10-09)

## Observed baseline and limit

- Base `main`: `961befc1547cf7e947ad33e915c33d52c38e6977`.
- PostgreSQL E2E run `37948775561`, first attempt, reported an abort due to timeout during the existing `sleep.steer` evaluation; the same commit's rerun succeeded. Neither outcome establishes the cause of the intermittency.
- `e2e/fixtures/agent-workflow-tools/evals/evals.config.ts` sets a **120,000 ms** eval timeout. `packages/orcel/src/evals/runner/execute-task.ts` makes that deadline an `AbortSignal.timeout(timeoutMs)` and races the evaluation against that signal via `runUntilAborted`. A nested client or transport operation may also fail; the summary alone did not reveal which operation timed out.

## Diagnostic change

Only the existing evaluation fixture gains `t.log()` records. `performance.now()` provides monotonic elapsed milliseconds from eval entry; a fixed stage name is logged **before and after** each awaited session create, initial turn start, sleep-action event wait, steering turn start, and turn-result wait. The last `*.start` / `*.wait` without a corresponding `*.done` / `*.observed` identifies the last unfinished await at deadline. These bounded messages contain no session IDs, prompts, event payloads, credentials, or absolute timestamps.

The existing tool-call predicates, assertions, steering action, result-await order, local timeout, and production runtime are untouched. This adds observability, **not** a timeout adjustment, deadlock fix, latency improvement, or causal proof. The evaluation runner captures `t.log` lines in task artifacts, and `.github/workflows/e2e-postgres.yml` already uses `orcel eval --strict --verbose`, making them visible in runner logs.

## Mac-local verification and limitations

- Authorized execution device: `macbook` (macOS/Darwin); a clean clone of the exact base was used, without touching other checkouts.
- pnpm `12.7.0`: frozen lockfile, supply-chain policy verification, workspace installation completed. No lockfile modification.
- `pnpm exec oxfmt --check e2e/fixtures/agent-workflow-tools/evals/sleep.steer.eval.ts`: PASS.
- `pnpm exec oxlint e2e/fixtures/agent-workflow-tools/evals/sleep.steer.eval.ts`: PASS (0 warnings, 0 errors).
- `pnpm guard:fixtures`: PASS; `git diff --check`: PASS.
- Docker daemon was not available on this Mac. **No local PostgreSQL E2E execution, timeout reproduction, or passing `sleep.steer` assertion is claimed.**
- Jev, Graft, PStack, and native Alibaba OpenCodeReview CLI were not found on the Mac PATH; no genuine execution or independent native review is claimed. GitHub's delegated OCR and exact-head CI must be observed independently after PR creation.

## Follow-up gate

Run clean PostgreSQL E2E against the immutable PR head repeatedly, preserving failed attempts and the last emitted stage. Correlate the failed stage with server logs and Workflow tool-abort ordering before proposing a root-cause fix. Keep #41 open until cause and stability are evidenced; keep #31 and #32 separate. A green retry alone is not a fix. No production-performance claim is authorized.
