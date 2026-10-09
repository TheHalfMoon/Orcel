---
issue: https://github.com/TheHalfMoon/Orcel/issues/41
status: bounded-unit-regression-candidate
last_updated: "2026-10-09"
---

# Already-aborted workflow sleep: test-first narrow correction

## Distinct, reproducible defect

A JavaScript `abort` event is not delivered retrospectively to listeners registered after `AbortSignal.aborted` became `true`. The provided `sleep` workflow body previously registered a listener without first checking the signal state and always scheduled a durable timer. Under a pre-aborted input, the interruption promise never settles from that prior event, and the timer is started needlessly. This is an independent, source-backed edge case, **not** a demonstrated root cause for the intermittent PostgreSQL E2E `sleep.steer` timeout in issue #41.

On macOS with the repository-pinned Node 24.15.0, a new focused unit test intentionally **FAILED** on unchanged production code: `sleep()` had been invoked with `600000` milliseconds for an already-aborted signal; the test asserted the timer must not start. Test-only negative run: 1 failure / 2 filtered (no assertions or global test timeout suppressed). The first test-only run also reported a rejected unmocked promise, so the test was tightened to use a pending mocked sleep; the subsequent negative run still failed on the precise unnecessary `600000`-ms call with no unrelated unhandled rejection.

## Bounded correction and positive results

A four-line guard immediately after the workflow directive returns `{ interrupted: true }` if `ctx.abortSignal.aborted` is already true, before registering the listener or starting durable `sleep()`. A second unit regression exercises normal in-flight interruption after the timer starts, preserving the original `Promise.race` behavior. No general cancellation protocol, steering order, timer duration, SDK version, or session semantics were changed.

Mac-local pinned Node 24.15.0, focused unit suite (`packages/orcel/src/tools/provided/sleep.test.ts`): **4 passed / 0 failed**. The original normal-completion test continues to pass. The existing real Local World integration test `runs the framework sleep tool through the workflow tool path` **passed 1 / 1** (8 other tests filtered, normal 30-second case deadline unchanged) after `build:js` on the same Mac; a passing normal sleep does not exercise the pre-aborted workflow path end to end. This is not a PostgreSQL E2E result.

Further completed Mac checks: `pnpm --filter @orcel/orcel run typecheck` **PASS**, `node scripts/guard-invariants.mjs` **PASS**, touched-file `oxfmt --check` **PASS**, touched-file `oxlint` **PASS** (0 warnings/errors), and `git diff --check` **PASS**. Graft 0.21.1 genuine wiring build/check **PASS**, with the deep meaning layer not built. Jev CLI is installed but `jev noul` returned **Not logged in**; there is **no Jev model judgment**. Native Alibaba OCR/provider configuration is not established; a delegated scan is required before any qualification claim. Exact-head CI, an independent review, and post-main CI/Release remain merge gates.

## Limitations and production gate

- No claim that the prior PostgreSQL 120-second timeout was caused by this already-aborted ordering; follow the stage instrumentation from draft PR #42 and review server traces independently.
- No local Docker/PostgreSQL run has been observed on this Mac; CI must be reviewed for this exact candidate head.
- Respect issue #32's separate atomic-handoff NO-GO and issue #31's compiler diagnostic gate.
- Every commit must be signed and GitHub-verified with DCO. This Mac's known local SSH key was previously rejected by GitHub (`unknown_key`), so a new PR must remain **DRAFT / NO MERGE** until the independent identity/signature and exact-head gates are met.
