---
issue: https://github.com/TheHalfMoon/Orcel/issues/41
status: bounded-unit-regression-candidate
last_updated: "2026-10-10"
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

## Test-first abort-listener lifecycle correction on the authorized Mac (2026-10-10)

The same `executeSleepTool` workflow installed one `AbortSignal` listener with
`{ once: true }` and raced the durable timer against the abort promise. When
the **timer normally won**, the one-time listener remained registered on a
still-live signal because the signal had never emitted an abort event. The
listener and its callback/promise may be retained while the signal remains
reachable. This is a bounded lifecycle cleanup defect, **not** evidence that
this listener caused the historical intermittent 120-second PostgreSQL
`sleep.steer` timeout in issue #41. This grain does not assert a measured
memory leak or any effect on remote production workloads.

Added a test spying on a real `AbortController.signal` to assert exactly one
`addEventListener("abort", listener, { once: true })` followed by the **same
listener** being removed when a mocked durable timer resolves normally. The
existing interrupted-while-pending test gained the corresponding cleanup
assertion. **Canonical red phase:** with the exact parent-commit production
function restored, a new test selected by the repository's actual
`vitest.unit.config.ts` **FAILED 1/1** (4 cases filtered) because
`removeEventListener` was never called. **Green phase:** an explicit
`try/finally` removes that listener after the existing timer-vs-interrupt
`Promise.race` exits. The complete **same five-case unit file PASSED 5/5**
(0 failures) with official unit config, including pre-aborted, in-flight
interruption and successful wake assertions. This confirms only the
listener-lifecycle behavior exercised by the unit mock.

An earlier invocation of bare `vitest run` without `--config` used an
unsupported test-import resolution for this repository, resolving a built
copy of the workflow body; it failed even after the source fix. This was
**not** accepted as a valid post-change negative result. Both the preserved
canonical test-first failure and the final success explicitly used the
checked-in **unit Vitest config** and therefore exercised the intended
source. The extra diagnostic first-run failure was not hidden.

The existing pinned **Local World** integration case `runs the framework
sleep tool through the workflow tool path` also **PASSED 1/1**, 8 filtered,
normal 30-second test deadline untouched, with Vitest file duration
**35.88 seconds** under the repository integration config. Package `tsc -p
tsconfig.json --noEmit` and changed-file Oxlint **PASSED**. The in-process
integration is a normal sleep path, not a deterministic steering-race or
PostgreSQL hang reproduction; separately maintained PR #42 and issue #41
retain the previously documented Postgres stage evidence and intermittent
failure provenance.

No Workflow SDK upgrade, durable-timer cancellation change, token/claim
handoff change, global deadline extension, production topology migration or
claim of elimination of the `sleep.steer` flake is included. All review,
DCO/GitHub signature, independent Alibaba OCR and exact-head/post-main CI
gates still apply. Keep issue #41 open pending root-cause qualification.

### Tool qualification and current governance (2026-10-10)

The Mac-local actual Graft v0.21.1 wiring graph build covered **4,536
files, 24,717 nodes, and 61,798 edges**; `graft check` returned **OK**.
The deeper semantic layer was **not** built and no meaning-tier qualification
is claimed. Genuine authenticated Jev **1.13.0** returned `ok=true` and
`noul=0.04` when asked whether this listener cleanup evidence establishes
that the historic intermittent 120-second Postgres `sleep.steer` timeout was
fixed. This is advisory only; we retain **NO ROOT-CAUSE CERTIFICATION**.
Alibaba OpenCodeReview v1.12.13 delegation preview against the PR's old
exact head selected **one production source file out of four changed files**;
tests and Markdown are excluded by its default selection rules. There is **no
successful independent native OCR LLM review** for this candidate. `PStack`
was **not installed** and was not reported as used. Any new commit requires
its **own** exact-head GitHub CI and independent review; prior green checks
on `3b4642e` cannot be inherited and the PR remains DRAFT/NO MERGE.
