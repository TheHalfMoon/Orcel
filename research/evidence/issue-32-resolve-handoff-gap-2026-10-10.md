---
issue: https://github.com/TheHalfMoon/Orcel/issues/32
status: bounded-production-hardening-not-successor-admission
last_updated: "2026-10-10"
scope: current-driver-child-session-inbox-resolution
---

# Fail-closed lookup during existing deployment-handoff gaps

## Observed production control-flow gap

`resumeSessionInbox` already checked `sessionHandoffMarkerToken(token)` when the
physical inbox was temporarily missing. Its companion `resolveSessionInbox`
looked up only the physical inbox and immediately tried the legacy session
lookup after `HookNotFoundError`. `createWorkflowRuntime.resolveContinuation`
turns that missing-hook error into `undefined` for the channel, which could
mistake a temporarily transferring existing session for an absent session.
This is a bounded **existing driver/child handoff lookup** problem, not a
claim that Orcel has implemented atomic successor ownership transfer.

Further, the shared retry helper checked its deadline _before_ looking for a
handoff marker. A still-present marker after the 5,000ms window therefore
looked identical to a nonexistent session when the caller fell through to
legacy lookup. Such an ambiguous handoff must fail closed, not invite a
replacement session or possibly duplicated processing.

## Scope of the fix

- Give `resolveSessionInbox` the same 5,000ms maximum marker-aware retry path
  used for inbox delivery, without retrying non-`HookNotFoundError` failures.
- When an active marker is still present at the retry-window boundary, throw
  `SessionHandoffPendingError`, which is **not** a `HookNotFoundError`.
  The existing caller therefore does not translate this into `undefined`
  or an absent session. The error message contains no tokens or session IDs.
- Apply the shared marker/deadline check to `resumeSessionInbox` as well, so
  delivery does not wrongly attempt the legacy path after the window.
- Preserve existing handling of truly missing markers and legitimate legacy
  inboxes. Do not change the SDK, public session/stream identity, accepted
  payload formats, retry window/interval, timer defaults or driver/child
  production topology.

## Reproducible Mac test-first evidence

Authorized device: **`macbook`**, Darwin, Node 24.15.0, original repository
`TheHalfMoon/Orcel`, starting from canonical `main`
`961befc1547cf7e947ad33e915c33d52c38e6977`. Work in an isolated Git
worktree with offline frozen pnpm dependencies; **no Windows access, paid
service or Workflow SDK upgrade**.

Two new focused unit tests were first run **against the unchanged production
implementation** under the checked-in `vitest.unit.config.ts`; the run
**FAILED 2/2** as expected: one temporary-hook gap incorrectly fell back to
legacy lookup and raised `HookNotFoundError`; the other still-marked timeout
returned `HookNotFoundError` instead of a fail-closed pending error. No test
assertion or deadline was relaxed to obtain a pass. After the bounded
production fix, the **entire unit file PASSED 8/8**, zero failures, original
test timeout, file duration **3.86s**. Its three new cases cover lookup
recovery, expired resolution failure, and expired delivery failure. Unit
mocks only control the low-level SDK `getHookByToken`/`resumeHook` functions;
no real concurrency or crash is claimed from them.

The unchanged existing pinned **Local World** integration test
`hands off an alias-addressed session and keeps the alias resolving through
the gap` initially **PASSED 1/1**, 4 filtered, original deadline unchanged,
Vitest file duration **41.56s** (test **14.47s**). Next, the **same test**
was strengthened by initiating `workflowRuntime.resolveContinuation(alias)`
from the same real mid-handoff `hook_disposed` interception as the gap
delivery, and asserting that it resolves to **the original anchor run's
public `sessionId`** (not `undefined`). This independently exercises the
public runtime resolver during the actual hook handoff, not only a mocked
helper. The expanded **real pinned Local World** integration case again
**PASSED 1/1**, 4 filtered, unchanged per-case deadline, file duration
**29.83s**. New unit tests cover the forced expiration branch; no actual
multi-process or arbitrary-interleaving guarantee is claimed.

Source-package `tsc -p tsconfig.json --noEmit` and changed-file Oxlint
**PASSED** for the original implementation/unit-test change. Source Graft
0.21.1 wiring graph build and check **PASS** (4,536 files, 24,719 nodes,
61,805 edges; deep semantic layer **not built**). Genuine Jev v1.13.0
returned `ok=true` and `noul=0.02` when asked whether this patch makes the
proposed atomic replay-idempotent cross-process successor safe: **NO**;
advisory result, not a formal proof. Alibaba OpenCodeReview 1.12.13
preview found the production `resume.ts` diff reviewable, but excluded
integration/unit tests and documentation under its default rules. **No
independent model-backed OCR review completed**. PStack not installed;
**not run**.

## Limits and gates

The local SDK's experimental `experimental_force` token claim, arbitrary
concurrent ingress, durable CAS/generation ownership, crash/replay,
idempotent outcome journal, exact FIFO across processes, checkpoint/stream
cursor continuity, authentication, cancellation/HITL/task/subagent fencing
remain **unqualified** for the proposed single-workflow successor refactor.
This patch does **not** eliminate the no-owner interval; it only avoids a
false absent-session result during existing handoff. If a marker persists,
the caller now receives a visible retryable-by-caller pending error rather
than a false "not found" outcome. It does **not** imply delivery succeeded.

Independent review, signed+DCO commit, exact-head CI and post-main release
checks remain gates; the successor architecture stays **PRODUCTION NO-GO**
and issue #32 stays OPEN. Do not silently merge this change solely because
unit/E2E tests pass.

## Expected pending-handoff log privacy follow-up (2026-10-10)

An additional risk was found by inspecting the **public**
`createWorkflowRuntime.resolveContinuation` catch path: before this fix, it
logged every error other than `HookNotFoundError` with a structured
`continuationToken` field. The new `SessionHandoffPendingError` is an
**expected transient contention outcome**; logging the associated stable
channel alias could reveal channel/thread/user identifiers even though the
new error's own message contains no identifier.

A test was first added to the checked-in `workflow-runtime.test.ts`, with a
real session pending error induced through the existing mocked Workflow SDK
hook interface and a still-live marker after the unchanged 5-second window.
The test captures structured logs and asserts the expected pending error is
**propagated** with no `failed to resolve session by continuation token`
error record. **Test-first RED:** against unchanged signed PR #47 source,
the focused test **FAILED 1/1** because the runtime wrote exactly that error
record; 46 other cases were filtered out. **GREEN:** the runtime catch now
explicitly rethrows `SessionHandoffPendingError` _before_ the generic logging
path. Unexpected backing-store errors still follow the preexisting logging
path; missing-session `HookNotFoundError` still returns `undefined`.

The complete canonical `workflow-runtime.test.ts` file **PASSED 47/47** after
the fix, original per-test deadline unchanged, Vitest file duration
**7.16s**. Source TypeScript and changed-file Oxlint **PASSED**. This
qualifies only the local expected-error logging contract and does not claim
that upstream host/HTTP proxies will never log request URLs or metadata,
nor a general data-exposure audit. It does not change retry budgets,
production topology, Workflow SDK, or solve cross-process atomic successor
handoff. Prior exact-head CI results apply only to the **older** SHA and
must be repeated after this signed follow-up commit.

## Found-owner metadata lookup error boundary (2026-10-10)

On previous signed PR #47 SHA 19432603b85927a4d3f34a33cfb052f41e6c0116,
resolveSessionInbox caught both getHookByToken and subsequent hook.metadata
hydration in one try/catch. A physically present owner whose metadata
hydration raised SDK HookNotFoundError could be mistaken for a missing hook
and fall through to legacy session lookup. Even after splitting these
operations, createWorkflowRuntime.resolveContinuation converted the raw
metadata HookNotFoundError into undefined, as if the entire session did
not exist. Either outcome could cause a channel to try starting another
session despite an existing inbox owner.

**Canonical Mac test-first qualification:**

- A new regression test first FAILED 1/1 against the unmodified signed PR
  head because the lookup incorrectly attempted a marker or legacy lookup
  instead of forwarding the found owner's metadata failure. Preliminary
  separated-lookup source passed the entire inbox unit suite 9/9 and
  Local World integration 1/1, but was NOT published.
- Two new focused tests then FAILED 2/2 against that preliminary source:
  a found-owner metadata error was still raw HookNotFoundError, and the
  public resolveContinuation returned undefined rather than failing closed.
- Final bounded code wraps ONLY an SDK-branded HookNotFoundError from
  identity metadata AFTER a hook is found into a separate
  SessionIdentityUnavailableError. It has a fixed identifier-free message
  and preserves the original as cause. Public resolveContinuation rethrows
  this identity-unavailable result, bypassing its structured
  continuationToken error log for this expected condition. Genuine absence
  of the hook still returns undefined; generic unrecognized errors,
  handoff retry windows, legacy fallback and other delivery remain intact.
- The complete TWO official-config unit files PASSED 57/57 (9 inbox,
  48 runtime), no failures (1.11s); the unchanged real pinned Local World
  alias-handoff integration PASSED 1/1, four other cases filtered,
  original deadline (13.14s file duration). Source-package TypeScript,
  Oxlint/Oxfmt, mechanical invariant guard and git diff checks PASSED.
  Offline frozen pnpm packages restored from the existing local Mac cache
  with zero downloads. No paid model, Windows PC, SDK upgrade, deadline
  extension, production successor refactor or migration.

This is a local mock-backed error-classification regression and existing
in-process handoff integration, NOT a reproduced real metadata-store
outage, global privacy proof, backend crash/replay recovery or distributed
atomic successor/fencing contract. Keep issue #32 OPEN and proposed
successor architecture production NO-GO. PR #47 remains DRAFT/NO MERGE
pending genuine independent Alibaba OCR model review, fresh exact-head CI
and repository governance.
