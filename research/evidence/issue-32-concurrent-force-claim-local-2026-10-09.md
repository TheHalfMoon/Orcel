---
issue: https://github.com/TheHalfMoon/Orcel/issues/32
status: single-process-local-conformance-candidate
last_updated: "2026-10-10"
---

# Concurrent experimental force-claim contenders: pinned Local World

## Decision boundary

The pinned experimental Workflow SDK supports an individual forced takeover, a refusal for running pre-v8 owners, and sequential forced owner replacement. None of these establishes orcel's proposed atomic successor-session transfer. The new bounded test covers two **simultaneously started** forced claimant runs against one existing live victim and one shared hook token, within **one process / Local World**. It does not introduce or activate a successor workflow in orcel production.

## Reproduction and assertions

- Start one original victim, wait for the token to become available, then submit two forced claimants with `Promise.all(start(...), start(...))` without presuming their scheduling or FIFO order.
- Wait for both claims to settle into **exactly one active contender and one failed contender**; the wait uses a bounded 15-second assertion retry inside the existing 30-second integration-test deadline, rather than extending the case timeout.
- Resolve the token through the SDK's public `getHookByToken` and assert it belongs to the active claimant.
- Resume the stable token once and assert the active claimant receives exactly that payload, while the failed claimant and original victim reject with the documented `HookForceClaimedError`. Release all still-running workflow runs in `finally`.

Mac initial targeted run, Node v24.15.0, pinned SDK and real Local World runner: **1 passed, 3 filtered**, 10.76s test / 22.24s file, exit 0. Full research conformance file then ran **4 passed / 0 failed**, 9.17s test / 13.05s file, exit 0. The same new focused case was then repeated in **three separately launched Mac runs** on the same exact test implementation with normal timeouts: **3/3 passes**, test durations 5.323s, 6.468s, and 4.742s; respective Vitest file durations 9.66s, 9.51s, and 7.89s. This is bounded repeatability evidence, not a statistical proof of race freedom. The SDK printed the expected displaced-owner `HookForceClaimedError` and legacy `HookConflictError` messages; they are asserted as outcomes, not test failures. No model or paid API calls.

Mac package `pnpm --filter @orcel/orcel run typecheck` **PASS**, `node scripts/guard-invariants.mjs` **PASS**, changed-file Oxfmt and Oxlint **PASS** (zero issues), `git diff --check` **PASS**. Neither a verified independent Jev opinion nor an Alibaba OCR native-LLM review is claimed. The GitHub delegated review job, if it passes, must not be mislabeled as an independent model review.

## Interpretation and outstanding gates

This test exercises the installed SDK's _local convergence_ behavior under two starts issued concurrently; it is **not** a deterministic interleaving injector, not a distributed atomic test, and not an assertion that the first or second claimant wins. It does not test replay of a lost acknowledgment, duplicate commit idempotency, crash during takeover, simultaneous messages, ingress ordering, a durable CAS checkpoint, persistent identity or stream cursors, authentication, HITL, timers, cancellations, deployment pinning, or subagent ownership. The proposed production single-workflow successor design remains **NO-GO**. Keep the driver/child architecture unchanged, require cross-process replay and full orcel contract proof, and never conflate a passing Local World test with the deployment outcome.

Review, DCO/GitHub-verified signing, exact-head CI, and independent post-merge checks remain required before this research-only test can enter `main`. Jev and independent Alibaba OCR review must be reported honestly rather than inferred from the GitHub workflow's delegated check name.

## Local World post-completion resume replay probe (2026-10-10)

On an **isolated authorized Mac** worktree at this PR's former exact head
`9caf86a18868f33a6014a21216f77b2824c8aa6c` with the **unchanged
frozen Workflow SDK packages** and Node 24.15.0, add one research-only test
using the supported public `start`, `resumeHook` and existing pinned Local
World runtime. The test registers an original victim, force-claims its token
with a successor, waits for the successor's stable hook, and delivers one
payload. It verifies that the successor returns exactly that payload and the
prior victim rejects with the documented force-claim outcome. Then it repeats
**the same `resumeHook(token, identicalPayload)` after the successor run has
completed**, as a bounded simulation of a client that lost a prior successful
resume acknowledgement.

**Observed:** the newly added focused test **PASSED**, 1 passed / 4 filtered,
exit 0 (Vitest file duration **19.22s**), under the original **30-second
case timeout**, with one fork and no additional model or paid service.
The first delivery succeeded; after completion the identical retry raised
`HookNotFoundError` with the **same token**, rather than returning a durable
acknowledgement of the previous successful delivery. The test pins that SDK
Local World behavior by matching both error name and token. Every run is
cleaned up with the existing `releaseIfLive` safety helper in `finally`.

**Interpretation:** this is a bounded, post-completion retry observation, **not
a crash/replay test**. It establishes that the public hook-resume call alone
cannot be treated as an application-level idempotency/outcome journal for a
lost-ack scenario after that hook completes. It does not prove that every
possible Workflow SDK operation lacks replay idempotency, nor that identical
payloads can ever cause duplicate model or tool side effects. Cross-process
uncertain commit, concurrent duplicate ingress, auth, FIFO and original
stream-cursor retention remain untested. A separately durable handoff ID,
atomic outcome record and recoverable status lookup remain required by the
proposed Orcel successor contract, and **the production decision stays NO-GO**.
Neither the existing driver/child topology nor the SDK version, production
code, CI declarations or test budgets were changed by this research grain.

### Full-file and review-tool qualification of the local retry grain

After adding the retry assertion, the **entire five-case**
`workflow-force-claim-research.integration.test.ts` file **PASSED 5/5**
(0 failed), with the original 30-second case timeout, one Vitest fork,
Node v24.15.0 and pinned Local World SDK; total file duration **30.92 s**.
The SDK's intentionally logged `HookForceClaimedError` and
`HookConflictError` messages are the expected behavior of displaced owners
and pre-v8 claim refusals, not additional unasserted failing tests. Source
package `tsc -p tsconfig.json --noEmit`, touched-file Oxfmt/Oxlint and
`node scripts/guard-invariants.mjs` **PASSED**; no timeout, runtime or
production source files were modified.

A genuine Jev **1.13.0** call answered `noul=0.04` to whether this
post-completion Local World retry establishes cross-process production-safe
replay-idempotent handoff. This is advisory judgment, not a correctness proof.
Alibaba OpenCodeReview 1.12.13's `delegate preview` on the exact branch
selected **0/2 files for native review** (integration test excluded by default
path policy, Markdown unsupported). Therefore **no native independent
LLM-backed code review is claimed**. These tools cannot replace a real
reviewer or the missing durable CAS, FIFO, crash/retry and stream gates.

## Simultaneous identical resume requests with a live forced claimant (2026-10-10)

This bounded extension tests **two simultaneous public** `resumeHook` calls with
**identical** token and payload against a single live, experimentally
force-claimed hook on the **pinned single-process Local World SDK**. It is
separate from the earlier **post-completion** repeat, which returns
`HookNotFoundError`. The test starts a victim, waits for its stable hook,
starts a forced claimant, waits for that claim's hook, issues both resumes
before awaiting either result via `Promise.allSettled`, and checks both call
outcomes, the claimant's returned payload and the former owner's expected
force-claim rejection. It cancels any still-live runs in `finally`.

**Important initial negative attempt and reproducibility:** An initial
exploratory test incorrectly required exactly **one** successful public resume
response. It **FAILED 1/1**, because **both** simultaneous duplicate calls
returned `fulfilled` on that run. The follow-up exploratory run of two cases
(identical plus _different_ simultaneous payloads) **FAILED 2/2 due to the
original 30-second per-test timeouts**; no reliable divergent-payload result
was established and that extra case was **discarded**. A subsequent
instrumented identical-payload attempt also timed out; the completed output
contained no evidence that both resume calls had been reached, so those
timeouts do **not** establish a second result for concurrent delivery. The
existing prior-force-claim control ran independently **PASS 1/1** in the same
checkout (file 15.94s). A final focused instrumented identical-resume run
**PASSED 1/1**, 6 filtered, file duration **15.80s**: both resumes were
`fulfilled`, the claimant was initially running, and its return value was
`identical-resume-payload`; the displaced owner rejected as expected.

The committed test removes all exploratory stage logging and the unqualified
divergent-payload scenario. On the same authorized Mac (Node v24.15.0,
original test deadlines and one Vitest fork, no paid model/cloud), the **full
six-case research integration file PASSED 6/6** (0 failed, Vitest file duration
**24.67s**). The new assertion is deliberately a pinned-SDK **observed
acknowledgment behavior**, not an approval for production exactly-once
execution. Two API calls returning successfully do **not** prove two tool or
model side effects occurred; neither test establishes any durable
application-level idempotency key, status journal, atomic owner/inbox CAS,
exact FIFO, cross-process recovery or original stream cursor. The new
expectation may need to change if an SDK upgrade intentionally adds a
stronger duplicate-request conflict policy. Do not generalize these local
observations to other adapters, crash states or all interleavings.

Only a **research integration test and its issue-linked evidence** are changed.
Workflow SDK dependencies, Orcel production code, protocol, timeout, host
configuration and release surface are unchanged. The proposed production
successor admission remains **NO-GO**, issue #32 stays OPEN and PR #44 must
remain DRAFT until genuinely qualified independent review and fresh exact-head
CI complete.

### Exact-grain tool and authoring-gate qualification (2026-10-10)

The new test satisfies orcel's `test-audit` authoring gate: it checks the
**actual observable public SDK `resumeHook` acknowledgment behavior under
simultaneous duplicates**, which the earlier serial after-completion
`HookNotFoundError` test cannot reach. A credible change to Local World hook
claim/resume conflict semantics changes the result. The integration tier is
the narrowest existing tier with a real unmocked pinned SDK World. It needs no
production-only injection point, fake response, unpublished API or duplicate
higher-tier E2E. It is intentionally pinned-SDK characterization rather than
a product requirement that both acknowledgments _ought_ to succeed.

- Source package `tsc -p tsconfig.json --noEmit`: **PASS**.
- `node scripts/guard-invariants.mjs`: **PASS**.
- Touched test/research Oxfmt/Oxlint and `git diff --check`: **PASS**.
- Real Graft **0.21.1** wiring graph build: **4,536 files, 24,717 nodes and
  61,798 edges**, seeded from the unchanged original Mac worktree;
  `graft check`: **OK**. Its deeper semantic/meaning layer is **not built**.
- Genuine authenticated Jev **1.13.0** `noul` returned `ok=true`,
  `noul=0.02` to whether these Local World outcomes prove safe cross-process
  replay-idempotent successor handoff. This is advisory risk calibration,
  **not** a proof or endorsement of production handoff.
- Alibaba OpenCodeReview **1.12.13** delegated diff preview: **0 of 2**
  changed test/research files eligible under default native selection
  (integration test excluded by `default_path`, Markdown by
  `unsupported_ext`). **No native independent model-backed review completed
  for this test grain**; a CI job named Review Gates does not supply one.
- PStack not installed on this Mac; **not run**. No paid model, cloud, Docker,
  SDK upgrade or host-device migration was used in this grain.

**Do not merge automatically.** Preserve the PR as DRAFT until exact new-head
CI and the independent review/governance gate genuinely qualify; even a green
research merge would not make the proposed successor production-safe or close
issue #32.
