---
issue: https://github.com/TheHalfMoon/Orcel/issues/32
status: blocked-upstream
last_updated: "2026-10-09"
scope: installed-public-api-and-contract
---

# Atomic successor and hook-ownership handoff: public-API capability decision

## Decision: NO-GO for production topology replacement

**Complete atomic successor handoff: NOT PROVEN for Orcel.** The installed SDK does declare an experimental forced hook-token takeover option, but it has not been qualified against Orcel's full replay/fencing/inbox/stream/deployment contract. Keep Orcel's current driver/child topology and all safety controls. Do not promote the proposed single-workflow successor refactor, locally simulated relay, or any latency claim to production.

Source-of-truth: `research/turn-performance.md` (successor feasibility, no-owner interval, negative performance evidence, next work) and `research/single-workflow-session-upgrades.md` (exact-deployment selection, checkpoint, handoff, admission and validation). The latter document is a _proposal_, not a deployed handoff guarantee. The earlier `barba/perf-exp-successor-turns` prototype already showed `HookNotFoundError` between disposal and successor claim and a sequencer workaround with new overhead and missing production semantics; do not recreate or ship either.

## Capability delta: experimental force-claim in the pinned SDK (2026-10-09)

The earlier public-*name* inventory below is historically accurate within its
scope but **incomplete for options on existing functions**. Upstream
[vercel/workflow PR #4193](https://github.com/vercel/workflow/pull/4193)
merged on 2026-09-23, exposing
`createHook({ token, experimental_force: true })` and the associated
`HookForceClaimedError` and World `hookForceClaim` capability. The SDK
describes an intent-first token takeover, a displaced-owner error after
buffered deliveries, and resume redirects with stable `resumeId` for bounded
races. This is a specific experimental hook ownership feature, **not an
atomic successor-session protocol for all Orcel state**.

The *already installed and pinned*, un-upgraded Orcel packages are
`@workflow/core@5.0.0-beta.57`,
`@workflow/errors@5.0.0-beta.24`,
`@workflow/world@5.0.0-beta.39`, and
`@workflow/world-local@5.0.0-beta.48`. The published TypeScript
declarations show `HookOptions.experimental_force?: boolean` in
`@workflow/core`, `HookForceClaimedError` in `@workflow/errors`,
and `hookForceClaim?: boolean` in `@workflow/world`. The expanded
`scripts/workflow-public-api-capabilities.test.mjs` checks these *published
declarations*, in addition to the previous 2 exported-symbol tests; this
is **not an exercised takeover, crash-recovery, or concurrency conformance test**.

The upstream feature refuses takeover of an older running victim below
protocol version 8 and rejects Worlds without the capability; it does
not apply to `createWebhook()`. The upstream description acknowledges
mixed-deployment `start()` spec-version stamping risk (tracked under
[workflow #4251](https://github.com/vercel/workflow/issues/4251)).
Upstream [#2376](https://github.com/vercel/workflow/issues/2376)
still tracks atomic keyed start and post-completion idempotency as separate gaps.

**Partial capability, not production GO:** forced token takeover may be a
building block. It does not by itself establish Orcel's single durable CAS
inbox sequence, accept/fence boundary, replay-idempotent successor activation,
cross-process crash/retry, original stream cursor/identity continuity,
cancellation, HITL, tasks/subagents, or authenticated latest-deployment
routing. The correct next bounded grain is a local-world behavioral
conformance matrix for the pinned SDK (positive force claim, legacy/version
refusal, concurrent claims, same-payload retries and crash/replay), followed
by explicit design validation of the remaining inbox and stream contracts.
No existing production topology is changed.

## Reproducible zero-cost public entrypoint inventory

On the authorized local Windows workstation, at canonical baseline `e5fdcbdc25a117a48d9b4cc9372cb8fbffc83158`, installed dependencies from the frozen pnpm lockfile with `pnpm install --offline --frozen-lockfile --filter '@orcel/orcel...'` (zero downloads). Executed:

```sh
node --test scripts/workflow-public-api-capabilities.test.mjs
```

**Result: 2/2 PASS;** `@workflow/core@5.0.0-beta.57`, `@workflow/world-local@5.0.0-beta.48` match the Orcel manifest. The root public entrypoint exposed `createHook`, `createWebhook`, `defineHook`. The public `@workflow/core/runtime` entrypoint exposed `getHookByToken`, `resumeHook`, `resumeWebhook`, `start`. Neither inspected entrypoint exposed a named transfer/handoff/atomic-claim function. The SDK package declares other export paths, including `./runtime/resume-hook`, `./runtime/start` and `./runtime/lifecycle-hooks`; the original probe did not inspect options on those entrypoints, private implementations, or takeover behaviors. The *separate* declaration probe above corrects that omission without claiming behavioral qualification.

Results are **a public-name inventory**, not a behavioral proof that an atomic operation is missing everywhere. Prior source-backed interrupted-handoff experiments supply the stronger observable negative result. The test deliberately exercises no unsafe state transition, network call, model or paid API, and it prints no tokens, user content or credentials. Re-run this probe against any prospective SDK upgrade before designing a new protocol.

## Capability matrix: supported means supported at the stated boundary

| Required primitive or guarantee                                          | Evidence status                   | Boundary                                                                                              |
| ------------------------------------------------------------------------ | --------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Single hook creation and resume                                          | SUPPORTED (local)                 | PR #28, two real local-world tests; no cross-process semantics                                        |
| Parent and child Workflow run with two ordered acknowledgments           | SUPPORTED (local)                 | PR #30, two independent local test runs; hooks always parent-owned                                    |
| Starting a separate Workflow run                                         | SUPPORTED (local)                 | PR #30 child identity differs from parent                                                             |
| Successor start targeted to a deployment                                 | PROTOTYPED only                   | Historical `turn-performance.md` proof; production Orcel rejects an unauthenticated `latest` selector |
| Stream continuity across bounded runs                                    | PROTOTYPED only                   | Prior sequencer experiment; no production cancellation/authorization evidence                         |
| Atomic, replay-idempotent successor activation plus hook transfer        | PARTIAL SDK CAPABILITY / UNPROVEN ORCEL CONTRACT | Experimental forced token claim is declared; successor activation, inbox sequence, stream/cancel and crash semantics remain unqualified |
| No `HookNotFoundError` interval at stable ingress token during transfer  | UPSTREAM CLAIM / UNTESTED FOR ORCEL | Upstream forced-claim redirects are documented; prior non-force disposal/claim gap remains valid |
| Fencing + monotonic FIFO inbox sequence as one SDK commit                | NOT SUPPORTED by present evidence | External CAS/inbox is a separate unimplemented protocol                                               |
| Cross-process crash/retry, duplicate dispatch and idempotent replay      | UNTESTED                          | Neither local PR #28 nor #30 establishes this                                                         |
| Authorization, cancellation, HITL, task/subagent, timeout, stream cursor | UNTESTED for successor mode       | Preserve existing driver/child production paths                                                       |
| Hosted paired benchmark and causal performance gain                      | NOT MEASURED                      | `research/turn-performance.md` remains `proposed`                                                     |

## Upstream capability contract (proposal, NOT an SDK API)

Input (opaque/private where appropriate): stable session and hook-token set, exact trusted authenticated target deployment, `expectedOwnerRunId`, `expectedGeneration`, `handoffId` (idempotency key), immutable validated checkpoint reference/hash, `lastAcceptedSequence`, and original resumable stream reference. This is a contract sketch only; none of these field names are asserted to exist in Workflow.

An acceptable single durable operation must: (1) compare owner and generation; (2) fence the old execution owner at an exact sequence; (3) atomically register all stable hook addresses with one successor and pin its authenticated deployment; (4) transfer all pre-fence accepted payloads in FIFO and route later accepted payloads continuously, never transiently returning not-found; (5) return the identical successor/commit outcome for every retry of `handoffId`; (6) preserve public session/stream identity, cursor and terminal ownership; and (7) expose a durable status lookup by `handoffId` for uncertain crashes.

Reject or explicitly resolve: stale generations, duplicate handoff IDs with mismatched checkpoint bytes, partial hook claims, divergent stream owner, late ingress during fence, ambiguous commit acknowledgments, cancelled or unauthorized handoffs, version-incompatible checkpoints and unexpected target deployment. The old owner must not execute duplicate model/tool side effects. Fail closed if post-crash ownership is uncertain.

## Minimum future proof gates

1. Positive public SDK capability confirmed in a reproducible pinned environment, with upstream protocol documentation and conformance tests. If unavailable, request upstream support rather than patch vendor internals.
2. Deterministic fault injection at every state transition: old-owner crash, successor crash, activation ambiguity, duplicate commit/retry, bursty concurrent ingress, stale producer generation and partial hook claims.
3. End-to-end FIFO, no missing accepted payloads, no duplicated model/tool execution, continuous stable token reachability, original stream/cursor continuity and exact authenticated deployment on both Windows and Linux/local-world plus a genuinely separate-process replay test.
4. Preservation of cancellation, timeout, authorization, HITL, subagents, task/workflow-tool leases, reset/compaction and mixed-deployment event schemas before production admission.
5. Separate owner-authorized paired hosted A/B with identical base/head workloads, raw timing artifacts, confidence bounds, p50 and p95 guardrails, zero unapproved expense. A local timer is never this evidence.

**Next decision:** test the experimental forced-claim capability already declared by the pinned Workflow SDK, then identify the additional Orcel-owned durable CAS inbox / stream directory and fail-closed recovery primitives required for full conformance. Do not upgrade the SDK or use forced claim in production without direct acceptance evidence and governance. Keep Issue #32 open as `blocked-upstream-and-unqualified-contract`; merging this research update does not mean the project or architecture is finished.

## Tool review and graph limitations

- Genuine Jev `jev-1.13.0` call on the fail-closed production decision returned `noul=0.87`; this is calibrated probabilistic advice, not a correctness certificate.
- Genuine Graft local-only wiring build indexed the `scripts` scope: 36 files, 388 nodes, 1,018 edges. This partial graph is not a system-wide blast-radius analysis; no deep meaning layer was produced.
- Alibaba OpenCodeReview's exact-range delegation preview/rules must be retained with the PR. No native LLM-backed OCR review is claimed unless independently executed with valid authorized credentials; the previously checked Windows Anthropic provider lacked an API key. PStack is optional and must not be marked used without a real invocation.
- The SDK capability probe, source-graph output, and research decision must be judged by exact-head CI; the historical local Windows invariant rule 36 cache/declaration error is not a local guard PASS and cannot be bypassed.
