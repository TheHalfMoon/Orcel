---
issue: https://github.com/TheHalfMoon/Orcel/issues/32
status: single-process-local-conformance-candidate
last_updated: "2026-10-09"
---

# Concurrent experimental force-claim contenders: pinned Local World

## Decision boundary

The pinned experimental Workflow SDK supports an individual forced takeover, a refusal for running pre-v8 owners, and sequential forced owner replacement. None of these establishes Orcel's proposed atomic successor-session transfer. The new bounded test covers two **simultaneously started** forced claimant runs against one existing live victim and one shared hook token, within **one process / Local World**. It does not introduce or activate a successor workflow in Orcel production.

## Reproduction and assertions

- Start one original victim, wait for the token to become available, then submit two forced claimants with `Promise.all(start(...), start(...))` without presuming their scheduling or FIFO order.
- Wait for both claims to settle into **exactly one active contender and one failed contender**; the wait uses a bounded 15-second assertion retry inside the existing 30-second integration-test deadline, rather than extending the case timeout.
- Resolve the token through the SDK's public `getHookByToken` and assert it belongs to the active claimant.
- Resume the stable token once and assert the active claimant receives exactly that payload, while the failed claimant and original victim reject with the documented `HookForceClaimedError`. Release all still-running workflow runs in `finally`.

Mac initial targeted run, Node v24.15.0, pinned SDK and real Local World runner: **1 passed, 3 filtered**, 10.76s test / 22.24s file, exit 0. Full research conformance file then ran **4 passed / 0 failed**, 9.17s test / 13.05s file, exit 0. The SDK printed the expected displaced-owner `HookForceClaimedError` and legacy `HookConflictError` messages; they are asserted as outcomes, not test failures. No model or paid API calls.

Mac package `pnpm --filter @orcel/orcel run typecheck` **PASS**, `node scripts/guard-invariants.mjs` **PASS**, changed-file Oxfmt and Oxlint **PASS** (zero issues), `git diff --check` **PASS**. Neither a verified independent Jev opinion nor an Alibaba OCR native-LLM review is claimed. The GitHub delegated review job, if it passes, must not be mislabeled as an independent model review.

## Interpretation and outstanding gates

This test exercises the installed SDK's _local convergence_ behavior under two starts issued concurrently; it is **not** a deterministic interleaving injector, not a distributed atomic test, and not an assertion that the first or second claimant wins. It does not test replay of a lost acknowledgment, duplicate commit idempotency, crash during takeover, simultaneous messages, ingress ordering, a durable CAS checkpoint, persistent identity or stream cursors, authentication, HITL, timers, cancellations, deployment pinning, or subagent ownership. The proposed production single-workflow successor design remains **NO-GO**. Keep the driver/child architecture unchanged, require cross-process replay and full Orcel contract proof, and never conflate a passing Local World test with the deployment outcome.

Review, DCO/GitHub-verified signing, exact-head CI, and independent post-merge checks remain required before this research-only test can enter `main`. Jev and independent Alibaba OCR review must be reported honestly rather than inferred from the GitHub workflow's delegated check name.
