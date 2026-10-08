---
issue: https://github.com/TheHalfMoon/Orcel/issues/29
status: qualified-local
last_updated: "2026-10-09"
---

# Local Workflow parent/child hook microreproducer — issue #29

## Source reuse and bounded scope

This local-only functional demonstration starts a distinct Workflow child run to acknowledge two parent-owned hooks. It does not change the production Orcel runtime.
Reused source: `e2e/fixtures/agent-workflow-tools/agent/lib/fanout.ts` (child launch in `use step`, reply through `resumeHook`); predecessor: PR #28 / Issue #27.
The rejected sequencer/successor experiments in `research/turn-performance.md` lines 771–837 are not reimplemented or shipped.

Sources:
- `packages/orcel/src/internal/testing/workflow-child-hook-microreproducer.ts`
- `packages/orcel/src/execution/workflow-child-hook-microreproducer.integration.test.ts`

## Verified Windows local qualification

Environment: authorized Windows workstation, Node 24, Vitest 5.0.2, repository-pinned Workflow SDK dependencies, local World; no hosted deployment, paid service, or model call.
Baseline main: `202f453ff4fd101e0553287ea0c17664a07ad8a4`.

Run after generating vendored dependencies through `node packages/orcel/scripts/build-js.mjs`, with `packages/orcel` as the current working directory:

```sh
./node_modules/.bin/vitest run --config vitest.integration.config.ts src/execution/workflow-child-hook-microreproducer.integration.test.ts --reporter=dot
```

Observed result: **1 test file / 1 test PASS**, exit 0; Vitest duration 21.18 s, including startup and transforms.
Package `tsc -p tsconfig.json --noEmit` PASS, exit 0 after `build-js.mjs` completed successfully.
Source Oxfmt check PASS for both new TypeScript files.
Initial pre-build attempts failed because the fresh worktree lacked `#compiled/*` vendor output. They are failures, not passes, and no invariant rule was disabled.

The test checks that the parent run ID matches its returned owner ID, a real child run has a distinct ID, the parent receives exact payloads `alpha` then `beta`, and the distinct child return value settles to the same pair.
The parent owns both hook tokens throughout; `using` disposes them. Test failure cleanup cancels a still-live parent.
Unique opaque tokens are generated but not printed or recorded in evidence.

## Explicit limitations

The test does **not** establish atomic ownership transfer, cancellation under fault injection, replay across processes or crashes, continuous stable-token addressability, FIFO under concurrent senders, latest-deployment routing, or hosted performance gains.
One local run is not a performance study. No causation or speedup is claimed.
`research/turn-performance.md` remains `status: proposed`. Deployment and future architecture changes remain separate approval gates.

## Review tools and invariant gate

- Genuine Jev 1.13.0 returned `noul=0.91` on a bounded evidence-interpretation question; this is probabilistic review support, not a proof of correctness.
- Genuine Graft `build` completed for the restricted source scope (`packages/orcel/src/execution` and `packages/orcel/src/internal/testing`): 394 files, 2,567 nodes, 6,671 edges. This partial graph cannot establish system-wide blast radius.
- Oxlint on the two changed TypeScript files PASS, exit 0; staged diff whitespace check PASS.
- Local Windows `node scripts/guard-invariants.mjs` **FAILED rule 36**: the extension-contract generator could not find a transient `.extension-contracts-cache/.../declarations/extension-contracts/entrypoints/extension.d.ts`. No source extension-contract files or invariant guards were changed, and **no local guard PASS is claimed**. Exact-head GitHub CI must independently run this check.
- Native model-backed Alibaba OpenCodeReview requires a configured provider API key that was absent on this Windows host. The supported native delegation workflow is separately checked on exact PR range; delegation is never represented as LLM review.

All tool scope and environment limitations are retained intentionally.
