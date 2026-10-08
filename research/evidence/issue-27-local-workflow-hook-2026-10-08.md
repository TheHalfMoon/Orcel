---
issue: https://github.com/TheHalfMoon/Orcel/issues/27
status: qualified-local
last_updated: "2026-10-08"
---

# Local Workflow hook microreproducer — issue #27

## Scope and provenance

This is a **local, independent Workflow SDK primitive smoke reproducer**, not
an end-to-end Orcel response benchmark or hosted A/B experiment. It uses the
existing repo-pinned compiled SDK and real local World harness; it does not
touch Nitro, production agent execution, runtime topology or dependency
versions. All tests used the authorized Windows workstation, Node 24,
Vitest 5.0.2 and **zero paid services**.

The test fixture sources are:

- `packages/orcel/src/internal/testing/workflow-hook-microreproducer.ts`
- `packages/orcel/src/execution/workflow-hook-microreproducer.integration.test.ts`

The tested package manifests specify `@workflow/core@5.0.0-beta.57` and
`@workflow/world-local@5.0.0-beta.48`. These are **not** the same aligned SDK
package set as the historical beta.43/beta.47 hosted experiment in
`research/turn-performance.md`.

Command, from the repository root:

```sh
corepack pnpm --filter @orcel/orcel exec vitest run \
  --config vitest.integration.config.ts \
  src/execution/workflow-hook-microreproducer.integration.test.ts
```

To retain operation-timing rows locally, explicitly set
`WORKFLOW_HOOK_MICROREPRO_EVIDENCE_PATH` to a writable _existing local
directory's new file path_ before invoking the test. If unset, the test
does not persist a report file.

## Actual local test evidence

Two integration tests **passed (2/2)** against the real compiled Workflow
local-world adapter. Single hook yielded the exact `one` payload.
Two sequential hooks yielded `alpha`, then `beta`, proving order and
non-polling public hook acknowledgment API functionality in this mock.

Two source-attributed, plain-JSON timing records were written to a local file
outside the Git repository, retained at
`D:\Orcel-Issue27-WorkflowMicroRepro.jsonl`.

- Raw local timing file SHA-256:
  `D08497CFF125F9263191EF2EF6B11DB2A5E05940648ACEB2A78EA48DD131D366`.
- One-hook observation: `firstResumeAckMs=21.9406`.
- Two-hook observations: `firstResumeAckMs=26.9559`;
  `secondResumeAckMs=25.9896`.
- The first hook-readiness time was **8,335.4539 ms** in the first case but
  **130.4090 ms** in the second. It includes local startup/compilation and
  readiness discovery **polling**, and should **not** be interpreted as a
  workload response latency.
- The two-hook `secondHookReadyMs=129.5276` likewise includes polling.

These are merely timing traces from **one run per variant**, with no
replication, no confidence interval, no A/A noise calibration and no
interleaved comparison of different SDK versions. The timings are not evidence
of a causal regression, a speedup, a hosted platform floor, or readiness for
sub-second production claims. The test deliberately imposes **no numeric
timing assertions**; it asserts delivery, ordering and cleanup behavior.

## Boundaries / remaining research roadmap

This minimal two-resume reproducer intentionally does **not** launch a child
Workflow run, transfer cross-deployment hook ownership, time a real
HTTP receipt or model compute start, or exercise durable crash/retry
semantics across workers. The historical beta.43 versus beta.47 comparison
requires isolated _aligned_ dependency versions and repeated interleaved
hosted trials with real retained artifacts, not a version edit in place.
`research/turn-performance.md` therefore remains `status: proposed`.

Issue #27's **local SDK primitive repro** is distinct from these
architecture/performance research gates. A new bounded successor issue
would be needed to qualify an actual parent/child + two-resume topology.
