---
issue: https://github.com/TheHalfMoon/Orcel/issues/31
status: measured-local-diagnostics
last_updated: "2026-10-09"
---

# Issue #31: opt-in Windows compiler phase measurements

## Scope and invariants

On canonical baseline `main` `2e4e6ba25b7cf0aebc288ea3ce8d464a6fed8f24`, the existing
`isolates configured built-in extension mounts` integration case was exercised on the authorized
Windows workstation with the **unchanged** checked-in 60,000 ms case deadline.
A test-helper-only `ORCEL_MOUNT_PHASE_PROFILE=1` switch emits integer millisecond phase durations.
It does not modify production code, fixtures, assertions, timeout, retries, or compilation semantics;
without the environment flag, it does not log these measurements.

The sampled phases surround actual `compileAgent`, the concurrent
`loadCompiledManifest` / `loadCompiledModuleMapFromAuthoredSource` phase, and
`resolveRuntimeAgentGraph`. Times are wall-clock observations and include associated filesystem,
scheduler, and runtime work; they are **not** CPU profiles or a decomposition of the internals
of `compileAgent`. Only numeric durations are logged; no user data, filesystem paths, tokens,
or model payloads are emitted by this opt-in helper.

## Repeatable command

From `packages/orcel` in the checked-out repository, after existing frozen dependencies and
compiled JS assets are present, run in PowerShell:

```powershell
$env:ORCEL_MOUNT_PHASE_PROFILE = '1'
pnpm exec vitest run --config vitest.integration.config.ts --disableConsoleIntercept src/compiler/mounted-extension.integration.test.ts -t 'isolates configured built-in extension mounts'
```

`--disableConsoleIntercept` was necessary to expose the diagnostic event in the Windows
terminal output. Two earlier successful executions with ordinary console interception produced
no captured phase line; no phase durations are inferred from those runs.

## Genuine local evidence

| Execution            | Vitest file duration | compileAgent |    Hydration | Graph resolve | Three-phase total | Result                        |
| -------------------- | -------------------: | -----------: | -----------: | ------------: | ----------------: | ----------------------------- |
| Intercepted output A |              42.83 s | Not captured | Not captured |  Not captured |      Not captured | 1 passed, 10 filtered, exit 0 |
| Intercepted output B |              36.79 s | Not captured | Not captured |  Not captured |      Not captured | 1 passed, 10 filtered, exit 0 |
| Visible profile A    |              38.81 s |    18,535 ms |     3,243 ms |         20 ms |         21,798 ms | 1 passed, 10 filtered, exit 0 |
| Visible profile B    |              39.41 s |    18,156 ms |     2,888 ms |         29 ms |         21,073 ms | 1 passed, 10 filtered, exit 0 |

Visible phase JSON was emitted by the exact `compileRuntimeGraph` helper in the existing
integration test. Both visible runs completed below the per-case 60s limit. File duration
also includes test collection/transform/setup and other case work, so it must **not** be
equated to the phase-total column.

For visible profiles, `compileAgent` accounted for roughly 85–86% of measured
`compileRuntimeGraph` time; hydration was roughly 14–15%; graph resolution was negligible
in these two particular runs. These ratios do not prove a causal Windows bottleneck or
generalize to all extensions or platforms.

A **temporary local-only** instrumentation attempt inside `compiler/compile-agent.ts`
to split discovery and artifact writing did not yield an observable detailed event in the
test output. This attempt was **reverted before qualification and commit**, so no attribution
to discovery versus artifact writing is made. No source-level speedup is claimed.

## Decisions and next bounded investigation

1. Keep the finite, case-specific 60s deadline from PR #34 and all original assertions.
2. Before optimizing `compileAgent`, capture reproducible separately observable phase evidence
   for `discoverAgentForCompilation` versus `writeAgentCompilation`, then
   `compileAgentManifest`, `materializeWorkspaceResources`, and filesystem artifact writes.
   Confirm the exact module resolution in the test runner first; unobserved instrumentation
   does not constitute measurement.
3. Compare several independent cold/warm trials on Windows and Ubuntu at immutable heads,
   with CPU and filesystem profiling separated. Do not mistake Rolldown's reported
   `orcel-workflow-transform load` overlap for a proved `compileAgent` root cause.
4. A production optimization needs a narrow causal change, unchanged extension mount
   identity/config correctness, full exact-head qualification, and independent post-main
   Windows/Ubuntu and scenario checks. The hosted turn-latency proposal remains distinct.

## Tool and review boundary

Genuine Jev 1.13.0 returned `noul=0.91` for the _bounded test-helper-only_ diagnostic
risk question; this probabilistic response is not a security or correctness certificate.
Genuine Graft restricted compiler source build indexed 54 files, 416 nodes and 1,081 edges,
and `graft check` passed with a wiring graph only (deep meaning tier unbuilt).
Genuine Alibaba OpenCodeReview `ocr delegate preview` saw the `.integration.test.ts` diff
but excluded it under `default_path` (zero reviewable files); this was **not** a model-backed
review. No PStack executable was found, and no native credential-backed OCR run is claimed.

This research increment is useful evidence, **not** closure of Issue #31, a CPU/IO cause,
or resolution of the separate atomic hook handoff in Issue #32.
