---
issue: https://github.com/TheHalfMoon/Orcel/issues/31
status: measured-local-diagnostics
last_updated: "2026-10-09"
---

# Issue #31: bounded compiler manifest-stage breakdown

## Purpose and boundaries

The opt-in `ORCEL_MOUNT_PHASE_PROFILE=1` integration-helper diagnostic from PR #35
previously measured `compileAgent` but could not separate discovery, normalization,
workspace materialization, or filesystem writes. This research grain adds an
optional numeric phase observer threaded through internal compiler functions.
The existing `isolates configured built-in extension mounts` assertions,
60-second case deadline, extension identity, namespace binding, fallback,
error behavior, artifact schema and output file set are unchanged.

The observer is supplied only when the test helper has the opt-in flag. No
observer is supplied on ordinary production compilation paths. Profile JSON
contains numeric milliseconds and phase names only; it does not include agent
source, tokens, user inputs, filesystem paths or model payloads. As with all
optional callback hooks, a throwing callback is not a claimed supported
production API; this internal observer is strictly for bounded diagnostics.

## Reproduce locally

From `packages/orcel`, after the exact lockfile dependencies, compiled assets
and `build:js` are installed/built:

```powershell
$env:ORCEL_MOUNT_PHASE_PROFILE = '1'
.\node_modules\.bin\vitest.cmd run --config vitest.integration.config.ts --disableConsoleIntercept --pool=forks --maxWorkers=1 src/compiler/mounted-extension.integration.test.ts -t 'isolates configured built-in extension mounts'
```

The fork/worker flags are local diagnostic runner choices and are not
committed as repository configuration. The test assertions and case timeout
were not modified. Do not compare unpaired runs with different workers as an
optimization benchmark.

## Observed Windows executions (2026-10-09)

Environment: authorized Windows workstation, Node v24.19.0,
pnpm v12.7.0 from Corepack, Vitest v5.0.2; checked-out baseline
`11d5a892b26230f457ca07f2ebf01802fd418440` plus only this
research instrumentation.

| Stage | First visible split | Nested stage sample |
| --- | ---: | ---: |
| `compileAgent` elapsed | 34,088 ms | 27,426 ms |
| `resolveDiscoveryProject` | 3 ms | 2 ms |
| `discoverAgent` | 148 ms | 118 ms |
| `compileAgentManifest` | 33,763 ms | 27,172 ms |
| `prepareDevelopmentExtensions` | Not measured | 1 ms |
| `rootCreatePhaseOne` | Not measured | 194 ms |
| `rootCompileAgentConfig` | Not measured | 3 ms |
| `rootCompileResources` | Not measured | 15,824 ms |
| `rootCompileChildren` | Not measured | 11,142 ms |
| `materializeWorkspaceResources` | 154 ms | 117 ms |
| `prepareCompilerArtifacts` | 10 ms | 8 ms |
| `writeCompilerArtifactFiles` | 7 ms | 7 ms |
| Authored module-map hydration | 4,787 ms | 3,956 ms |
| Runtime graph resolve | 33 ms | 26 ms |
| Total `compileRuntimeGraph` | 38,908 ms | 31,408 ms |
| Vitest file duration | 65.04 s | 55.49 s |
| Result | 1 passed, 10 filtered, exit 0 | 1 passed, 10 filtered, exit 0 |

An additional Windows confirmation after **gating the timer starts on the
presence of the optional phase observer** passed the same single-fork
filtered test (1 passed, 10 skipped, exit 0; Vitest file duration 59.62s).
It measured `compileAgent=28,717ms`,
`compileAgentManifest=28,453ms`,
`rootCompileResources=17,813ms`,
`rootCompileChildren=10,421ms`,
`materializeWorkspaceResources=121ms`,
`writeCompilerArtifactFiles=7ms`,
`hydrateMs=4,261ms`, and `resolveMs=43ms`. The observed spread across
these three runs is **not** a controlled performance improvement. When
the observer is omitted, initial `performance.now()` calls are now
avoided even on internal production compiler paths. The observer and
test assertions remain unchanged.

The first split measured `compileAgentManifest` before the internal
root-stage observer was added; the nested sample used that observer.
Measured root-stage spans do not claim to be a full CPU profile,
exclusive child costs, or stable cold/warm performance numbers.

## What the observations support

In these two local runs, file writes were approximately 7 ms and did
not account for the large `compileAgent` duration. Manifest normalization
dominated measured `compileAgent`. In the nested sample, the two
largest root scopes were resource normalization (~15.8 s) and compiling
children (~11.1 s). This narrows the next investigation to module
evaluation/loading and per-resource normalization, but it does **not**
identify a specific avoidable operation, prove a Windows-only root
cause, or establish any production latency improvement.

Rolldown's separate `orcel-workflow-transform load` plugin timings
occurred during Vitest processing and must not be conflated with the
measured internal compiler spans.

## Failed / incomplete qualification explicitly retained

- The first clean-worktree Vitest integration start exited Windows
  `0xC0000409` before producing test results. The two successful
  measurements used a single fork worker; do not conceal the failure.
- An independent unit smoke case initially reached its 5s default
  deadline. That is not an integration correctness assertion or proof
  of a compiler regression.
- The invariant guard failed twice (including after the official `build:js`
  succeeded): rule 36 could not find its generated
  `extension-contracts/entrypoints/extension.d.ts` while preparing API reports.
  This remains an unresolved Windows-local qualification gate; neither
  failure has been ignored or the invariant baseline changed.
- No independent Ubuntu profile, CPU sample, native paid LLM review,
  hosted workload, or paired production benchmark is claimed.

## Local qualification and review-tool boundary

- Changed-file `oxlint` passed (exit 0); `oxfmt` formatted five TS files;
  TypeScript `tsc -p packages/orcel/tsconfig.json --noEmit` passed (exit 0);
  `git diff --check` passed.
- Genuine Jev 1.13.0 returned a probabilistic `noul=0.83` (exit 0)
  for a limited risk question about optional local timing. This is not
  a correctness, performance, or security certification.
- Genuine Alibaba OpenCodeReview 1.12.13 `delegate preview` identified
  four source files as reviewable and excluded the test (default path)
  and evidence Markdown (unsupported extension). A rule resolution
  also ran. No credential-backed native LLM review occurred.
- Genuine Graft 0.21.1 source graph build and check passed:
  54 files, 418 nodes, 1,085 edges; the meaning/deep layer was not built.
- PStack executable was not found. Its absence is not represented
  as a successful execution.
- Invariant guard rule 36 failed twice on the Windows worktree; this
  grain is not qualified for normal merge until the guard and exact-head
  CI requirements pass. No Ubuntu measurements have been obtained.

## Required next evidence

1. Measure individual resource-category and child-module load phases,
   then validate the suspected module-evaluation cause with CPU/IO
   profiling and a controlled change to only that cause.
2. Re-run independent Windows cold/warm samples with stable worker and
   ambient-load conditions and compare against equivalent Ubuntu
   runs on immutable heads.
3. Preserve mount identity, isolation, config, extension contract
   failures, retries and authored source behavior; do not increase
   the 60-second case limit to disguise the bottleneck.
4. Require real Jev, Alibaba OCR, Graft, static checks, exact-head
   CI, and independent main CI+Release before closing Issue #31.
5. Keep the separate hosted turn-latency proposal `proposed`.
