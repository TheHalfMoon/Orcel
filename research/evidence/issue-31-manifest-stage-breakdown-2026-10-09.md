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

| Stage                           |           First visible split |           Nested stage sample |
| ------------------------------- | ----------------------------: | ----------------------------: |
| `compileAgent` elapsed          |                     34,088 ms |                     27,426 ms |
| `resolveDiscoveryProject`       |                          3 ms |                          2 ms |
| `discoverAgent`                 |                        148 ms |                        118 ms |
| `compileAgentManifest`          |                     33,763 ms |                     27,172 ms |
| `prepareDevelopmentExtensions`  |                  Not measured |                          1 ms |
| `rootCreatePhaseOne`            |                  Not measured |                        194 ms |
| `rootCompileAgentConfig`        |                  Not measured |                          3 ms |
| `rootCompileResources`          |                  Not measured |                     15,824 ms |
| `rootCompileChildren`           |                  Not measured |                     11,142 ms |
| `materializeWorkspaceResources` |                        154 ms |                        117 ms |
| `prepareCompilerArtifacts`      |                         10 ms |                          8 ms |
| `writeCompilerArtifactFiles`    |                          7 ms |                          7 ms |
| Authored module-map hydration   |                      4,787 ms |                      3,956 ms |
| Runtime graph resolve           |                         33 ms |                         26 ms |
| Total `compileRuntimeGraph`     |                     38,908 ms |                     31,408 ms |
| Vitest file duration            |                       65.04 s |                       55.49 s |
| Result                          | 1 passed, 10 filtered, exit 0 | 1 passed, 10 filtered, exit 0 |

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

## Mac reproducibility and timeout-safe incremental phase evidence (2026-10-10)

Authorized `macbook`, macOS, pinned Node v24.15.0, PR #36 exact prior
head `8dec9712e402f6e50b2f94c18120ceee3ed9fd26` in a separate clean
worktree, frozen workspace dependencies reused from the local pnpm store
(2,382 packages; no network downloads) and `@orcel/orcel` JS built.
The existing `isolates configured built-in extension mounts` case was run
_twice_ sequentially with `ORCEL_MOUNT_PHASE_PROFILE=1`, one Vitest fork,
and the checked-in **60-second** case deadline, no timeout overrides.

| macOS attempt                     | Result                               | Case time | Vitest file duration |
| --------------------------------- | ------------------------------------ | --------: | -------------------: |
| First, freshly prepared worktree  | 1 failed / 10 filtered, case timeout | 61,901 ms |              86.12 s |
| Second, same worktree after first | 1 failed / 10 filtered, case timeout | 60,223 ms |             207.14 s |

Both runs returned exit 1 with `Test timed out in 60000ms`. The second
invocation did **not** demonstrate warm-cache improvement; its file-level
report also included substantial module transform and setup overhead.
Vitest durations are **not** equivalent to compiler stage timings. Rolldown
hook spans can overlap. These runs add cross-platform failure evidence but
do not identify an underlying compiler, host, or filesystem root cause.

The prior helper recorded completed `phaseObserver` results only in an
in-memory map, then printed **one** `ORCEL_MOUNT_PHASE_PROFILE` summary
_after_ `compileAgent`, module-map hydration and graph resolution finished.
Neither timed-out run reached this final report. To preserve bounded evidence
from incomplete runs, the test helper now emits
`ORCEL_MOUNT_PHASE_PROGRESS` when compiler invocation begins and for each
**completed** compiler phase callback, with a static phase name and numeric
phase duration / elapsed milliseconds. This logger is present **only when the
original environment opt-in flag is enabled**; ordinary production compiler
calls and default test paths do not enable it. No filesystem paths, agent
content, payloads or model data enter the new logs.

Partial phases remain just that: a missing completion marker **cannot**
prove whether work never began, is CPU-bound or blocked in I/O. Logging has a
small opt-in cost and is not a performance optimization or paired benchmark.
The test assertions, extension mount isolation semantics, 60-second deadline,
production loader behavior and release surface are unchanged. The first post-change **same original isolation case** with the profiler
enabled **PASSED** (1 pass / 10 filtered, exit 0), Vitest file duration
**14.86 seconds**. It emitted `ORCEL_MOUNT_PHASE_PROGRESS` from
`compileAgent.start` through `writeCompilerArtifactFiles`, followed by
`ORCEL_MOUNT_PHASE_PROFILE`. Rounded timings: `compileMs=7262`,
`compileAgentManifest=7233`, `rootCompileResources=3778`,
`rootCompileChildren=3419`, `writeCompilerArtifactFiles=1`,
`hydrateMs=1278`, `resolveMs=14`, `totalMs=8553` milliseconds. An
additional independent existing **smaller fixture** (`keeps state
independent across mounts and context restoration`) also **PASSED** in
profiling mode with phase markers, 10.34 seconds file duration. Running that
same smaller fixture with profiling **disabled** **PASSED** (1 pass / 10
filtered; 6.32 seconds file duration) and emitted **no** new phase or
profile marker.

These successful post-change invocations are **not a performance win**:
separate unpaired runs observed major test/host scheduling variability,
including two earlier unchanged-head 60-second failures. A future
post-change timeout is still required to demonstrate the precise stage
markers preserved when a run aborts mid-compiler, and repeated paired
measurements would be required to attribute a speedup or root cause.

## Mac per-kind resource and per-child opt-in timings (2026-10-10)

An additional bounded diagnostic grain on top of signed PR #36 head
`e14b81e192dde02f2c2f34abe29e04d119e47911` extends the **existing
optional** `CompilerPhaseObserver` names for root-node resources and immediate
root-child subagents. Each completed resource gets a paired start and completion
marker of the form `rootResource.<static-kind>.<ordinal>.<start|done>`; each
immediate root child gets `rootChild.<ordinal>.<start|done>`. Every completion
records a numeric duration in milliseconds and the previously implemented
`ORCEL_MOUNT_PHASE_PROGRESS` logger supplies total elapsed milliseconds.
This does **not** log source identifiers, extension names, filesystem paths,
agent content, model requests, tokens or tool payloads. The phase name type is
restricted to statically enumerated resource kinds and numeric ordinals;
no arbitrary observer-supplied strings are introduced. Calls are gated on
`input.isRoot` and a supplied optional phase observer; ordinary compilation
without an observer has no new callbacks or timestamp reads.

### Mac execution and observed results

In an isolated macOS Git worktree with exact original PR branch, Node v24.15.0,
frozen offline dependencies reused from the local pnpm store and the compiled
package, the existing `isolates configured built-in extension mounts` case
**PASSED**, 1 passed / 10 filtered, unchanged **60,000ms** deadline and a
single Vitest fork. Total Vitest file duration: **22.13 seconds**. All 82
incremental progress records and the final diagnostic summary were emitted:
**66** root resource start/done records (33 root resources), **4** root-child
start/done records (2 root children), plus 12 existing broad phase records.

| Root resource kind | Count | Sum of individually completed durations (ms) | Largest individual (ms) |
| ------------------ | ----: | -------------------------------------------: | ----------------------: |
| tool               |    14 |                                        2,595 |                     628 |
| hook               |     2 |                                        1,572 |                   1,033 |
| sandbox            |     1 |                                          627 |                     627 |
| channel            |     2 |                                          239 |                     232 |
| config             |     1 |                                            0 |                       0 |
| extension          |     2 |                                            0 |                       0 |
| instructions       |     3 |                                            0 |                       0 |
| skill              |     8 |                                            0 |                       0 |

The two immediate root-child durations were **1,612ms** and **2,949ms**.
Those child figures include nested work; do not add them to root resource
elapsed time to infer CPU consumption. The recorded root resource `phaseMs`
values are wall-time spans for serial candidate handling, not exclusive CPU
samples. Zero values mean rounded milliseconds, not proven zero work. These
numbers are **single-run exploratory evidence, not a stable baseline or
measured optimization**; earlier unchanged-head Mac runs failed at the same
60-second deadline.

A separate existing smaller root-mount test (`keeps state independent across
mounts and context restoration`) also **PASSED**, 1 passed / 10 filtered,
with the optional resource-kind timing enabled (7.60s file duration).
With `ORCEL_MOUNT_PHASE_PROFILE` unset, the same smaller test **PASSED**,
1 passed / 10 filtered (10.38s file duration), and emitted **no**
`ORCEL_MOUNT_PHASE_PROGRESS` or final profiler lines. These unpaired
wall-time results are **not** evidence of a speedup or overhead measurement.

Original assertions, workspace extension isolation, mount owner bindings,
normal build/public artifacts, timeout, and GitHub workflow declarations are
unchanged. A future timed-out profiled run can now report the **last started
resource kind and ordinal** without exposing sensitive app source material,
but we do not claim such a post-change failure was observed in this grain.
Do not mark issue #31 resolved or interpret the observations as a proved
compiler performance defect or repair.
