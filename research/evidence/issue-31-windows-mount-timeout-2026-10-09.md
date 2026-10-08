---
issue: https://github.com/TheHalfMoon/Orcel/issues/31
status: stabilization-candidate
last_updated: "2026-10-09"
---

# Windows mounted-extension integration timeout: bounded stabilization

## Actual issue and baseline

At canonical `main` `202f453ff4fd101e0553287ea0c17664a07ad8a4`, post-merge GitHub CI run `37847938104`, attempt 1, failed Windows integration solely on `src/compiler/mounted-extension.integration.test.ts` / `isolates configured built-in extension mounts`: default Vitest 30,000 ms test timeout. The other 1,038 integration tests passed and 2 were skipped. Same-head attempt 2 passed all nine CI jobs with no source change. This is an intermittent timer failure, **not** proof the underlying compiler has been optimized.

Independent local Windows evidence at the previous candidate and/or baseline:

- Prior PR-head Windows CI: targeted case passed in 17.565 seconds.
- Authorized Windows focused reproduction, default 30-second test timeout: FAILED because the case did not complete within the test budget.
- Authorized Windows focused diagnostic with temporary 120-second CLI timeout: PASS at 23.013-second case duration; another focused diagnostic PASS at 24.041 seconds.
- Separate worktree from immutable `e5fdcbdc25a117a48d9b4cc9372cb8fbffc83158`, frozen offline pnpm (zero downloaded packages), successfully built generated vendor/runtime assets and compiled JavaScript.
- Temporary **local-only** monotonic markers in the exact case with a 120-second **CLI-only** diagnostic timeout produced 1/1 PASS and `ORCEL_MOUNT_DIAGNOSTICS`: app-root setup 9.7583 ms; `compileRuntimeGraph` 20013.9201 ms; second module map load and assertions 2260.3857 ms; total within-test 22284.0688 ms. This experiment was recorded in Issue #31 and the marker code has been **removed from the candidate**.

`compileRuntimeGraph` combines compileAgent, manifest/module-map hydration and graph resolution; these phase measurements do not isolate a root cause _inside_ that function or prove that shared runner contention caused the variance.

## Minimal test-only change

Only this existing heavy compiler integration case gets an explicit **60,000 ms** upper bound. It remains an end-to-end authored-source compile of both configured built-in extension mounts and reload, with all prior assertions unchanged. No suite-wide timeout increase, test skip, mocked compilation, version change, production runtime modification, invariant suppression or hosted-performance claim.

This bounds additional Windows scheduling/IO/compilation variance while retaining a real finite failure deadline. It does **not** establish a source-level compiler speedup, nor permanently solve the root cause of the expensive graph compile. A future performance-focused grain may profile `compileAgent` and hydration individually without weakening this correctness gate.

## Required qualification

Review the narrow diff. Run the identical focused test at its **checked-in** timeout, real TypeScript and formatting/lint checks, genuine Jev + Alibaba OCR delegation and Graft with limitations, full mandatory exact-head GitHub CI and independent post-merge `main` CI+Release. A local invariant failure is a FAIL and must not be called PASS; no test or guard can be suppressed for green output. Persist all observed failures as well as successes.

## Candidate local evidence and review limits

- Exact focused Vitest test at checked-in per-case timeout: first candidate execution **1 PASS / 10 filtered skips**, exit 0 (40.07 s total Vitest file duration including transforms and setup). This case still enforces failure at 60,000 ms. A **second independently executed focused check PASS**, exit 0, with Vitest file duration 31.41 s. The two executions used the checked-in per-case limit with no global/CLI timeout override.
- `tsc -p tsconfig.json --noEmit` **PASS**, exit 0 with generated compiled dependencies from genuine local build. Oxlint on the changed TypeScript test file **PASS**. Oxfmt applied to the narrow source and evidence file.
- Genuine Jev `jev-1.13.0` answered a limited risk question with `noul=0.82`. This is judgment support, not proof of absence of compiler defects.
- Genuine Graft restricted compiler source build: **54 files, 416 nodes, 1081 edges**, freshness `graft check` PASS. No deep meaning layer; graph is not a cross-repository dependency proof.
- Alibaba OpenCodeReview exact-range delegation must be run on the signed candidate. Native provider-backed OCR is credential-blocked on the authorized workstation and cannot be claimed as executed. No PStack CLI was identified in the prior PATH checks.
- The diagnostic environment variable, temporary phase prints and temporary 120s CLI timeout are **not** part of the candidate diff. The test's original assertions remain byte-for-byte unchanged.
