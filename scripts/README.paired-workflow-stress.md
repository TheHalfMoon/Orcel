# Paired Workflow stress evidence

Issue: https://github.com/TheHalfMoon/Orcel/issues/17

A/A calibration safety follow-up: https://github.com/TheHalfMoon/Orcel/issues/23

This is a **measurement-only**, informational path. It does not change Workflow orchestration, provider/model behavior, durable hooks, or streaming semantics.

## Acquisition

The existing manually dispatched **E2E Tests (Vercel)** workflow has an agent-workflow-stress fixture using the deterministic mock model. That fixture already records raw samples from 100 sequential turns and 100 turns across 50 concurrent sessions and retains the original eval artifacts and stress report for 30 days.

For a hosted paired trial, build and deploy _two immutable commits_, ideally in an interleaved or near-contemporaneous sequence with identical environment and Workflow versions. Run the manual hosted fixture once for each SHA; capture the resulting run IDs and exact deployment URLs. Benchmark deployment runs are subject to the existing explicit Vercel credential and zero-cost policy; this repository does **not** silently deploy or require paid services.

Dispatch **Paired Workflow Performance Evidence** with these required inputs:

- comparison_mode: `base-head` (default) or `aa` (explicit same-code A/A diagnostic)

- base_run_id, head_run_id: existing GitHub Actions runs that each uploaded workflow-stress-performance
- base_sha, head_sha: full 40-character Git commit IDs
- base_deployment_id, head_deployment_id: immutable URLs recorded inside each stress report
- No manual version inputs: each capture derives the Orcel, @workflow/core, @workflow/world and @workflow/world-vercel versions from the source report, which records its own checked-out package manifest.

GitHub verifies that each source is a successful manually dispatched Vercel E2E run; its run ID, SHA and run attempt must agree with the source report. Each new hosted stress report records the package versions directly from its checked-out packages/orcel/package.json. Capture rejects a mismatched run ID, SHA, deployment URL, non-mock-model run, or a missing source-backed version. Metadata versions are never overridden by manually typed values. A legacy report without the source-backed version fields fails closed; it cannot qualify a claimed version. Workflow versions must match across arms before statistical comparison. Orcel versions may differ when comparing two commits. The workflow records the run attempt from the original report.

**A/A diagnostics:** select `aa` to compare two independently identified successful hosted stress runs for the **same immutable commit SHA**, Orcel/Workflow dependency versions and deterministic mock model. The action requires two different GitHub run IDs; the direct CLI also accepts independently archived attempts of one run. GitHub's manual hosted fixture deploys a fresh preview on each run, so two A/A runs may have different immutable deployment URLs. The report explicitly records whether deployment identities matched; when they differ, A/A includes deployment-to-deployment variation, and no isolated environment noise-floor or performance gate may be claimed. A single A/A pair never establishes a calibrated noise floor. Do not start hosted runs without the existing explicit zero-cost policy and credentials.

The workflow downloads existing hosted eval evidence and **does not deploy anything**. It retains the self-contained raw base/head captures, JSON and Markdown summary for 30 days. Every summary is recomputed from the original captures; the summary is not an independent source of truth.

## Direct CLI

From a repository with Node.js 24 or later:

    node --test scripts/workflow-stress-report.test.mjs scripts/paired-workflow-stress.test.mjs

    node scripts/paired-workflow-stress.mjs capture \
      --artifacts /path/to/base/e2e/fixtures/agent-workflow-stress/.orcel/evals \
      --sha BASE_SHA --run-id BASE_RUN_ID --run-attempt BASE_RUN_ATTEMPT \
      --deployment-id DEPLOYMENT_URL \
      --report /path/to/base/.artifacts/workflow-stress-report.json \
      --output base-capture.json

Repeat for head, then:

    node scripts/paired-workflow-stress.mjs compare \
      --base base-capture.json --head head-capture.json \
      --summary paired-summary.json --markdown paired-summary.md

For two independent captures of the same SHA, select A/A mode explicitly:

    node scripts/paired-workflow-stress.mjs compare \
      --base aa-run-1.json --head aa-run-2.json \
      --summary aa-summary.json --markdown aa-summary.md \
      --comparison-mode aa

Default base/head mode rejects equal commit SHAs. A/A rejects different SHAs, different Orcel versions, and a repeated identical run ID plus attempt; its raw evidence and outcome remain reproducible. Do not invent placeholder values.

## Artifact semantics

- Each capture includes immutable run identity, raw stress metrics, stable per-case IDs, sequential turn depth (the observed preceding turns in that fixture's session), concurrent batch makespan, and explicit phase and topology fields.
- Statistics are informational: mean, p50, p95, concurrent makespan, a slope against **the observed sequential turn number** (confounded with elapsed time and queue/warming effects; not a causal history-depth coefficient), paired mean delta, and a deterministic **exploratory 95% per-turn bootstrap interval**. The bootstrap seed derives from both SHAs. The JSON retains its existing `pairedMeanDelta95CiMs` field for compatibility, but it is **not** an independent-run confidence interval. All reports now include `inference.classification=exploratory-uncalibrated`, `isPerformanceGate=false` and `isIndependentRunConfidenceInterval=false`. A hundred turns of one sequential session and two turns per concurrent session are statistically dependent; they are **not** 200 independent hosted replications. Calibrated inferential intervals require independent repeated, balanced hosted runs and an observed A/A noise floor. Neither a single A/A pair nor a base/head pair authorizes a regression gate.
- turnSettlementMs is currently the **client-observed send-to-ack** duration, _not_ whole Workflow tail completion. Server acceptance, session/hook readiness, and model-step-start phase timings are null until supported instrumentation provides genuine timestamps.
- The stress fixture records `streamEventCount` directly from the eval driver's completed per-turn event array, providing an exact count of **client-observed stream events**. This is not equivalent to Workflow durable event writes or persistence operations. Durable step, hook/resume, serialized-byte and any other unobserved counters remain null unless the raw sample explicitly carries a source-backed observation. **Null does not mean zero**; coverage reports distinguish missing metrics.
- Validation rejects missing modalities, duplicate or unmatched case IDs, incomplete capture structure, non-finite measurements, values altered relative to raw metrics, forged provenance, model mismatches and Workflow version mismatch.
- Samples are never trimmed, winsorized or silently dropped. Control for deployment timing, version skew, depth, cache/warmup and hosted-platform noise before claiming a speedup.

The analysis works with local/CI artifacts when hosted deployment credentials are unavailable. Hosted acquisition is an optional, explicit external gate.
