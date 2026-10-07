# Paired Workflow stress evidence

Issue: https://github.com/TheHalfMoon/Orcel/issues/17

This is a **measurement-only**, informational path. It does not change Workflow orchestration, provider/model behavior, durable hooks, or streaming semantics.

## Acquisition

The existing manually dispatched **E2E Tests (Vercel)** workflow has an agent-workflow-stress fixture using the deterministic mock model. That fixture already records raw samples from 100 sequential turns and 100 turns across 50 concurrent sessions and retains the original eval artifacts and stress report for 30 days.

For a hosted paired trial, build and deploy _two immutable commits_, ideally in an interleaved or near-contemporaneous sequence with identical environment and Workflow versions. Run the manual hosted fixture once for each SHA; capture the resulting run IDs and exact deployment URLs. Benchmark deployment runs are subject to the existing explicit Vercel credential and zero-cost policy; this repository does **not** silently deploy or require paid services.

Dispatch **Paired Workflow Performance Evidence** with these required inputs:

- base_run_id, head_run_id: existing GitHub Actions runs that each uploaded workflow-stress-performance
- base_sha, head_sha: full 40-character Git commit IDs
- base_deployment_id, head_deployment_id: immutable URLs recorded inside each stress report
- orcel_version, workflow_core_version, workflow_world_version: explicit versions for both arms

GitHub verifies each run against its requested SHA. Capture rejects a mismatched run ID, SHA, deployment URL, or non-mock-model run. Workflow versions are declared inputs checked for equality between arms; a missing authoritative version in an old artifact is **not** proof of the version. Record independently inspected version evidence before drawing causal conclusions.

The workflow downloads existing hosted eval evidence and **does not deploy anything**. It retains the self-contained raw base/head captures, JSON and Markdown summary for 30 days. Every summary is recomputed from the original captures; the summary is not an independent source of truth.

## Direct CLI

From a repository with Node.js 24 or later:

    node --test scripts/workflow-stress-report.test.mjs scripts/paired-workflow-stress.test.mjs

    node scripts/paired-workflow-stress.mjs capture \
      --artifacts /path/to/base/e2e/fixtures/agent-workflow-stress/.orcel/evals \
      --sha BASE_SHA --run-id BASE_RUN_ID \
      --orcel-version ORCEL_VERSION --workflow-core-version WORKFLOW_VERSION \
      --workflow-world-version WORLD_VERSION --deployment-id DEPLOYMENT_URL \
      --report /path/to/base/.artifacts/workflow-stress-report.json \
      --output base-capture.json

Repeat for head, then:

    node scripts/paired-workflow-stress.mjs compare \
      --base base-capture.json --head head-capture.json \
      --summary paired-summary.json --markdown paired-summary.md

Do not invent placeholder values.

## Artifact semantics

- Each capture includes immutable run identity, raw stress metrics, stable per-case IDs, sequential turn depth (the observed preceding turns in that fixture's session), concurrent batch makespan, and explicit phase and topology fields.
- Statistics are informational: mean, p50, p95, concurrent makespan, slope against **observed fixture turn depth**, paired mean delta, and deterministic paired bootstrap 95% confidence interval. The bootstrap seed derives from both SHAs.
- turnSettlementMs is currently the **client-observed send-to-ack** duration, _not_ whole Workflow tail completion. Server acceptance, session/hook readiness, and model-step-start phase timings are null until supported instrumentation provides genuine timestamps.
- Exact durable step, hook/resume, stream-event and serialized byte counters are null unless the original sample explicitly carries an observed count. **Null does not mean zero**. Coverage reports distinguish missing metrics.
- Validation rejects missing modalities, duplicate or unmatched case IDs, incomplete capture structure, non-finite measurements, values altered relative to raw metrics, forged provenance, model mismatches and Workflow version mismatch.
- Samples are never trimmed, winsorized or silently dropped. Control for deployment timing, version skew, depth, cache/warmup and hosted-platform noise before claiming a speedup.

The analysis works with local/CI artifacts when hosted deployment credentials are unavailable. Hosted acquisition is an optional, explicit external gate.
