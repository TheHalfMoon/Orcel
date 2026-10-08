import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  captureWorkflowStressRun,
  createPairedWorkflowReport,
  renderPairedWorkflowMarkdown,
  validateCapture,
} from "./paired-workflow-stress-lib.mjs";
import { main } from "./paired-workflow-stress.mjs";

const baseSha = "a".repeat(40);
const headSha = "b".repeat(40);
function identity(sha, runId = "202") {
  return {
    sha,
    orcelVersion: "0.25.0",
    workflowCoreVersion: "5.0.0-beta.57",
    workflowWorldVersion: "5.0.0-beta.39",
    workflowHostWorldVersion: "5.0.0-beta.52",
    deploymentId: "deployment-" + sha.slice(0, 8),
    runId,
    runAttempt: "1",
    model: "mock",
  };
}
function metrics(offset = 0) {
  return {
    runDirectory: "run-1",
    sequential: {
      artifactPath: "run-1/evals/sequential.json",
      metric: {
        schemaVersion: 1,
        scenario: "sequential",
        fixture: "agent-workflow-stress",
        unit: "milliseconds",
        samples: Array.from({ length: 100 }, (_, index) => ({
          durationMs: 10 + 2 * index + offset,
          turnNumber: index + 1,
        })),
      },
    },
    concurrent: {
      artifactPath: "run-1/evals/concurrent.json",
      metric: {
        schemaVersion: 1,
        scenario: "concurrent",
        fixture: "agent-workflow-stress",
        unit: "milliseconds",
        batches: [
          {
            turnNumber: 1,
            batchDurationMs: 20 + offset,
            samples: Array.from({ length: 50 }, (_, index) => ({
              sessionNumber: index + 1,
              durationMs: 17 + offset,
            })),
          },
          {
            turnNumber: 2,
            batchDurationMs: 22 + offset,
            samples: Array.from({ length: 50 }, (_, index) => ({
              sessionNumber: index + 1,
              durationMs: 19 + offset,
            })),
          },
        ],
      },
    },
  };
}
function captures() {
  return [
    captureWorkflowStressRun(metrics(), identity(baseSha, "202")),
    captureWorkflowStressRun(metrics(5), identity(headSha, "203")),
  ];
}

test("captures all raw per-case evidence and explicit phase/topology unknowns", () => {
  const [capture] = captures();
  assert.equal(capture.cases.length, 200);
  assert.equal(capture.batches.length, 2);
  assert.equal(capture.cases[0].turnDepth, 0);
  assert.equal(capture.cases[3].turnDepth, 3);
  assert.equal(capture.cases[0].phases.requestAcceptanceMs, null);
  assert.equal(capture.cases[0].phases.sessionHookReadyMs, null);
  assert.equal(capture.cases[0].phases.turnModelStepStartMs, null);
  assert.equal(capture.cases[0].phases.turnSettlementMs, 10);
  assert.equal(capture.cases[0].topology.stepCount, null);
  assert.deepEqual(validateCapture(capture), capture);
});

test("paired statistics are reproducible, including a deterministic 95% CI and depth slope", () => {
  const [base, head] = captures();
  const result = createPairedWorkflowReport(base, head, { bootstrapDraws: 200 });
  assert.deepEqual(result, createPairedWorkflowReport(base, head, { bootstrapDraws: 200 }));
  assert.equal(result.pairCount, 200);
  assert.equal(result.statistics.pairedMeanDeltaMs, 5);
  assert.equal(result.statistics.pairedMeanDelta95CiMs.lowerMs, 5);
  assert.equal(result.statistics.pairedMeanDelta95CiMs.upperMs, 5);
  assert.equal(result.statistics.turnDepthSlopeMsPerTurn.base, 2);
  assert.equal(result.statistics.turnDepthSlopeMsPerTurn.head, 2);
  assert.equal(result.statistics.concurrentMakespan.deltaMeanMs, 5);
  assert.equal(result.phaseCoverage.requestAcceptanceMs.base, 0);
  assert.match(renderPairedWorkflowMarkdown(result), /not zero/);
  assert.match(renderPairedWorkflowMarkdown(result), /Base commit/);
});

test("rejects missing, duplicated, unmatched, or tampered per-case raw evidence", () => {
  const [base, head] = captures();
  const corrupted = structuredClone(head);
  corrupted.cases[0].durationMs += 1;
  assert.throws(() => createPairedWorkflowReport(base, corrupted), /disagree/);
  const duplicate = structuredClone(base);
  duplicate.rawMetrics.concurrent = undefined;
  assert.throws(() => validateCapture(duplicate), /Missing sequential or concurrent/);
  const unmatched = structuredClone(head);
  unmatched.rawMetrics.sequential.samples.pop();
  unmatched.cases = unmatched.cases.filter((item) => item.caseId !== "sequential/0100");
  assert.throws(() => createPairedWorkflowReport(base, unmatched), /Missing sequential/);
  const bad = structuredClone(base);
  bad.rawMetrics.sequential.samples[1].durationMs = Number.NaN;
  assert.throws(() => validateCapture(bad), /Invalid sequential duration/);
});

test("rejects spoofed or incomplete identity and incompatible mock/provider baselines", () => {
  const [base, head] = captures();
  assert.throws(
    () => captureWorkflowStressRun(metrics(), { ...identity(baseSha), sha: "main" }),
    /SHA/,
  );
  assert.throws(
    () => captureWorkflowStressRun(metrics(), { ...identity(baseSha), model: "live-provider" }),
    /mock-model/,
  );
  assert.throws(
    () => createPairedWorkflowReport(base, { ...head, identity: base.identity }),
    /distinct immutable/,
  );
  const changed = structuredClone(head);
  changed.identity.workflowCoreVersion = "6.0.0";
  assert.throws(() => createPairedWorkflowReport(base, changed), /Incompatible/);
});

test("CLI captures authenticated report inputs and reproduces exact summary from JSON", async () => {
  const root = await mkdtemp(join(tmpdir(), "orcel-paired-test-"));
  try {
    const output = join(root, "artifacts");
    const run = join(output, "run-1", "evals");
    await mkdir(run, { recursive: true });
    const sample = metrics();
    await writeFile(
      join(run, "seq.json"),
      JSON.stringify({
        result: {
          logs: ["ORCEL_WORKFLOW_STRESS_METRIC=" + JSON.stringify(sample.sequential.metric)],
        },
      }),
    );
    await writeFile(
      join(run, "con.json"),
      JSON.stringify({
        result: {
          logs: ["ORCEL_WORKFLOW_STRESS_METRIC=" + JSON.stringify(sample.concurrent.metric)],
        },
      }),
    );
    const report = join(root, "original-report.json");
    await writeFile(
      report,
      JSON.stringify({
        metadata: {
          sha: baseSha,
          runId: "202",
          attempt: "1",
          model: "mock",
          orcelVersion: "0.25.0",
          workflowCoreVersion: "5.0.0-beta.57",
          workflowWorldVersion: "5.0.0-beta.39",
          workflowHostWorldVersion: "5.0.0-beta.52",
          deploymentId: "deployment-" + baseSha.slice(0, 8),
        },
      }),
    );
    const captured = join(root, "captured.json");
    const args = [
      "capture",
      "--artifacts",
      output,
      "--sha",
      baseSha,
      "--deployment-id",
      identity(baseSha).deploymentId,
      "--run-id",
      "202",
      "--run-attempt",
      "1",
      "--report",
      report,
      "--output",
      captured,
    ];
    await main(args);
    const saved = JSON.parse(await readFile(captured, "utf8"));
    assert.equal(saved.cases.length, 200);
    const head = captureWorkflowStressRun(metrics(5), identity(headSha, "203"));
    const headPath = join(root, "head.json");
    await writeFile(headPath, JSON.stringify(head));
    const summary = join(root, "summary.json");
    const markdown = join(root, "summary.md");
    const cmp = [
      "compare",
      "--base",
      captured,
      "--head",
      headPath,
      "--summary",
      summary,
      "--markdown",
      markdown,
    ];
    await main(cmp);
    const first = await readFile(summary, "utf8");
    await main(cmp);
    assert.equal(await readFile(summary, "utf8"), first);
    assert.match(await readFile(markdown, "utf8"), /Exploratory 95% per-turn bootstrap interval/i);
    const broken = [...args];
    broken[broken.indexOf("--sha") + 1] = headSha;
    await assert.rejects(main(broken), /provenance/);
    const forgedAttempt = [...args];
    forgedAttempt[forgedAttempt.indexOf("--run-attempt") + 1] = "2";
    await assert.rejects(main(forgedAttempt), /provenance/);
    const missingVersion = JSON.parse(await readFile(report, "utf8"));
    delete missingVersion.metadata.workflowCoreVersion;
    await writeFile(report, JSON.stringify(missingVersion));
    await assert.rejects(main(args), /Missing workflowCoreVersion/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("preserves genuine per-case phase and durable topology observations without inventing other counters", () => {
  const observed = metrics();
  observed.sequential.metric.samples[0].phases = {
    requestAcceptanceMs: 1,
    sessionHookReadyMs: 2,
    turnModelStepStartMs: 4,
    turnSettlementMs: 10,
  };
  observed.sequential.metric.samples[0].topology = {
    stepCount: 5,
    hookResumeCount: 2,
    streamEventCount: 9,
    serializedInputBytes: 120,
    serializedOutputBytes: 88,
  };
  const base = captureWorkflowStressRun(observed, identity(baseSha));
  const head = captureWorkflowStressRun(metrics(5), identity(headSha, "203"));
  const report = createPairedWorkflowReport(base, head);
  assert.equal(base.cases[0].phases.requestAcceptanceMs, 1);
  assert.equal(base.cases[0].topology.stepCount, 5);
  assert.equal(base.cases[0].topology.streamEventCount, 9);
  assert.equal(base.cases[1].phases.requestAcceptanceMs, null);
  assert.deepEqual(report.phaseCoverage.requestAcceptanceMs, { base: 1, head: 0 });
  assert.deepEqual(report.topologyCoverage.stepCount, { base: 1, head: 0 });
  observed.sequential.metric.samples[0].phases.turnModelStepStartMs = 99;
  assert.throws(
    () => captureWorkflowStressRun(observed, identity(baseSha)),
    /Phase exceeds turn duration/,
  );
});

test("refuses truncated, reordered, or duplicate stress fixture samples", () => {
  const truncatedSequential = metrics();
  truncatedSequential.sequential.metric.samples.pop();
  assert.throws(
    () => captureWorkflowStressRun(truncatedSequential, identity(baseSha)),
    /Missing sequential or concurrent/,
  );
  const missingConcurrent = metrics();
  missingConcurrent.concurrent.metric.batches[0].samples.pop();
  assert.throws(
    () => captureWorkflowStressRun(missingConcurrent, identity(baseSha)),
    /Malformed concurrent batch/,
  );
  const swappedSequential = metrics();
  [swappedSequential.sequential.metric.samples[1], swappedSequential.sequential.metric.samples[2]] =
    [
      swappedSequential.sequential.metric.samples[2],
      swappedSequential.sequential.metric.samples[1],
    ];
  assert.throws(
    () => captureWorkflowStressRun(swappedSequential, identity(baseSha)),
    /Invalid sequential turn depth/,
  );
  const duplicateSession = metrics();
  duplicateSession.concurrent.metric.batches[1].samples[49].sessionNumber = 1;
  assert.throws(
    () => captureWorkflowStressRun(duplicateSession, identity(baseSha)),
    /Invalid session number/,
  );
  const missingBatch = metrics();
  missingBatch.concurrent.metric.batches.pop();
  assert.throws(
    () => captureWorkflowStressRun(missingBatch, identity(baseSha)),
    /Missing sequential or concurrent/,
  );
});

test("hosted reporter sources package versions from checkout and capture enforces them", async () => {
  const { execFileSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const root = await mkdtemp(join(tmpdir(), "orcel-paired-versions-"));
  try {
    const artifactRoot = join(root, "eval-artifacts");
    const evalRoot = join(artifactRoot, "test-run", "evals");
    await mkdir(evalRoot, { recursive: true });
    const fixture = metrics();
    for (const scenario of ["sequential", "concurrent"]) {
      await writeFile(
        join(evalRoot, scenario + ".json"),
        JSON.stringify({
          result: {
            logs: ["ORCEL_WORKFLOW_STRESS_METRIC=" + JSON.stringify(fixture[scenario].metric)],
          },
        }),
      );
    }
    const sourcePackage = JSON.parse(
      await readFile(new URL("../packages/orcel/package.json", import.meta.url), "utf8"),
    );
    const report = join(root, "source-report.json");
    const deploymentId = "https://immutable-benchmark-example.vercel.app";
    execFileSync(
      process.execPath,
      [
        fileURLToPath(new URL("./workflow-stress-report.mjs", import.meta.url)),
        "--artifacts",
        artifactRoot,
        "--json",
        report,
      ],
      {
        env: {
          ...process.env,
          GITHUB_SHA: baseSha,
          GITHUB_RUN_ID: "202",
          GITHUB_RUN_ATTEMPT: "1",
          ORCEL_E2E_MODEL: "mock",
          ORCEL_STRESS_DEPLOYMENT_URL: deploymentId,
        },
        stdio: "pipe",
      },
    );
    const reportJson = JSON.parse(await readFile(report, "utf8"));
    assert.equal(reportJson.metadata.orcelVersion, sourcePackage.version);
    assert.equal(
      reportJson.metadata.workflowCoreVersion,
      sourcePackage.devDependencies["@workflow/core"],
    );
    assert.equal(
      reportJson.metadata.workflowWorldVersion,
      sourcePackage.devDependencies["@workflow/world"],
    );
    assert.equal(
      reportJson.metadata.workflowHostWorldVersion,
      sourcePackage.devDependencies["@workflow/world-vercel"],
    );
    const output = join(root, "captured.json");
    const args = [
      "capture",
      "--artifacts",
      artifactRoot,
      "--sha",
      baseSha,
      "--deployment-id",
      deploymentId,
      "--run-id",
      "202",
      "--run-attempt",
      "1",
      "--report",
      report,
      "--output",
      output,
    ];
    await main(args);
    assert.equal(JSON.parse(await readFile(output, "utf8")).cases.length, 200);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("A/A calibration is explicit, run-distinct, reproducible, and never inferential", () => {
  const base = captureWorkflowStressRun(metrics(), identity(baseSha, "202"));
  const repeat = captureWorkflowStressRun(metrics(3), identity(baseSha, "203"));
  assert.throws(() => createPairedWorkflowReport(base, repeat), /distinct immutable SHAs/);
  const report = createPairedWorkflowReport(base, repeat, {
    bootstrapDraws: 200,
    comparisonMode: "aa",
  });
  assert.deepEqual(
    report,
    createPairedWorkflowReport(base, repeat, {
      bootstrapDraws: 200,
      comparisonMode: "aa",
    }),
  );
  assert.equal(report.comparisonMode, "aa");
  assert.equal(report.statistics.pairedMeanDeltaMs, 3);
  assert.equal(report.inference.isPerformanceGate, false);
  assert.equal(report.inference.isIndependentRunConfidenceInterval, false);
  assert.equal(report.inference.deploymentIdentityMatches, true);
  assert.match(renderPairedWorkflowMarkdown(report), /A\/A calibration trial/);
  assert.match(renderPairedWorkflowMarkdown(report), /not a run-level CI/);
  const separateDeployment = structuredClone(repeat);
  separateDeployment.identity.deploymentId = "independent-immutable-deployment";
  const mixedDeploymentAa = createPairedWorkflowReport(base, separateDeployment, {
    comparisonMode: "aa",
  });
  assert.equal(mixedDeploymentAa.inference.deploymentIdentityMatches, false);
  assert.match(
    renderPairedWorkflowMarkdown(mixedDeploymentAa),
    /deployment noise is not separated/,
  );

  assert.throws(
    () => createPairedWorkflowReport(base, repeat, { comparisonMode: "unsupported" }),
    /Unsupported comparison mode/,
  );
  const duplicateRun = structuredClone(repeat);
  duplicateRun.identity.runId = base.identity.runId;
  assert.throws(
    () => createPairedWorkflowReport(base, duplicateRun, { comparisonMode: "aa" }),
    /independently identifiable runs/,
  );
  duplicateRun.identity.runAttempt = "2";
  assert.equal(
    createPairedWorkflowReport(base, duplicateRun, { comparisonMode: "aa" }).comparisonMode,
    "aa",
  );
  const differentPackage = structuredClone(repeat);
  differentPackage.identity.orcelVersion = "99.0.0";
  assert.throws(
    () => createPairedWorkflowReport(base, differentPackage, { comparisonMode: "aa" }),
    /identical Orcel version/,
  );
  const [otherCommit] = captures();
  const differentSha = captureWorkflowStressRun(metrics(3), identity(headSha, "203"));
  assert.throws(
    () => createPairedWorkflowReport(otherCommit, differentSha, { comparisonMode: "aa" }),
    /identical immutable SHA/,
  );
});

test("CLI A/A output is reproducible and mismatched modes fail closed", async () => {
  const root = await mkdtemp(join(tmpdir(), "orcel-aa-calibration-"));
  try {
    const base = join(root, "base.json");
    const head = join(root, "head.json");
    const summary = join(root, "summary.json");
    const markdown = join(root, "summary.md");
    await writeFile(
      base,
      JSON.stringify(captureWorkflowStressRun(metrics(), identity(baseSha, "202"))),
    );
    await writeFile(
      head,
      JSON.stringify(captureWorkflowStressRun(metrics(0.5), identity(baseSha, "203"))),
    );
    const args = [
      "compare",
      "--base",
      base,
      "--head",
      head,
      "--summary",
      summary,
      "--markdown",
      markdown,
      "--comparison-mode",
      "aa",
    ];
    await main(args);
    assert.equal(JSON.parse(await readFile(summary, "utf8")).comparisonMode, "aa");
    assert.match(await readFile(markdown, "utf8"), /Exploratory/);
    await assert.rejects(main(args.slice(0, -2)), /distinct immutable SHAs/);
    await assert.rejects(main([...args.slice(0, -1), "broken"]), /Unsupported comparison mode/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
