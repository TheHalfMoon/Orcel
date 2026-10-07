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
    workflowWorldVersion: "5.0.0-beta.57",
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
        samples: [10, 12, 14, 16].map((durationMs, index) => ({
          durationMs: durationMs + offset,
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
            samples: [
              { sessionNumber: 1, durationMs: 17 + offset },
              { sessionNumber: 2, durationMs: 18 + offset },
            ],
          },
          {
            turnNumber: 2,
            batchDurationMs: 22 + offset,
            samples: [
              { sessionNumber: 1, durationMs: 19 + offset },
              { sessionNumber: 2, durationMs: 20 + offset },
            ],
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
  assert.equal(capture.cases.length, 8);
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
  assert.equal(result.pairCount, 8);
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
  unmatched.cases = unmatched.cases.filter((item) => item.caseId !== "sequential/0004");
  assert.throws(() => createPairedWorkflowReport(base, unmatched), /Unpaired/);
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
      "--orcel-version",
      "0.25.0",
      "--workflow-core-version",
      "5.0.0-beta.57",
      "--workflow-world-version",
      "5.0.0-beta.57",
      "--deployment-id",
      identity(baseSha).deploymentId,
      "--run-id",
      "202",
      "--report",
      report,
      "--output",
      captured,
    ];
    await main(args);
    const saved = JSON.parse(await readFile(captured, "utf8"));
    assert.equal(saved.cases.length, 8);
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
    assert.match(await readFile(markdown, "utf8"), /paired bootstrap/i);
    const broken = [...args];
    broken[broken.indexOf("--sha") + 1] = headSha;
    await assert.rejects(main(broken), /provenance/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
