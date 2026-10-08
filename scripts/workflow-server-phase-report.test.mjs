import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createServerPhaseObserver } from "../e2e/fixtures/agent-workflow-stress/agent/lib/server-phase-observer.ts";
import {
  SERVER_PHASE_LOG_PREFIX,
  createServerPhaseReport,
  main,
  parseServerPhaseLog,
} from "./workflow-server-phase-report.mjs";

const domainA = "process-domain-a";
const domainB = "process-domain-b";
function makeObserver(domain, times, sink) {
  let i = 0;
  return createServerPhaseObserver({
    clockDomainId: domain,
    clock: () => times[i++],
    emit: (record) => sink.push(record),
  });
}
const turn = (type, sessionId = "session-1", turnId = "turn-1", attemptId = "attempt-1") => {
  if (type === "model.call.started")
    return {
      type,
      scope: { sessionId, turnId, attemptId },
      // This secret-like field must never enter the phase output.
      input: { text: "PRIVATE_PROMPT" },
    };
  return { type, sessionId, turnId, message: "PRIVATE_PROMPT" };
};

test("measures genuinely observed local handler times from an opt-in mock lifecycle", () => {
  const events = [];
  const observer = makeObserver(domainA, [10, 25, 31, 48], events);
  observer.observe(turn("turn.started"));
  observer.observe(turn("model.call.started"));
  observer.observe(turn("model.call.started", "session-1", "turn-1", "attempt-2"));
  observer.observe(turn("turn.completed"));
  const text =
    "unrelated log\n" +
    events.map((event) => "log: " + SERVER_PHASE_LOG_PREFIX + JSON.stringify(event)).join("\n");
  assert.doesNotMatch(text, /PRIVATE_PROMPT/);
  const evidence = createServerPhaseReport(parseServerPhaseLog(text));
  assert.equal(evidence.sourceEventCount, 4);
  assert.equal(evidence.clockDomainCount, 1);
  assert.equal(evidence.coverage.turnStartToFirstModelHandlerMs.measured, 1);
  assert.equal(evidence.cases[0].turnStartToFirstModelHandlerMs, 15);
  assert.equal(evidence.cases[0].turnStartToTerminalHandlerMs, 38);
  assert.equal(evidence.cases[0].firstModelAttemptId, "attempt-1");
  assert.equal(evidence.cases[0].observedModelCallCount, 2);
  assert.match(evidence.interpretation, /Not HTTP ingress/);
  assert.equal(evidence.unobservedBoundaries.httpReceiptMs, null);
  assert.equal(evidence.unobservedBoundaries.hookReadyMs, null);
  assert.equal(evidence.unobservedBoundaries.trueModelExecutionStartMs, null);
  assert.equal(evidence.unobservedBoundaries.durableStepWrites, null);
});

test("interleaved concurrent sessions stay correlated by opaque session and turn IDs", () => {
  const events = [];
  const observer = makeObserver(domainA, [5, 6, 9, 13, 17, 21], events);
  observer.observe(turn("turn.started", "session-a", "turn-1"));
  observer.observe(turn("turn.started", "session-b", "turn-1"));
  observer.observe(turn("model.call.started", "session-b", "turn-1"));
  observer.observe(turn("model.call.started", "session-a", "turn-1"));
  observer.observe(turn("turn.completed", "session-b", "turn-1"));
  observer.observe(turn("turn.completed", "session-a", "turn-1"));
  const report = createServerPhaseReport(events);
  assert.equal(report.cases.length, 2);
  assert.deepEqual(
    report.cases.map((row) => [row.sessionId, row.turnStartToFirstModelHandlerMs]),
    [
      ["session-a", 8],
      ["session-b", 3],
    ],
  );
  assert.equal(report.coverage.turnStartToTerminalHandlerMs.measured, 2);
});

test("different worker domains and worker restarts never produce cross-clock durations", () => {
  const rows = [];
  makeObserver(domainA, [10], rows).observe(turn("turn.started"));
  makeObserver(domainB, [2], rows).observe(turn("model.call.started"));
  makeObserver(domainA, [40], rows).observe(turn("turn.completed"));
  // Two fresh observer objects claiming one domain reuse sequence 1.
  const report = createServerPhaseReport(rows);
  assert.equal(report.cases[0].turnStartToFirstModelHandlerMs, null);
  assert.equal(report.cases[0].turnStartToTerminalHandlerMs, null);
  assert.equal(report.cases[0].modelObservationReason, "clock-domain-reused-or-reset");
  assert.equal(report.coverage.turnStartToFirstModelHandlerMs.measured, 0);
  const distinctRows = [];
  makeObserver(domainA, [10, 40], distinctRows).observe(turn("turn.started"));
  makeObserver(domainB, [2], distinctRows).observe(turn("model.call.started"));
  assert.equal(
    createServerPhaseReport(distinctRows).cases[0].modelObservationReason,
    "different-process-clock-domains",
  );
});

test("missing events, duplicate start, retry and reset fail closed instead of manufacturing time", () => {
  const rows = [];
  const observer = makeObserver(domainA, [10, 20, 30, 35], rows);
  observer.observe(turn("turn.started"));
  observer.observe(turn("turn.started"));
  observer.observe(turn("model.call.started"));
  observer.observe(turn("turn.failed"));
  const duplicated = createServerPhaseReport(rows);
  assert.equal(duplicated.cases[0].modelObservationReason, "duplicate-start");
  assert.equal(duplicated.cases[0].turnStartToTerminalHandlerMs, null);
  const reset = [];
  const backwards = makeObserver(domainA, [30, 1], reset);
  backwards.observe(turn("turn.started"));
  backwards.observe(turn("model.call.started"));
  assert.equal(
    createServerPhaseReport(reset).cases[0].modelObservationReason,
    "clock-domain-reused-or-reset",
  );
  const missing = [];
  makeObserver(domainA, [12], missing).observe(turn("model.call.started"));
  assert.equal(createServerPhaseReport(missing).cases[0].modelObservationReason, "missing-start");
});

test("untrusted or content-bearing evidence is rejected, including bad sequence and negative clock", () => {
  const rows = [];
  const observer = makeObserver(domainA, [1], rows);
  observer.observe(turn("turn.started"));
  for (const patch of [
    { content: "PRIVATE_PROMPT" },
    { timestampMs: -3 },
    { clock: "wall" },
    { sequence: 0 },
    { source: "forged" },
  ]) {
    assert.throws(() => createServerPhaseReport([{ ...rows[0], ...patch }]));
  }
  assert.throws(() => parseServerPhaseLog("plain log\n"), /No opt-in/);
  const failed = makeObserver(domainA, [-1], []);
  assert.throws(() => failed.observe(turn("turn.started")), /Invalid local monotonic/);
});

test("CLI writes only JSON evidence from a real observer output, without hidden inference", async () => {
  const dir = await mkdtemp(join(tmpdir(), "orcel-phase-evidence-"));
  try {
    const rows = [];
    const observer = makeObserver(domainA, [4, 8, 15], rows);
    observer.observe(turn("turn.started"));
    observer.observe(turn("model.call.started"));
    observer.observe(turn("turn.completed"));
    const file = join(dir, "server.log");
    const output = join(dir, "observations.json");
    await writeFile(
      file,
      rows.map((row) => SERVER_PHASE_LOG_PREFIX + JSON.stringify(row)).join("\n"),
    );
    await main(["--logs", file, "--output", output]);
    const result = JSON.parse(await readFile(output, "utf8"));
    assert.equal(result.cases[0].turnStartToFirstModelHandlerMs, 4);
    assert.equal(result.cases[0].turnStartToTerminalHandlerMs, 11);
    assert.equal(result.schemaVersion, 1);
    assert.equal(result.coverage.turnStartToTerminalHandlerMs.measured, 1);
    await assert.rejects(main(["--output", output]), /Expected --logs/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
