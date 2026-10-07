import { createHash } from "node:crypto";

const SHA = /^[0-9a-f]{40}$/;
const PHASES = [
  "requestAcceptanceMs",
  "sessionHookReadyMs",
  "turnModelStepStartMs",
  "turnSettlementMs",
];
const TOPOLOGY = [
  "stepCount",
  "hookResumeCount",
  "streamEventCount",
  "serializedInputBytes",
  "serializedOutputBytes",
];

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") throw new Error("Missing " + name);
  return value;
}

function finiteNonnegative(value, name) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error("Invalid " + name);
  }
  return value;
}

export function validateIdentity(identity) {
  if (!identity || typeof identity !== "object" || !SHA.test(identity.sha)) {
    throw new Error("Invalid immutable git SHA");
  }
  for (const name of [
    "orcelVersion",
    "workflowCoreVersion",
    "workflowWorldVersion",
    "deploymentId",
    "runId",
  ]) {
    requireText(identity[name], name);
  }
  if (!/^[1-9][0-9]*$/.test(String(identity.runAttempt ?? ""))) {
    throw new Error("Missing immutable GitHub run attempt");
  }
  if (identity.model !== "mock")
    throw new Error("Only deterministic mock-model measurements are supported");
  return identity;
}

function phaseCounters(sample) {
  const provided = sample.phases ?? {};
  const result = {};
  for (const name of PHASES) {
    const value = Object.hasOwn(provided, name) ? provided[name] : null;
    if (value !== null) finiteNonnegative(value, name);
    if (value !== null && value > sample.durationMs)
      throw new Error("Phase exceeds turn duration: " + name);
    result[name] = value;
  }
  // The eval observes the client send-to-ack boundary, not Nitro ingress.
  if (result.turnSettlementMs === null) result.turnSettlementMs = sample.durationMs;
  return result;
}

function topologyCounters(sample) {
  const provided = sample.topology ?? {};
  const result = {};
  for (const name of TOPOLOGY) {
    const value = Object.hasOwn(provided, name) ? provided[name] : null;
    if (value !== null && (!Number.isSafeInteger(value) || value < 0)) {
      throw new Error("Invalid topology counter: " + name);
    }
    result[name] = value;
  }
  return result;
}

function extractCases(rawMetrics) {
  const seq = rawMetrics?.sequential;
  const con = rawMetrics?.concurrent;
  if (
    !Array.isArray(seq?.samples) ||
    seq.samples.length < 2 ||
    !Array.isArray(con?.batches) ||
    con.batches.length < 1
  ) {
    throw new Error("Missing sequential or concurrent raw Workflow stress samples");
  }
  const cases = [];
  let priorDepth = -1;
  const seen = new Set();
  for (const sample of seq.samples) {
    const depth = sample.turnNumber - 1;
    if (!Number.isSafeInteger(depth) || depth < 0 || depth <= priorDepth)
      throw new Error("Invalid sequential turn depth");
    priorDepth = depth;
    finiteNonnegative(sample.durationMs, "sequential duration");
    cases.push({
      caseId: "sequential/" + String(sample.turnNumber).padStart(4, "0"),
      mode: "sequential",
      turnDepth: depth,
      durationMs: sample.durationMs,
      phases: phaseCounters(sample),
      topology: topologyCounters(sample),
    });
  }
  const batches = [];
  for (const batch of con.batches) {
    if (
      !Number.isSafeInteger(batch.turnNumber) ||
      batch.turnNumber < 1 ||
      !Array.isArray(batch.samples) ||
      batch.samples.length === 0
    ) {
      throw new Error("Malformed concurrent batch");
    }
    finiteNonnegative(batch.batchDurationMs, "concurrent makespan");
    const batchId = "concurrent/batch-" + batch.turnNumber;
    batches.push({ batchId, makespanMs: batch.batchDurationMs });
    for (const sample of batch.samples) {
      if (!Number.isSafeInteger(sample.sessionNumber) || sample.sessionNumber < 1)
        throw new Error("Invalid session number");
      finiteNonnegative(sample.durationMs, "concurrent duration");
      cases.push({
        caseId: batchId + "/session-" + String(sample.sessionNumber).padStart(4, "0"),
        mode: "concurrent",
        turnDepth: batch.turnNumber - 1,
        durationMs: sample.durationMs,
        phases: phaseCounters(sample),
        topology: topologyCounters(sample),
      });
    }
  }
  for (const item of cases) {
    if (seen.has(item.caseId)) throw new Error("Duplicate case identifier: " + item.caseId);
    seen.add(item.caseId);
  }
  const uniqueBatch = new Set(batches.map((b) => b.batchId));
  if (uniqueBatch.size !== batches.length) throw new Error("Duplicate concurrent batch");
  return { cases, batches };
}

export function captureWorkflowStressRun(metrics, identity) {
  validateIdentity(identity);
  const rawMetrics = {
    sequential: metrics?.sequential?.metric,
    concurrent: metrics?.concurrent?.metric,
  };
  const { cases, batches } = extractCases(rawMetrics);
  return {
    schemaVersion: 1,
    identity: structuredClone(identity),
    sources: {
      sequential: metrics.sequential.artifactPath ?? null,
      concurrent: metrics.concurrent.artifactPath ?? null,
    },
    rawMetrics: structuredClone(rawMetrics),
    cases,
    batches,
  };
}

export function validateCapture(capture) {
  if (capture?.schemaVersion !== 1) throw new Error("Unsupported capture schema");
  validateIdentity(capture.identity);
  const expected = extractCases(capture.rawMetrics);
  if (
    JSON.stringify(capture.cases) !== JSON.stringify(expected.cases) ||
    JSON.stringify(capture.batches) !== JSON.stringify(expected.batches)
  ) {
    throw new Error("Capture cases disagree with raw metrics");
  }
  return capture;
}

function mean(xs) {
  return xs.reduce((sum, x) => sum + x, 0) / xs.length;
}
function percentile(xs, probability) {
  const sorted = [...xs].sort((a, b) => a - b);
  const p = (sorted.length - 1) * probability;
  const lo = Math.floor(p);
  const hi = Math.ceil(p);
  return sorted[lo] + (sorted[hi] - sorted[lo]) * (p - lo);
}
function slope(points) {
  if (points.length < 2) throw new Error("Insufficient sequential depth samples");
  const x = mean(points.map((p) => p[0]));
  const y = mean(points.map((p) => p[1]));
  let top = 0;
  let bottom = 0;
  for (const [depth, duration] of points) {
    top += (depth - x) * (duration - y);
    bottom += (depth - x) ** 2;
  }
  if (bottom === 0) throw new Error("No variation in turn depth");
  return top / bottom;
}
function describe(xs) {
  if (xs.length === 0) throw new Error("Empty measurement group");
  return {
    count: xs.length,
    meanMs: mean(xs),
    p50Ms: percentile(xs, 0.5),
    p95Ms: percentile(xs, 0.95),
  };
}
function ciSeed(baseSha, headSha) {
  return (
    createHash("sha256")
      .update(baseSha + ":" + headSha)
      .digest()
      .readUInt32LE(0) || 1
  );
}
function bootstrapMeanDelta(deltas, seed, draws) {
  let state = seed >>> 0;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const resampled = [];
  for (let i = 0; i < draws; i++) {
    let total = 0;
    for (let j = 0; j < deltas.length; j++) total += deltas[next() % deltas.length];
    resampled.push(total / deltas.length);
  }
  return {
    lowerMs: percentile(resampled, 0.025),
    upperMs: percentile(resampled, 0.975),
    seed,
    draws,
  };
}
function matchById(baseItems, headItems, idKey) {
  const base = new Map(baseItems.map((entry) => [entry[idKey], entry]));
  const head = new Map(headItems.map((entry) => [entry[idKey], entry]));
  if (
    base.size !== baseItems.length ||
    head.size !== headItems.length ||
    base.size !== head.size ||
    [...base.keys()].some((key) => !head.has(key))
  ) {
    throw new Error("Unpaired or duplicate " + idKey + " across immutable captures");
  }
  return [...base.keys()].sort().map((key) => [base.get(key), head.get(key)]);
}
function coverage(rows) {
  return Object.fromEntries(
    PHASES.map((name) => [
      name,
      {
        base: rows.filter(([a]) => a.phases[name] !== null).length,
        head: rows.filter(([, b]) => b.phases[name] !== null).length,
      },
    ]),
  );
}
function topologyCoverage(rows) {
  return Object.fromEntries(
    TOPOLOGY.map((name) => [
      name,
      {
        base: rows.filter(([a]) => a.topology[name] !== null).length,
        head: rows.filter(([, b]) => b.topology[name] !== null).length,
      },
    ]),
  );
}

export function createPairedWorkflowReport(
  baseCapture,
  headCapture,
  { bootstrapDraws = 2000 } = {},
) {
  const base = validateCapture(baseCapture);
  const head = validateCapture(headCapture);
  if (base.identity.sha === head.identity.sha)
    throw new Error("Base and head must have distinct immutable SHAs");
  if (
    base.identity.model !== head.identity.model ||
    base.identity.workflowCoreVersion !== head.identity.workflowCoreVersion ||
    base.identity.workflowWorldVersion !== head.identity.workflowWorldVersion
  ) {
    throw new Error("Incompatible benchmark model or Workflow dependencies");
  }
  if (!Number.isSafeInteger(bootstrapDraws) || bootstrapDraws < 100)
    throw new Error("Invalid bootstrap draws");
  const rows = matchById(base.cases, head.cases, "caseId");
  for (const [a, b] of rows)
    if (a.mode !== b.mode || a.turnDepth !== b.turnDepth)
      throw new Error("Mismatched case semantics");
  const batchRows = matchById(base.batches, head.batches, "batchId");
  const sequentialRows = rows.filter(([a]) => a.mode === "sequential");
  const concurrencyRows = rows.filter(([a]) => a.mode === "concurrent");
  if (sequentialRows.length < 2 || concurrencyRows.length === 0)
    throw new Error("Missing required measurement modes");
  const deltas = rows.map(([a, b]) => b.durationMs - a.durationMs);
  const describeArm = (subset, side) => describe(subset.map((pair) => pair[side].durationMs));
  const s0 = sequentialRows.map(([a]) => [a.turnDepth, a.durationMs]);
  const s1 = sequentialRows.map(([, b]) => [b.turnDepth, b.durationMs]);
  return {
    schemaVersion: 1,
    base: base.identity,
    head: head.identity,
    pairCount: rows.length,
    statistics: {
      all: { base: describeArm(rows, 0), head: describeArm(rows, 1) },
      sequential: { base: describeArm(sequentialRows, 0), head: describeArm(sequentialRows, 1) },
      concurrent: { base: describeArm(concurrencyRows, 0), head: describeArm(concurrencyRows, 1) },
      concurrentMakespan: {
        base: describe(batchRows.map(([a]) => a.makespanMs)),
        head: describe(batchRows.map(([, b]) => b.makespanMs)),
        deltaMeanMs: mean(batchRows.map(([a, b]) => b.makespanMs - a.makespanMs)),
      },
      turnDepthSlopeMsPerTurn: { base: slope(s0), head: slope(s1) },
      pairedMeanDeltaMs: mean(deltas),
      pairedMeanDelta95CiMs: bootstrapMeanDelta(
        deltas,
        ciSeed(base.identity.sha, head.identity.sha),
        bootstrapDraws,
      ),
    },
    phaseCoverage: coverage(rows),
    topologyCoverage: topologyCoverage(rows),
    evidence: {
      baseDigestSha256: createHash("sha256").update(JSON.stringify(base)).digest("hex"),
      headDigestSha256: createHash("sha256").update(JSON.stringify(head)).digest("hex"),
      note: "Client send-to-ack timings are observed. Null phases/topology counters are not observable from this artifact; no server-phase values are inferred.",
    },
  };
}

export function renderPairedWorkflowMarkdown(report) {
  const s = report.statistics;
  const lines = [
    "## Paired Workflow stress benchmark",
    "",
    "> Informational only; the captures are run-specific and immutable. Null counters mean unobserved, not zero.",
    "",
    "| Metric | Base | Head |",
    "| --- | ---: | ---: |",
    ...["all", "sequential", "concurrent", "concurrentMakespan"]
      .map((key) => [
        "| " +
          key +
          " mean (ms) | " +
          s[key].base.meanMs.toFixed(2) +
          " | " +
          s[key].head.meanMs.toFixed(2) +
          " |",
        "| " +
          key +
          " p50 (ms) | " +
          s[key].base.p50Ms.toFixed(2) +
          " | " +
          s[key].head.p50Ms.toFixed(2) +
          " |",
        "| " +
          key +
          " p95 (ms) | " +
          s[key].base.p95Ms.toFixed(2) +
          " | " +
          s[key].head.p95Ms.toFixed(2) +
          " |",
      ])
      .flat(),
    "",
    "Paired mean delta (head - base): " + s.pairedMeanDeltaMs.toFixed(2) + " ms.",
    "95% deterministic paired bootstrap CI: [" +
      s.pairedMeanDelta95CiMs.lowerMs.toFixed(2) +
      ", " +
      s.pairedMeanDelta95CiMs.upperMs.toFixed(2) +
      "] ms.",
    "Turn-depth slope (base / head): " +
      s.turnDepthSlopeMsPerTurn.base.toFixed(3) +
      " / " +
      s.turnDepthSlopeMsPerTurn.head.toFixed(3) +
      " ms per turn.",
    "",
    "Base commit: " +
      report.base.sha +
      " (run " +
      report.base.runId +
      ", deployment " +
      report.base.deploymentId +
      ")",
    "Head commit: " +
      report.head.sha +
      " (run " +
      report.head.runId +
      ", deployment " +
      report.head.deploymentId +
      ")",
    "",
    "Phase observability: " + JSON.stringify(report.phaseCoverage),
    "",
    "Topology observability: " + JSON.stringify(report.topologyCoverage),
    "",
  ];
  return lines.join("\n");
}
