import { readFile, mkdir, writeFile } from "node:fs/promises";
import { dirname, parse, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const SERVER_PHASE_LOG_PREFIX = "WORKFLOW_STRESS_SERVER_PHASE=";
const EVENTS = new Set([
  "turn.started",
  "model.call.started",
  "turn.completed",
  "turn.cancelled",
  "turn.failed",
]);
const TERMINALS = new Set(["turn.completed", "turn.cancelled", "turn.failed"]);
const FIELDS = new Set([
  "schemaVersion",
  "source",
  "clock",
  "clockDomainId",
  "sequence",
  "timestampMs",
  "event",
  "sessionId",
  "turnId",
  "attemptId",
]);

export function validateServerPhaseObservation(row) {
  if (!row || typeof row !== "object" || Array.isArray(row)) {
    throw new Error("Invalid server phase observation");
  }
  if (
    row.schemaVersion !== 1 ||
    row.source !== "orcel-instrumentation-handler" ||
    row.clock !== "server-process-monotonic" ||
    !EVENTS.has(row.event)
  ) {
    throw new Error("Untrusted server phase schema or event source");
  }
  if (Object.keys(row).some((key) => !FIELDS.has(key)) || Object.keys(row).length !== FIELDS.size) {
    throw new Error("Unexpected server phase field (no prompt or model content permitted)");
  }
  for (const field of ["sessionId", "turnId", "clockDomainId"]) {
    if (typeof row[field] !== "string" || !row[field] || row[field].length > 256) {
      throw new Error("Invalid opaque server phase field: " + field);
    }
  }
  if (
    !Number.isSafeInteger(row.sequence) ||
    row.sequence < 1 ||
    typeof row.timestampMs !== "number" ||
    !Number.isFinite(row.timestampMs) ||
    row.timestampMs < 0
  )
    throw new Error("Invalid monotonic sequence or timestamp");
  if (
    row.attemptId !== null &&
    (row.event !== "model.call.started" ||
      typeof row.attemptId !== "string" ||
      !row.attemptId ||
      row.attemptId.length > 256)
  )
    throw new Error("Invalid model attempt identity");
  return row;
}

export function decodeServerPhaseLog(bytes) {
  const buffer = Buffer.from(bytes);
  const utf16le = buffer[0] === 0xff && buffer[1] === 0xfe;
  if (buffer[0] === 0xfe && buffer[1] === 0xff) {
    throw new Error("Unsupported UTF-16BE server log encoding");
  }
  const text = utf16le ? buffer.subarray(2).toString("utf16le") : buffer.toString("utf8");
  if (text.includes("\u0000")) {
    throw new Error("Malformed server log encoding");
  }
  return text;
}

export function parseServerPhaseLog(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    const index = line.indexOf(SERVER_PHASE_LOG_PREFIX);
    if (index === -1) continue;
    const row = JSON.parse(line.slice(index + SERVER_PHASE_LOG_PREFIX.length));
    rows.push(validateServerPhaseObservation(row));
  }
  if (rows.length === 0) throw new Error("No opt-in server phase observations found");
  return rows;
}

function observedDelta(starts, ends, ambiguousDomain) {
  if (ambiguousDomain) return { durationMs: null, reason: "clock-domain-reused-or-reset" };
  if (starts.length !== 1)
    return { durationMs: null, reason: starts.length ? "duplicate-start" : "missing-start" };
  if (ends.length === 0) return { durationMs: null, reason: "missing-end" };
  const start = starts[0];
  // Multiple model calls are legitimate. Use the first *observed* call, never
  // interpret it as physical model execution starting inside the provider.
  const end = [...ends].sort((a, b) => a.sequence - b.sequence)[0];
  if (start.clockDomainId !== end.clockDomainId) {
    return { durationMs: null, reason: "different-process-clock-domains" };
  }
  if (end.sequence <= start.sequence || end.timestampMs < start.timestampMs) {
    return { durationMs: null, reason: "non-monotonic-event-order" };
  }
  return { durationMs: end.timestampMs - start.timestampMs, reason: null };
}

export function createServerPhaseReport(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("Server phase evidence cannot be empty");
  }
  const domains = new Map();
  const turns = new Map();
  for (const raw of rows) {
    const row = validateServerPhaseObservation(raw);
    let domain = domains.get(row.clockDomainId);
    if (!domain) {
      domain = { seen: new Set(), readings: [], invalid: false };
      domains.set(row.clockDomainId, domain);
    }
    if (domain.seen.has(row.sequence)) domain.invalid = true;
    domain.seen.add(row.sequence);
    domain.readings.push(row);
    const key = JSON.stringify([row.sessionId, row.turnId]);
    if (!turns.has(key)) turns.set(key, []);
    turns.get(key).push(row);
  }
  for (const domain of domains.values()) {
    domain.readings.sort((a, b) => a.sequence - b.sequence);
    if (
      domain.readings.some(
        (row, i) => i > 0 && row.timestampMs < domain.readings[i - 1].timestampMs,
      )
    ) {
      domain.invalid = true;
    }
  }
  const cases = [...turns.entries()]
    .map(([key, events]) => {
      const [sessionId, turnId] = JSON.parse(key);
      const start = events.filter((x) => x.event === "turn.started");
      const models = events.filter((x) => x.event === "model.call.started");
      const terminals = events.filter((x) => TERMINALS.has(x.event));
      const invalid = events.some((x) => domains.get(x.clockDomainId).invalid);
      const model = observedDelta(start, models, invalid);
      const terminal =
        terminals.length > 1
          ? { durationMs: null, reason: "duplicate-terminal" }
          : observedDelta(start, terminals, invalid);
      return {
        sessionId,
        turnId,
        clockDomainIds: [...new Set(events.map((x) => x.clockDomainId))].sort(),
        turnStartToFirstModelHandlerMs: model.durationMs,
        turnStartToTerminalHandlerMs: terminal.durationMs,
        modelObservationReason: model.reason,
        terminalObservationReason: terminal.reason,
        firstModelAttemptId: models.length
          ? [...models].sort((a, b) => a.sequence - b.sequence)[0].attemptId
          : null,
        observedModelCallCount: models.length,
      };
    })
    .sort((a, b) => a.sessionId.localeCompare(b.sessionId) || a.turnId.localeCompare(b.turnId));
  const coverage = Object.fromEntries(
    ["turnStartToFirstModelHandlerMs", "turnStartToTerminalHandlerMs"].map((name) => [
      name,
      { measured: cases.filter((item) => item[name] !== null).length, total: cases.length },
    ]),
  );
  return {
    schemaVersion: 1,
    evidenceKind: "opt-in-server-instrumentation-handler",
    clock: "server-process-monotonic",
    interpretation:
      "Event-handler observation deltas within one monotonic process clock only. Not HTTP ingress, hook readiness, true model execution start, durable writes, client latency or Workflow completion.",
    sourceEventCount: rows.length,
    clockDomainCount: domains.size,
    unobservedBoundaries: {
      httpReceiptMs: null,
      hookReadyMs: null,
      trueModelExecutionStartMs: null,
      durableStepWrites: null,
      serializedBytes: null,
    },
    coverage,
    cases,
  };
}

export async function main(argv) {
  if (argv.length !== 4 || argv[0] !== "--logs" || argv[2] !== "--output" || !argv[1] || !argv[3])
    throw new Error("Expected --logs PATH --output PATH");
  const rows = parseServerPhaseLog(decodeServerPhaseLog(await readFile(argv[1])));
  const report = createServerPhaseReport(rows);
  const parent = dirname(resolve(argv[3]));
  if (parent !== parse(parent).root) await mkdir(parent, { recursive: true });
  await writeFile(argv[3], JSON.stringify(report, null, 2) + "\n");
  return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main(process.argv.slice(2));
}
