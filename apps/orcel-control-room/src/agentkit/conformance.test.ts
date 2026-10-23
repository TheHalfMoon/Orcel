// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/conformance/index.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-03).
// Taken: the conformance harness shape (a named check list in a report,
// assert/withTimeout helpers, a transport under test) and the transport
// invariants it checks: capabilities truthfulness, unsupported operations
// refused, event ordering and deduplication, version compatibility, cursor
// replay, and resubscribe never re-dispatches.
// Orcel changes: the transport under test is orceld's app API through
// run against the real daemon binary; AgentKit's run,
// cancellation, approval, queue and terminal-failure scenarios have no
// counterpart in a read-only API and are not taken; snapshot-on-gap and
// snapshot-on-epoch checks are added for ORCEL_APP_API_1.md section 5.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import {
  APP_API_PROTOCOL,
  READ_METHODS,
  RESERVED_READ_METHODS,
  ORCELD_METHODS,
  parseCapabilities,
  parseSnapshotData,
  parseStatus,
  type AppApiEvent,
  type ServerFrame,
} from "./protocol/index.js";
import { type AppApiConnector } from "./transport/orceld-transport.js";
import { exchange } from "../tests/raw.js";
import {
  createSandbox,
  testTransport,
  liveSkipReason,
  startOrceld,
  uniqueInstance,
  type RunningOrceld,
  type Sandbox,
} from "../tests/orceld.js";

class AppApiConformanceError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "AppApiConformanceError";
  }
}

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new AppApiConformanceError(message);
}

export interface AppApiConformanceReport {
  epoch: string;
  eventCount: number;
  checks: readonly string[];
}

const request = (id: string, method: string, params: Record<string, unknown> = {}) =>
  `${JSON.stringify({ v: APP_API_PROTOCOL, id, method, params })}\n`;

async function call(connector: AppApiConnector, method: string, params = {}): Promise<ServerFrame> {
  const { frames } = await exchange(connector, request("c", method, params));
  const frame = frames[0];
  check(frame, `${method} got no answer`);
  return frame;
}

async function resultOf(connector: AppApiConnector, method: string): Promise<unknown> {
  const frame = await call(connector, method);
  check(frame.type === "result" && frame.id === "c", `${method} did not answer with a result`);
  return frame.result;
}

/** Subscribes and reads `count` events (or until a snapshot or the end). */
async function stream(
  connector: AppApiConnector,
  params: { after_seq: number; epoch: string },
  count: number,
): Promise<{ ack: ServerFrame | undefined; events: AppApiEvent[]; ended: boolean }> {
  const { frames, ended } = await exchange(connector, request("s", "events.subscribe", params), (frames) => {
    const events = frames.filter((frame) => frame.type === "event");
    return events.length >= count || events.some((frame) => frame.type === "event" && frame.event.kind === "snapshot");
  });
  return {
    ack: frames[0],
    events: frames.flatMap((frame) => (frame.type === "event" ? [frame.event] : [])),
    ended,
  };
}

/** The CR-02 conformance suite over one orceld app API endpoint. */
export async function assertAppApiConformance(
  connector: AppApiConnector,
  daemon: RunningOrceld,
): Promise<AppApiConformanceReport> {
  const checks: string[] = [];

  // Version compatibility.
  const status = parseStatus(await resultOf(connector, "status.get"));
  check(status.app_api === APP_API_PROTOCOL, "status names the protocol");
  const { frames: versionFrames } = await exchange(
    connector,
    `${JSON.stringify({ v: "orcel-app-api/2", id: "x", method: "status.get" })}\n`,
  );
  const version = versionFrames[0];
  check(version?.type === "error" && version.error.code === "UNSUPPORTED_VERSION", "another version is refused");
  checks.push("version compatibility");

  // Capabilities truthfulness: the read-only flag and method list are exact.
  const caps = parseCapabilities(await resultOf(connector, "capabilities.get"));
  check(caps.read_only, "capabilities say read_only");
  check(JSON.stringify(caps.methods) === JSON.stringify(ORCELD_METHODS), `methods are ${caps.methods.join(", ")}`);
  check(
    JSON.stringify(caps.reserved_methods) === JSON.stringify(RESERVED_READ_METHODS),
    "reserved methods are the read-only reservations",
  );
  for (const row of caps.capabilities) {
    check(row.state === "available" || Boolean(row.reason), `${row.id} says why it is unavailable`);
  }
  check(caps.os === status.os, "capabilities and status agree on the OS");
  checks.push("capabilities truthfulness");

  // Unsupported operations: nothing that writes, approves or mints exists.
  for (const method of [
    "approval.respond",
    "approval.resolve",
    "approval.grant",
    "approval.mint",
    "task.submit",
    "task.cancel",
    "stop.request",
    "mcp.serve",
  ]) {
    const frame = await call(connector, method);
    check(frame.type === "error" && frame.error.code === "UNKNOWN_METHOD", `${method} is unknown`);
  }
  for (const method of RESERVED_READ_METHODS) {
    const frame = await call(connector, method);
    check(frame.type === "error" && frame.error.code === "METHOD_UNAVAILABLE", `${method} is reserved`);
  }
  // SG-000126 task reads are served and only read.
  const tasks = await call(connector, "task.list");
  check(tasks.type === "result" && Array.isArray((tasks.result as { tasks?: unknown }).tasks), "task.list returns tasks");
  const unknownTask = await call(connector, "task.get");
  check(unknownTask.type === "error" && unknownTask.error.code === "INVALID_REQUEST", "task.get needs a task_id");
  checks.push("unsupported operations");

  // Event ordering and deduplication: a full replay is contiguous, in one
  // epoch, without repeats.
  await daemon.publish(10);
  const head = parseStatus(await resultOf(connector, "status.get")).events.head_seq;
  const replay = await stream(connector, { after_seq: 0, epoch: status.events.epoch }, head);
  check(replay.ack?.type === "result", "subscribe is acknowledged first");
  check(replay.events.length === head, `replay delivered ${replay.events.length} of ${head}`);
  replay.events.forEach((event, index) => {
    check(event.seq === index + 1, `event ${index} has seq ${event.seq}`);
    check(event.epoch === status.events.epoch, "every event names the epoch");
  });
  check(replay.events[0]?.kind === "daemon.started", "the first event is daemon.started");
  checks.push("event ordering/deduplication");

  // Cursor replay: resuming after k starts at k + 1.
  const resumed = await stream(connector, { after_seq: head - 3, epoch: status.events.epoch }, 3);
  check(
    JSON.stringify(resumed.events.map((event) => event.seq)) === JSON.stringify([head - 2, head - 1, head]),
    "resume delivers exactly the events after the cursor",
  );
  checks.push("cursor replay");

  // Snapshot on a cursor the daemon cannot serve, and on another epoch.
  for (const [params, reason] of [
    [{ after_seq: head + 100, epoch: status.events.epoch }, "gap"],
    [{ after_seq: 1, epoch: "another-run" }, "epoch"],
  ] as const) {
    const answer = await stream(connector, params, 1);
    const snapshot = answer.events[0];
    check(snapshot?.kind === "snapshot", `${reason}: a snapshot is sent`);
    const data = parseSnapshotData(snapshot.data);
    check(data.reason === reason, `${reason}: reason is ${data.reason}`);
    check(data.resubscribe.epoch === status.events.epoch, `${reason}: resubscribe names the current epoch`);
    check(data.resubscribe.after_seq === data.head_seq, `${reason}: resubscribe starts at the head`);
    const { ended } = await exchange(connector, request("s", "events.subscribe", params), () => false, 10_000);
    check(ended, `${reason}: the daemon closes the stream after the snapshot`);
  }
  checks.push("snapshot on gap", "snapshot on epoch");

  // #375 item 4: a cursor without the epoch it belongs to is refused, so a
  // cursor from an earlier run never silently receives this run's events.
  const unanchored = await call(connector, "events.subscribe", { after_seq: 1 });
  check(
    unanchored.type === "error" && unanchored.error.code === "INVALID_REQUEST",
    "a cursor without its epoch is refused",
  );
  checks.push("cursor requires its epoch");

  // Resubscribe never re-dispatches: subscribing publishes nothing.
  const before = parseStatus(await resultOf(connector, "status.get")).events.head_seq;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await stream(connector, { after_seq: before - 1, epoch: status.events.epoch }, 1);
  }
  const afterHead = parseStatus(await resultOf(connector, "status.get")).events.head_seq;
  check(afterHead === before, `resubscribing moved the head from ${before} to ${afterHead}`);
  checks.push("resubscribe never re-dispatches");

  return { epoch: status.events.epoch, eventCount: head, checks };
}

const skip = liveSkipReason();
let sandbox: Sandbox | undefined;
let daemon: RunningOrceld | undefined;

before(async () => {
  if (skip) return;
  sandbox = await createSandbox(uniqueInstance("conf"));
  daemon = await startOrceld(sandbox);
});

after(async () => {
  await daemon?.stop();
  await sandbox?.dispose();
});

test("orceld's app API passes the conformance suite", { skip: skip ?? false, timeout: 120_000 }, async () => {
  assert.ok(daemon);
  const connector = await testTransport(daemon.endpoint);
  const report = await assertAppApiConformance(connector, daemon);
  assert.deepEqual(report.checks, [
    "version compatibility",
    "capabilities truthfulness",
    "unsupported operations",
    "event ordering/deduplication",
    "cursor replay",
    "snapshot on gap",
    "snapshot on epoch",
    "cursor requires its epoch",
    "resubscribe never re-dispatches",
  ]);
  assert.ok(report.eventCount >= 11);
});
