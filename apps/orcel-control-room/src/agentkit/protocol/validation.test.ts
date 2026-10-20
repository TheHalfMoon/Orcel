import assert from "node:assert/strict";
import { test } from "node:test";

import {
  APP_API_PROTOCOL,
  AppApiProtocolError,
  AppApiValidationError,
  MAX_FRAME_BYTES,
  READ_METHODS,
  encodeRequest,
  parseCapabilities,
  parseServerFrame,
  parseSnapshotData,
  type ReadMethod,
} from "./index.js";

const event = {
  seq: 3,
  epoch: "e1",
  run_id: null,
  step_id: null,
  kind: "request.completed",
  at_ms: 1,
  data: {},
};

const status = {
  name: "orceld",
  version: "0.2.0",
  app_api: APP_API_PROTOCOL,
  read_only: true,
  os: "linux",
  pid: 7,
  events: { epoch: "e1", head_seq: 3, oldest_seq: 1, ring_capacity: 1024 },
};

test("frames of every kind parse", () => {
  const v = APP_API_PROTOCOL;
  assert.deepEqual(parseServerFrame(JSON.stringify({ v, id: "r1", ok: true, result: {} })), {
    type: "result",
    id: "r1",
    result: {},
  });
  assert.equal(
    parseServerFrame(JSON.stringify({ v, id: null, ok: false, error: { code: "BUSY", message: "full" } })).type,
    "error",
  );
  assert.equal(parseServerFrame(JSON.stringify({ v, id: 1, event })).type, "event");
  assert.deepEqual(parseServerFrame(JSON.stringify({ v, id: 1, heartbeat: { head_seq: 9 } })), {
    type: "heartbeat",
    id: 1,
    headSeq: 9,
  });
});

test("an unknown envelope field is rejected", () => {
  const v = APP_API_PROTOCOL;
  for (const frame of [
    { v, id: "r1", ok: true, result: {}, approve: true },
    { v, id: "r1", event, extra: 1 },
    { v, id: "r1", event: { ...event, approval: "granted" } },
    { v, id: "r1", heartbeat: { head_seq: 1, extra: 2 } },
    { v, id: "r1", ok: false, error: { code: "BUSY", message: "", retry: true } },
  ]) {
    assert.throws(() => parseServerFrame(JSON.stringify(frame)), AppApiValidationError);
  }
});

test("frames of another version or shape are rejected", () => {
  assert.throws(() => parseServerFrame("not json"), AppApiValidationError);
  assert.throws(() => parseServerFrame("[]"), AppApiValidationError);
  assert.throws(
    () => parseServerFrame(JSON.stringify({ v: "orcel-app-api/2", id: 1, ok: true, result: {} })),
    /frame\.v/u,
  );
  assert.throws(
    () => parseServerFrame(JSON.stringify({ v: APP_API_PROTOCOL, id: 1, result: {} })),
    AppApiValidationError,
  );
  assert.throws(
    () => parseServerFrame(JSON.stringify({ v: APP_API_PROTOCOL, id: 1, ok: false, error: { code: "NOPE", message: "" } })),
    /frame\.error\.code/u,
  );
  assert.throws(
    () => parseServerFrame(JSON.stringify({ v: APP_API_PROTOCOL, id: 1, event: { ...event, seq: -1 } })),
    /frame\.event\.seq/u,
  );
});

test("the client sends only read-only methods", () => {
  assert.deepEqual([...READ_METHODS], ["status.get", "capabilities.get", "events.subscribe"]);
  for (const method of [
    "approval.respond",
    "approval.resolve",
    "approval.grant",
    "task.submit",
    "task.cancel",
    "stop.request",
    "devices.list",
  ]) {
    assert.throws(
      () => encodeRequest("r1", method as ReadMethod),
      (error: unknown) => error instanceof AppApiProtocolError && error.code === "UNKNOWN_METHOD",
    );
  }
  assert.equal(
    encodeRequest("r1", "status.get"),
    `{"v":"${APP_API_PROTOCOL}","id":"r1","method":"status.get","params":{}}\n`,
  );
});

test("events.subscribe always carries an epoch and nothing else (#375 item 4)", () => {
  assert.throws(
    () => encodeRequest("s", "events.subscribe", { after_seq: 3 } as never),
    /request\.params\.epoch/u,
  );
  assert.throws(
    () => encodeRequest("s", "events.subscribe", { after_seq: 3, epoch: "e", extra: 1 } as never),
    /request\.params\.extra/u,
  );
  assert.throws(() => encodeRequest("s", "events.subscribe", { after_seq: -1, epoch: "e" }), /after_seq/u);
  assert.match(encodeRequest("s", "events.subscribe", { after_seq: 3, epoch: "e" }), /"epoch":"e"/u);
  assert.throws(() => encodeRequest("s", "status.get", { epoch: "e" } as never), /request\.params\.epoch/u);
});

test("every request the client can form fits a frame; longer fields are refused", () => {
  // Ids and epochs are capped at 128 characters, so the largest request the
  // client can encode is far below 64 KiB; encodeRequest still checks the
  // byte size. The contract test sends a raw oversize frame to orceld.
  assert.throws(
    () => encodeRequest("s", "events.subscribe", { after_seq: 0, epoch: "e".repeat(MAX_FRAME_BYTES) }),
    AppApiValidationError,
  );
  assert.throws(() => encodeRequest("x".repeat(129), "status.get"), /request\.id/u);
  const largest = encodeRequest("\u{1F600}".repeat(128), "events.subscribe", {
    after_seq: Number.MAX_SAFE_INTEGER,
    epoch: "e".repeat(128),
  });
  assert.ok(Buffer.byteLength(largest) < MAX_FRAME_BYTES);
});

test("capability rows must say why they are unavailable", () => {
  const caps = { os: "linux", read_only: true, methods: [], reserved_methods: [], capabilities: [] as unknown[] };
  assert.equal(parseCapabilities({ ...caps, capabilities: [{ id: "fs", state: "available", reason: null }] }).capabilities.length, 1);
  assert.throws(
    () => parseCapabilities({ ...caps, capabilities: [{ id: "x", state: "unavailable", reason: null }] }),
    /reason/u,
  );
  assert.throws(() => parseCapabilities({ ...caps, read_only: false }), /read_only/u);
  assert.throws(() => parseCapabilities({ ...caps, approve: [] }), /capabilities\.approve/u);
});

test("snapshot data is validated, including its status", () => {
  const data = {
    reason: "epoch",
    head_seq: 3,
    oldest_seq: 1,
    status,
    resubscribe: { after_seq: 3, epoch: "e1" },
  };
  assert.equal(parseSnapshotData(data).resubscribe.epoch, "e1");
  assert.throws(() => parseSnapshotData({ ...data, reason: "other" }), /reason/u);
  assert.throws(() => parseSnapshotData({ ...data, resubscribe: { after_seq: 3 } }), /resubscribe\.epoch/u);
  assert.throws(() => parseSnapshotData({ ...data, status: { ...status, read_only: false } }), /read_only/u);
});
