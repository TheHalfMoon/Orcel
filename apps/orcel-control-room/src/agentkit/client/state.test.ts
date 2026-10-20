import assert from "node:assert/strict";
import { test } from "node:test";

import { APP_API_PROTOCOL, AppApiValidationError, type AppApiEvent, type DaemonStatus } from "../protocol/index.js";
import {
  MAX_TIMELINE_EVENTS,
  applySnapshot,
  applyStatus,
  classifyEvent,
  createControlRoomState,
  reduceEvent,
} from "./state.js";

function status(epoch: string, head: number): DaemonStatus {
  return {
    name: "orceld",
    version: "0.2.0",
    app_api: APP_API_PROTOCOL,
    read_only: true,
    os: "linux",
    pid: 1,
    events: { epoch, head_seq: head, oldest_seq: 1, ring_capacity: 1024 },
  };
}

function event(seq: number, epoch = "e1"): AppApiEvent {
  return { seq, epoch, run_id: null, step_id: null, kind: "request.completed", at_ms: seq, data: {} };
}

test("contiguous events advance the cursor in order", () => {
  let state = applyStatus(createControlRoomState(), status("e1", 0), 0);
  for (let seq = 1; seq <= 3; seq += 1) state = reduceEvent(state, event(seq));
  assert.equal(state.cursor, 3);
  assert.deepEqual(state.events.map((e) => e.seq), [1, 2, 3]);
});

test("a sequence gap is rejected before the cursor advances", () => {
  const state = reduceEvent(applyStatus(createControlRoomState(), status("e1", 0), 0), event(1));
  assert.deepEqual(classifyEvent(state, event(3)), { status: "gap", expectedSequence: 2, receivedSequence: 3 });
  assert.throws(() => reduceEvent(state, event(3)), AppApiValidationError);
  assert.equal(state.cursor, 1);
  assert.equal(state.events.length, 1);
});

test("duplicates and other epochs change nothing", () => {
  const state = reduceEvent(applyStatus(createControlRoomState(), status("e1", 0), 0), event(1));
  assert.equal(classifyEvent(state, event(1)).status, "duplicate");
  assert.equal(reduceEvent(state, event(1)), state);
  assert.equal(classifyEvent(state, event(2, "e2")).status, "foreign");
  assert.equal(reduceEvent(state, event(2, "e2")), state);
  assert.equal(classifyEvent(createControlRoomState(), event(1)).status, "foreign");
});

test("snapshot events are not reduced as ordinary events", () => {
  const state = applyStatus(createControlRoomState(), status("e1", 0), 0);
  assert.throws(() => reduceEvent(state, { ...event(1), kind: "snapshot" }), /applySnapshot/u);
});

test("an epoch snapshot resets the timeline and the cursor", () => {
  let state = applyStatus(createControlRoomState(), status("e1", 0), 0);
  state = reduceEvent(reduceEvent(state, event(1)), event(2));
  const next = applySnapshot(state, {
    reason: "epoch",
    head_seq: 5,
    oldest_seq: 1,
    status: status("e2", 5),
    resubscribe: { after_seq: 5, epoch: "e2" },
  });
  assert.equal(next.epoch, "e2");
  assert.equal(next.cursor, 5);
  assert.deepEqual(next.events, []);
  assert.equal(next.snapshots, 1);
  assert.equal(next.status?.events.epoch, "e2");
});

test("a gap snapshot in the same epoch keeps the timeline and moves the cursor", () => {
  let state = applyStatus(createControlRoomState(), status("e1", 0), 0);
  state = reduceEvent(state, event(1));
  const next = applySnapshot(state, {
    reason: "gap",
    head_seq: 2000,
    oldest_seq: 977,
    status: status("e1", 2000),
    resubscribe: { after_seq: 2000, epoch: "e1" },
  });
  assert.equal(next.cursor, 2000);
  assert.equal(next.events.length, 1);
});

test("a status of the same epoch keeps the cursor; a new epoch starts over", () => {
  let state = reduceEvent(applyStatus(createControlRoomState(), status("e1", 0), 0), event(1));
  state = applyStatus(state, status("e1", 9), 0);
  assert.equal(state.cursor, 1);
  state = applyStatus(state, status("e2", 4), 4);
  assert.equal(state.cursor, 4);
  assert.deepEqual(state.events, []);
});

test("the timeline is bounded", () => {
  let state = applyStatus(createControlRoomState(), status("e1", 0), 0);
  for (let seq = 1; seq <= MAX_TIMELINE_EVENTS + 10; seq += 1) state = reduceEvent(state, event(seq));
  assert.equal(state.events.length, MAX_TIMELINE_EVENTS);
  assert.equal(state.events[0]?.seq, 11);
});
