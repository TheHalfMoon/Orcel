// Client behaviour on stream faults orceld itself never produces, driven by
// an in-memory scripted server (src/tests/scripted.ts). The same behaviour
// against the real daemon is in client.contract.test.ts.

import assert from "node:assert/strict";
import { test } from "node:test";

import { READ_METHODS } from "../protocol/index.js";
import {
  ScriptedConnector,
  capabilitiesResult,
  eventFrame,
  statusResult,
  v,
  type Script,
  type ScriptedRequest,
} from "../../tests/scripted.js";
import { waitForState } from "../../tests/wait.js";
import { ControlRoomClient, type IntegrityReport } from "./client.js";

/** Answers status/capabilities; `stream(n, request)` scripts subscription n. */
function server(
  epoch: () => string,
  stream: (subscription: number, request: ScriptedRequest) => unknown[],
): Script {
  let subscriptions = 0;
  return (request) => {
    if (request.method === "status.get") return [{ v, id: request.id, ok: true, result: statusResult(epoch(), 0) }];
    if (request.method === "capabilities.get") return [{ v, id: request.id, ok: true, result: capabilitiesResult }];
    const ack = {
      v,
      id: request.id,
      ok: true,
      result: { epoch: epoch(), head_seq: 0, after_seq: request.params.after_seq },
    };
    return [ack, ...stream(subscriptions++, request)];
  };
}

function client(connector: ScriptedConnector) {
  const reports: IntegrityReport[] = [];
  const instance = new ControlRoomClient({ connector, reconnect: { initialDelayMs: 1, maxDelayMs: 10 } });
  instance.onIntegrity((report) => reports.push(report));
  return { instance, reports };
}

function subscriptions(connector: ScriptedConnector) {
  return connector.sent.filter((request) => request.method === "events.subscribe");
}

function assertOnlyReadMethods(connector: ScriptedConnector) {
  for (const request of connector.sent) {
    assert.ok((READ_METHODS as readonly string[]).includes(request.method), request.method);
  }
  for (const request of subscriptions(connector)) {
    assert.equal(typeof request.params.epoch, "string", "every subscription carries its epoch");
  }
}

test("SG-000126 task reads stay daemon-only, even when advertised", async () => {
  const connector = new ScriptedConnector(server(() => "e1", () => []));
  const { instance } = client(connector);

  // orceld now advertises task reads, but the Control Room cannot expand
  // its authority based on the server's capability advertisement.
  const capabilities = await instance.getCapabilities();
  assert.ok(capabilities.methods.includes("task.list"));
  assert.ok(capabilities.methods.includes("task.get"));
  const before = connector.sent.length;

  for (const method of ["task.list", "task.get", "task.submit", "approval.respond"]) {
    await assert.rejects(
      () => instance.request(method as never),
      (error: unknown) => error instanceof Error && "code" in error && error.code === "UNKNOWN_METHOD",
      method,
    );
  }
  assert.equal(connector.sent.length, before, "refused methods never reach the transport");
  assert.deepEqual(connector.sent.map((request) => request.method), ["capabilities.get"]);
});

test("a sequence gap is reported, the cursor holds, and the client resubscribes from it", async () => {
  const connector = new ScriptedConnector(
    server(
      () => "e1",
      (n, request) => {
        if (n === 0) return [eventFrame(request.id, 1, "e1"), eventFrame(request.id, 3, "e1")];
        if (n === 1) return [2, 3].map((seq) => eventFrame(request.id, seq, "e1"));
        return [];
      },
    ),
  );
  const { instance, reports } = client(connector);
  void instance.start();
  const state = await waitForState(instance, (s) => s.cursor === 3, "cursor 3");
  await instance.stop();
  assert.deepEqual(reports[0], { code: "sequence_gap", expectedSequence: 2, receivedSequence: 3 });
  assert.deepEqual(state.events.map((e) => e.seq), [1, 2, 3]);
  const subs = subscriptions(connector);
  assert.deepEqual(
    subs.slice(0, 2).map((s) => s.params),
    [
      { after_seq: 0, epoch: "e1" },
      { after_seq: 1, epoch: "e1" },
    ],
  );
  assertOnlyReadMethods(connector);
});

test("a duplicate delivery is reported and dropped", async () => {
  const connector = new ScriptedConnector(
    server(
      () => "e1",
      (n, request) =>
        n === 0 ? [1, 1, 2].map((seq) => eventFrame(request.id, seq, "e1")) : [],
    ),
  );
  const { instance, reports } = client(connector);
  void instance.start();
  const state = await waitForState(instance, (s) => s.cursor === 2, "cursor 2");
  await instance.stop();
  assert.deepEqual(reports, [{ code: "duplicate_event", expectedSequence: 2, receivedSequence: 1 }]);
  assert.deepEqual(state.events.map((e) => e.seq), [1, 2]);
});

test("an event of another epoch or an unknown envelope field ends the stream", async () => {
  const connector = new ScriptedConnector(
    server(
      () => "e1",
      (n, request) => {
        if (n === 0) return [eventFrame(request.id, 1, "other")];
        if (n === 1) return [{ ...eventFrame(request.id, 1, "e1"), approve: true }];
        if (n === 2) return [eventFrame(request.id, 1, "e1")];
        return [];
      },
    ),
  );
  const { instance, reports } = client(connector);
  void instance.start();
  await waitForState(instance, (s) => s.cursor === 1, "cursor 1");
  await instance.stop();
  assert.equal(reports[0]?.code, "foreign_epoch");
  assert.equal(reports[1]?.code, "invalid_frame");
  assert.ok(subscriptions(connector).length >= 3);
  assertOnlyReadMethods(connector);
});

test("an epoch snapshot switches the view and resubscribes with the new epoch", async () => {
  let epoch = "e1";
  const connector = new ScriptedConnector((request) => {
    if (request.method === "status.get") return [{ v, id: request.id, ok: true, result: statusResult(epoch, 0) }];
    if (request.method === "capabilities.get") return [{ v, id: request.id, ok: true, result: capabilitiesResult }];
    const ack = { v, id: request.id, ok: true, result: { epoch, head_seq: 0, after_seq: request.params.after_seq } };
    if (request.params.epoch === "e1" && epoch === "e1") {
      epoch = "e2"; // the daemon restarts after this stream
      return [ack, eventFrame(request.id, 1, "e1")];
    }
    if (request.params.epoch === "e1") {
      return [
        ack,
        {
          v,
          id: request.id,
          event: {
            seq: 4,
            epoch: "e2",
            run_id: null,
            step_id: null,
            kind: "snapshot",
            at_ms: 1,
            data: {
              reason: "epoch",
              head_seq: 4,
              oldest_seq: 1,
              status: statusResult("e2", 4),
              resubscribe: { after_seq: 4, epoch: "e2" },
            },
          },
        },
      ];
    }
    return [ack, eventFrame(request.id, 5, "e2")];
  });
  const { instance, reports } = client(connector);
  void instance.start();
  const state = await waitForState(instance, (s) => s.epoch === "e2" && s.cursor === 5, "epoch e2 cursor 5");
  await instance.stop();
  assert.deepEqual(reports, []);
  assert.equal(state.snapshots, 1);
  assert.deepEqual(state.events.map((e) => [e.epoch, e.seq]), [["e2", 5]]);
  const subs = subscriptions(connector).map((s) => s.params);
  assert.deepEqual(subs.slice(0, 3), [
    { after_seq: 0, epoch: "e1" },
    { after_seq: 1, epoch: "e1" },
    { after_seq: 4, epoch: "e2" },
  ]);
  // Capabilities are read again for the new daemon run.
  assert.equal(connector.sent.filter((r) => r.method === "capabilities.get").length, 2);
  assertOnlyReadMethods(connector);
});

test("BUSY and dropped connections back off and retry with the same cursor", async () => {
  let busy = 2;
  const base = server(
    () => "e1",
    (n, request) => (n === 0 ? [eventFrame(request.id, 1, "e1")] : []),
  );
  const connector = new ScriptedConnector((request, index) => {
    if (request.method === "events.subscribe" && busy > 0) {
      busy -= 1;
      return [{ v, id: null, ok: false, error: { code: "BUSY", message: "full" } }];
    }
    return base(request, index);
  });
  const { instance } = client(connector);
  const seen = new Set<string>();
  instance.onState((s) => seen.add(s.connection));
  void instance.start();
  await waitForState(instance, (s) => s.cursor === 1, "cursor 1");
  await instance.stop();
  assert.ok(seen.has("offline"));
  assert.ok(seen.has("connected"));
  assert.deepEqual(
    subscriptions(connector).slice(0, 3).map((s) => s.params),
    [
      { after_seq: 0, epoch: "e1" },
      { after_seq: 0, epoch: "e1" },
      { after_seq: 0, epoch: "e1" },
    ],
  );
});

test("an unsupported version stops the client with an error", async () => {
  const connector = new ScriptedConnector((request) => [
    { v, id: request.id, ok: false, error: { code: "UNSUPPORTED_VERSION", message: "v2 only" } },
  ]);
  const instance = new ControlRoomClient({ connector, reconnect: { initialDelayMs: 1 } });
  await assert.rejects(instance.start(), /UNSUPPORTED_VERSION/u);
  assert.equal(instance.getState().connection, "error");
});
