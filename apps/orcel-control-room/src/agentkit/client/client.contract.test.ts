// Contract tests of the headless client against the real orceld app API
// (CR-01) on the OS the tests run on. CI runs them on Windows, macOS and
// Linux with ORCEL_REQUIRE_LIVE_ORCELD=1, so a missing daemon fails.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

import { APP_API_PROTOCOL, MAX_FRAME_BYTES, READ_METHODS } from "../protocol/index.js";
import {
  connectEndpoint,
  defaultEndpoint,
  orceldTransport,
  type AppApiConnector,
  type FrameConnection,
} from "../transport/orceld-transport.js";
import { exchange } from "../../tests/raw.js";
import {
  createSandbox,
  liveSkipReason,
  startOrceld,
  uniqueInstance,
  type RunningOrceld,
  type Sandbox,
} from "../../tests/orceld.js";
import { waitForState } from "../../tests/wait.js";
import { ControlRoomClient, type IntegrityReport } from "./client.js";

const skip = liveSkipReason() ?? false;

interface SentFrame {
  method: string;
  params: Record<string, unknown>;
}

/** Wraps a connector to record every frame the client writes. */
function recording(inner: AppApiConnector): AppApiConnector & { sent: SentFrame[] } {
  const sent: SentFrame[] = [];
  return {
    endpoint: inner.endpoint,
    sent,
    connect: async () => {
      const connection: FrameConnection = await inner.connect();
      return {
        send: (line) => {
          sent.push(JSON.parse(line) as SentFrame);
          return connection.send(line);
        },
        lines: () => connection.lines(),
        close: () => connection.close(),
      };
    },
  };
}

function assertReadOnlyTraffic(sent: SentFrame[]): void {
  assert.ok(sent.length > 0);
  for (const frame of sent) {
    assert.ok((READ_METHODS as readonly string[]).includes(frame.method), `sent ${frame.method}`);
    if (frame.method === "events.subscribe") {
      assert.equal(typeof frame.params.epoch, "string", "every subscription carries its epoch");
    }
  }
}

async function withDaemon(
  label: string,
  body: (sandbox: Sandbox, daemon: RunningOrceld) => Promise<void>,
): Promise<void> {
  const sandbox = await createSandbox(uniqueInstance(label));
  const daemon = await startOrceld(sandbox);
  try {
    await body(sandbox, daemon);
  } finally {
    await daemon.stop();
    await sandbox.dispose();
  }
}

test("status and capabilities round-trip, and orceld identifies this process", { skip, timeout: 60_000 }, async () => {
  await withDaemon("status", async (sandbox, daemon) => {
    // The client derives the same endpoint orceld chose for this user.
    assert.equal(await defaultEndpoint({ ...process.env, ...sandbox.env }), daemon.endpoint);
    const client = new ControlRoomClient({ connector: await orceldTransport({ endpoint: daemon.endpoint }) });
    const status = await client.getStatus();
    assert.equal(status.app_api, APP_API_PROTOCOL);
    assert.equal(status.read_only, true);
    assert.equal(status.pid, daemon.child.pid);
    // CR-01 admitted this connection by kernel peer identity: it names us.
    const peer = status.peer as { pid: number; source: string };
    assert.equal(peer.pid, process.pid);
    if (process.platform === "linux") assert.equal(peer.source, "linux-so-peerpidfd");
    const caps = await client.getCapabilities();
    assert.deepEqual(caps.methods, [...READ_METHODS]);
  });
});

test("the client follows events in order without duplicates", { skip, timeout: 60_000 }, async () => {
  await withDaemon("follow", async (_sandbox, daemon) => {
    const connector = recording(await orceldTransport({ endpoint: daemon.endpoint }));
    const client = new ControlRoomClient({ connector });
    const reports: IntegrityReport[] = [];
    client.onIntegrity((report) => reports.push(report));
    void client.start();
    await waitForState(client, (s) => s.connection === "connected", "connected");
    await daemon.publish(25);
    const state = await waitForState(client, (s) => s.cursor === 26, "cursor 26");
    await client.stop();
    assert.deepEqual(state.events.map((e) => e.seq), Array.from({ length: 26 }, (_, i) => i + 1));
    assert.equal(state.events[0]?.kind, "daemon.started");
    assert.ok(state.events.slice(1).every((e) => e.kind === "request.completed"));
    assert.deepEqual(reports, []);
    assertReadOnlyTraffic(connector.sent);
  });
});

test("a cursor the ring no longer holds gets a gap snapshot and the client resyncs", { skip, timeout: 120_000 }, async () => {
  await withDaemon("gap", async (_sandbox, daemon) => {
    const connector = recording(await orceldTransport({ endpoint: daemon.endpoint }));
    const client = new ControlRoomClient({ connector, reconnect: { initialDelayMs: 20, maxDelayMs: 200 } });
    void client.start();
    await waitForState(client, (s) => s.connection === "connected" && s.cursor === 1, "first event");
    await client.stop();
    // While the client is away the 1,024-event ring rolls past its cursor.
    await daemon.publish(1_100);
    void client.start();
    const resynced = await waitForState(client, (s) => s.snapshots === 1 && s.connection === "connected", "gap snapshot");
    assert.equal(resynced.lastSnapshot?.reason, "gap");
    assert.equal(resynced.cursor, 1_101);
    assert.equal(resynced.status?.events.head_seq, 1_101);
    await daemon.publish(3);
    const state = await waitForState(client, (s) => s.cursor === 1_104, "events after the snapshot");
    await client.stop();
    assert.deepEqual(state.events.map((e) => e.seq), [1, 1_102, 1_103, 1_104]);
    const subs = connector.sent.filter((f) => f.method === "events.subscribe");
    assert.deepEqual(subs[1]?.params, { after_seq: 1, epoch: state.epoch });
    assert.deepEqual(subs[2]?.params, { after_seq: 1_101, epoch: state.epoch });
    assertReadOnlyTraffic(connector.sent);
  });
});

test("a daemon restart is seen as a new epoch; the client reconnects and resubscribes", { skip, timeout: 120_000 }, async () => {
  const sandbox = await createSandbox(uniqueInstance("epoch"));
  let daemon = await startOrceld(sandbox);
  const connector = recording(await orceldTransport({ endpoint: daemon.endpoint }));
  const client = new ControlRoomClient({ connector, reconnect: { initialDelayMs: 50, maxDelayMs: 250 } });
  const reports: IntegrityReport[] = [];
  client.onIntegrity((report) => reports.push(report));
  const states = new Set<string>();
  client.onState((s) => states.add(s.connection));
  try {
    void client.start();
    await daemon.publish(4);
    const first = await waitForState(client, (s) => s.cursor === 5, "first run's events");
    const firstEpoch = first.epoch;
    await daemon.stop();
    await waitForState(client, (s) => s.connection === "offline" || s.connection === "reconnecting", "daemon gone");
    daemon = await startOrceld(sandbox);
    const second = await waitForState(
      client,
      (s) => s.epoch !== firstEpoch && s.connection === "connected",
      "second run",
      60_000,
    );
    assert.equal(second.lastSnapshot?.reason, "epoch");
    assert.deepEqual(second.events, [], "the old run's timeline is dropped");
    await daemon.publish(2);
    const state = await waitForState(client, (s) => s.events.length === 2, "second run's events");
    assert.ok(state.events.every((e) => e.epoch === second.epoch));
    assert.deepEqual(
      state.events.map((e) => e.seq),
      [second.cursor + 1, second.cursor + 2],
    );
    assert.ok(states.has("offline") || states.has("reconnecting"));
    assert.deepEqual(reports, []);
    const subs = connector.sent.filter((f) => f.method === "events.subscribe");
    // The first resubscribe after the restart offered the old epoch.
    assert.ok(subs.some((f) => f.params.epoch === firstEpoch && f.params.after_seq === 5));
    assert.equal(subs.at(-1)?.params.epoch, second.epoch);
    assertReadOnlyTraffic(connector.sent);
  } finally {
    await client.stop();
    await daemon.stop();
    await sandbox.dispose();
  }
});

test("an oversize frame is refused by orceld and the connection closed", { skip, timeout: 60_000 }, async () => {
  await withDaemon("frame", async (_sandbox, daemon) => {
    const connector = await orceldTransport({ endpoint: daemon.endpoint });
    const { frames, ended } = await exchange(connector, `${"x".repeat(MAX_FRAME_BYTES)}\n`, () => false);
    assert.equal(frames.length, 1);
    const frame = frames[0];
    assert.ok(frame?.type === "error");
    assert.equal(frame.error.code, "FRAME_TOO_LARGE");
    assert.equal(frame.id, null);
    assert.ok(ended, "orceld closes the connection");
    // A frame of exactly 64 KiB, newline included, is still served.
    const base = { v: APP_API_PROTOCOL, id: "r", method: "status.get", params: {}, pad: "" };
    const pad = MAX_FRAME_BYTES - Buffer.byteLength(`${JSON.stringify(base)}\n`);
    const exact = `${JSON.stringify({ ...base, pad: "p".repeat(pad) })}\n`;
    assert.equal(Buffer.byteLength(exact), MAX_FRAME_BYTES);
    const served = await exchange(connector, exact);
    assert.equal(served.frames[0]?.type, "result");
  });
});

test("another user cannot reach the endpoint", { skip, timeout: 60_000 }, async (t) => {
  if (process.platform === "win32") {
    // CR-01's pipe DACL names only this user's SID (read back by its
    // cr01 Windows test); there is no second account on the runner. The
    // client side is endpoint.test.ts: this user's name, never another's.
    t.skip("Windows: covered by CR-01's DACL read-back; no second account on the runner");
    return;
  }
  if (process.env.ORCEL_APP_API_OTHER_USER_TEST !== "1") {
    t.skip("set ORCEL_APP_API_OTHER_USER_TEST=1 with passwordless sudo (CI does)");
    return;
  }
  await withDaemon("other", async (_sandbox, daemon) => {
    const sudo = spawnSync("sudo", ["-n", "-u", "nobody", "true"]);
    assert.equal(sudo.status, 0, "the other-user test needs sudo -n -u nobody");
    // The same Node connect the client uses, run as `nobody`.
    const probe = [
      "const net = require('node:net');",
      "const s = net.createConnection({ path: process.argv[1] });",
      "s.on('connect', () => process.exit(0));",
      "s.on('error', (e) => process.exit(e.code === 'EACCES' ? 13 : 2));",
    ].join("\n");
    let run = spawnSync("sudo", ["-n", "-u", "nobody", process.execPath, "-e", probe, daemon.endpoint], {
      encoding: "utf8",
      timeout: 30_000,
    });
    if (run.status !== 0 && run.status !== 13) {
      // `nobody` may not be able to execute this Node (a toolcache under a
      // private home); CR-01's python3 probe makes the same connect(2).
      const python = [
        "import socket,sys",
        "s=socket.socket(socket.AF_UNIX)",
        "try:",
        "    s.connect(sys.argv[1])",
        "except PermissionError:",
        "    sys.exit(13)",
        "except OSError as e:",
        "    print(e); sys.exit(2)",
        "sys.exit(0)",
      ].join("\n");
      run = spawnSync("sudo", ["-n", "-u", "nobody", "python3", "-c", python, daemon.endpoint], {
        encoding: "utf8",
        timeout: 30_000,
      });
    }
    assert.equal(run.status, 13, `nobody's connect: status ${run.status} ${run.stderr}`);
    // orceld never saw a connection to refuse.
    assert.ok(!daemon.stderr.some((line) => line.includes("refused a connection")));
    // And the client refuses to use an endpoint that is not this user's.
    await assert.rejects(connectEndpoint("/tmp"), /refusing app API endpoint/u);
  });
});
