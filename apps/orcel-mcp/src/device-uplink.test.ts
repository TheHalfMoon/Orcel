import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createDeviceChallenge,
  generateDeviceKeyPair,
  publicDeviceIdentity,
  revokeDevice,
  verifyChallengeResponse,
  type ChallengeResponse,
  type DeviceChallenge,
  type RevocationRecord
} from "./device_identity.js";
import {
  backoffMs,
  computeRequestDigest,
  createMcpFrameDispatcher,
  DeviceUplinkCore,
  isPairedConnection,
  isRelayOrigin,
  runDeviceUplink,
  sessionContextFor,
  UPLINK_PATHS,
  type ConnectionBinding,
  type OutboundFrame,
  type PairedConnection,
  type UplinkDispatcher
} from "./device_uplink.js";
import { attachRemoteContext, buildRequest, type KernelClient, type KernelRequest, type RemoteDispatchContext } from "./kernel.js";
import { DENIED_RELAY_CAPABILITIES, RELAY_BOUNDS, RELAY_PROTOCOL_VERSION } from "./relay_contract.js";
import { CANONICAL_TOOL_NAMES } from "./server.js";
import { REMOTE_TOOL_NAMES } from "./tool_contract.js";
import { parseUplinkFile } from "./transports/relay_device.js";
import { loadDeviceKey, loadDeviceRecord, loadRevocations } from "./uplink_state.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");
const readSource = (rel: string): string => readFileSync(join(srcDir, rel), "utf8");

const NOW = 1_800_000_000_000;
const DEVICE = "dev-" + "c".repeat(32);
const TOKEN = "T".repeat(43);
const PAIRED: PairedConnection = {
  principal: "rp-" + "a".repeat(32),
  remoteConnectionId: "rc-" + "b".repeat(32),
  providerKind: "generic",
  clientProfileId: "profile-1",
  clientProfileRevision: 1,
  toolSurfaceProfile: "core",
  scopeCeiling: ["orcel.read", "orcel.write"]
};
const OTHER: PairedConnection = {
  ...PAIRED,
  principal: "rp-" + "e".repeat(32),
  remoteConnectionId: "rc-" + "f".repeat(32)
};

let nonceCounter = 0;
function nonce(): string {
  nonceCounter += 1;
  return Buffer.from(`nonce-${nonceCounter}-${"x".repeat(16)}`).toString("base64url");
}

function call(id: number, name: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: { path: "README.md" } } });
}

interface FrameOptions {
  sequence: number;
  correlationId?: string;
  connectionId?: string;
  paired?: PairedConnection;
  payload?: string;
  kind?: string;
  scopes?: readonly ("orcel.read" | "orcel.write" | "orcel.execute")[];
  createdAt?: number;
  expiresAt?: number;
  channelAuth?: string;
  routeDeviceId?: string;
  envelopePrincipal?: string;
  epoch?: number;
  digestPayload?: string;
  replayNonce?: string;
  extra?: Record<string, unknown>;
}

function frame(options: FrameOptions): Record<string, unknown> {
  const paired = options.paired ?? PAIRED;
  const kind = options.kind ?? "mcp_request";
  const payload = options.payload ?? (kind === "mcp_request" ? call(options.sequence, "fs_read") : "");
  const connectionId = options.connectionId ?? "conn-0001";
  const correlationId = options.correlationId ?? `corr-${options.sequence}`;
  let method = "";
  if (kind === "mcp_request") {
    method = (JSON.parse(payload) as { method: string }).method;
  }
  const scopes = options.scopes ?? ["orcel.read"];
  return {
    protocolVersion: RELAY_PROTOCOL_VERSION,
    routeDeviceId: options.routeDeviceId ?? DEVICE,
    remoteConnectionId: paired.remoteConnectionId,
    connectionId,
    sequence: options.sequence,
    replayNonce: options.replayNonce ?? nonce(),
    correlationId,
    messageKind: kind,
    payloadLength: Buffer.byteLength(payload, "utf8"),
    createdAt: options.createdAt ?? NOW,
    expiresAt: options.expiresAt ?? NOW + 60_000,
    channelAuth: options.channelAuth ?? TOKEN,
    authorizationEnvelope: {
      principal: options.envelopePrincipal ?? paired.principal,
      connection: paired.remoteConnectionId,
      device: DEVICE,
      requestDigest: computeRequestDigest({
        principal: paired.principal,
        remoteConnectionId: paired.remoteConnectionId,
        connectionId,
        deviceId: DEVICE,
        correlationId,
        sequence: options.sequence,
        method,
        payload: options.digestPayload ?? payload
      }),
      epoch: options.epoch ?? 1,
      sessionContext: sessionContextFor(scopes)
    },
    payload,
    ...(options.extra ?? {})
  };
}

class StubDispatcher implements UplinkDispatcher {
  readonly calls: Array<{ binding: ConnectionBinding; payload: string }> = [];
  readonly closed: string[] = [];
  private readonly waiters: Array<() => void> = [];
  hold = false;

  async dispatch(binding: ConnectionBinding, payload: string): Promise<string | null> {
    this.calls.push({ binding, payload });
    if (this.hold) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    const id = (JSON.parse(payload) as { id?: unknown }).id;
    return id === undefined ? null : JSON.stringify({ jsonrpc: "2.0", id, result: { ok: true } });
  }

  release(): void {
    this.hold = false;
    for (const resolve of this.waiters.splice(0)) {
      resolve();
    }
  }

  closeConnection(connectionId: string): void {
    this.closed.push(connectionId);
  }
}

function core(
  dispatcher: UplinkDispatcher = new StubDispatcher(),
  revocations: RevocationRecord[] = [],
  clock: () => number = () => NOW
): DeviceUplinkCore {
  const uplink = new DeviceUplinkCore(
    { deviceId: DEVICE, deviceEpoch: 1 },
    [PAIRED, OTHER],
    dispatcher,
    () => revocations,
    clock
  );
  uplink.setChannelToken(TOKEN);
  return uplink;
}

function errors(frames: OutboundFrame[]): Array<string | null> {
  return frames.filter((f) => f.messageKind === "mcp_error").map((f) => f.failure);
}

async function settle(promises: Promise<void>[]): Promise<void> {
  await Promise.all(promises);
}

test("a verified request dispatches once with server-supplied remote context and answers on the same route", async () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 1 })], NOW);
  assert.equal(uplink.queueLength(), 1);
  await settle(uplink.pump(NOW));
  assert.equal(dispatcher.calls.length, 1);
  const remote = dispatcher.calls[0]?.binding.remote;
  assert.deepEqual(remote, {
    principal: PAIRED.principal,
    remoteConnectionId: PAIRED.remoteConnectionId,
    connectionId: "conn-0001",
    deviceId: DEVICE,
    deviceEpoch: 1,
    providerKind: "generic",
    clientProfileId: "profile-1",
    clientProfileRevision: 1,
    toolSurfaceProfile: "core",
    scopes: ["orcel.read"]
  });
  const out = uplink.drainOutbox(NOW);
  assert.equal(out.length, 1);
  const response = out[0] as OutboundFrame;
  assert.equal(response.messageKind, "mcp_response");
  assert.equal(response.correlationId, "corr-1");
  assert.equal(response.routeDeviceId, DEVICE);
  assert.equal(response.remoteConnectionId, PAIRED.remoteConnectionId);
  assert.equal(response.connectionId, "conn-0001");
  assert.equal(response.sequence, 1);
  assert.equal(response.channelAuth, TOKEN);
  assert.equal(response.payloadLength, Buffer.byteLength(response.payload ?? "", "utf8"));
});

test("negative: replayed nonce, duplicate correlation, and repeated sequence never re-execute", async () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  const first = frame({ sequence: 1 });
  uplink.receive([first], NOW);
  uplink.receive([first], NOW);
  uplink.receive([frame({ sequence: 2, correlationId: "corr-1" })], NOW);
  uplink.receive([frame({ sequence: 1, correlationId: "corr-x" })], NOW);
  await settle(uplink.pump(NOW));
  assert.equal(dispatcher.calls.length, 1, "exactly one execution");
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), [
    "RELAY_REPLAY_DETECTED",
    "RELAY_REPLAY_DETECTED",
    "RELAY_REPLAY_DETECTED"
  ]);
});

test("negative: reordered and gapped sequences fail with RELAY_SEQUENCE_INVALID", async () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 2 })], NOW);
  uplink.receive([frame({ sequence: 1 }), frame({ sequence: 3 })], NOW);
  await settle(uplink.pump(NOW));
  assert.equal(dispatcher.calls.length, 1);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), ["RELAY_SEQUENCE_INVALID", "RELAY_SEQUENCE_INVALID"]);
});

test("negative: expired, future, and over-long frames fail closed", () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 1, createdAt: NOW - 120_000, expiresAt: NOW - 1 })], NOW);
  uplink.receive([frame({ sequence: 1, createdAt: NOW + 60_000, expiresAt: NOW + 120_000 })], NOW);
  uplink.receive([frame({ sequence: 1, createdAt: NOW, expiresAt: NOW + 121_000 })], NOW);
  assert.equal(uplink.queueLength(), 0);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), [
    "REMOTE_QUEUE_EXPIRED",
    "REMOTE_QUEUE_EXPIRED",
    "REMOTE_QUEUE_EXPIRED"
  ]);
});

test("negative: oversized and malformed frames never reach dispatch", () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  const big = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: { pad: "x".repeat(RELAY_BOUNDS.maxFrameBytes) } });
  uplink.receive([frame({ sequence: 1, payload: big })], NOW);
  const lying = frame({ sequence: 1 });
  lying.payloadLength = 3;
  uplink.receive([lying], NOW);
  const notJson = frame({ sequence: 1 });
  notJson.payload = "not json";
  notJson.payloadLength = 8;
  uplink.receive([notJson], NOW);
  uplink.receive([frame({ sequence: 1, payload: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {} }) })], NOW);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), [
    "REMOTE_RATE_LIMITED",
    "MCP_PROTOCOL_UNSUPPORTED",
    "MCP_PROTOCOL_UNSUPPORTED",
    "MCP_PROTOCOL_UNSUPPORTED"
  ]);
  // Unattributable malformed frames are dropped without any reply.
  uplink.receive(
    [
      null,
      "frame",
      { ...frame({ sequence: 1 }), extra: true },
      (() => {
        const f = frame({ sequence: 1 });
        delete f.authorizationEnvelope;
        return f;
      })(),
      frame({ sequence: 1, extra: { protocolVersion: "orcel-relay/2" } }),
      frame({ sequence: 1, kind: "mcp_response" }),
      frame({ sequence: 1, kind: "tcp_forward" })
    ],
    NOW
  );
  assert.equal(uplink.drainOutbox(NOW).length, 0);
  assert.equal(uplink.queueLength(), 0);
  assert.equal(dispatcher.calls.length, 0);
});

test("negative: wrong channel, wrong device, unknown route, and cross-route reuse fail without dispatch", () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 1, channelAuth: "U".repeat(43) })], NOW);
  uplink.receive([frame({ sequence: 1, routeDeviceId: "dev-" + "d".repeat(32) })], NOW);
  uplink.receive([frame({ sequence: 1, paired: { ...PAIRED, remoteConnectionId: "rc-" + "9".repeat(32) } })], NOW);
  assert.equal(uplink.drainOutbox(NOW).length, 0, "unauthenticated or unknown routes get no reply");
  uplink.receive([frame({ sequence: 1 })], NOW);
  uplink.receive([frame({ sequence: 2, paired: OTHER })], NOW);
  assert.equal(uplink.queueLength(), 1, "a connection id can never switch routes");
  assert.equal(uplink.drainOutbox(NOW).length, 0);
});

test("negative: principal remap, digest tampering, stale epoch, and revoked device fail the envelope", () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 1, envelopePrincipal: OTHER.principal })], NOW);
  uplink.receive([frame({ sequence: 1, digestPayload: call(1, "fs_list") })], NOW);
  uplink.receive([frame({ sequence: 1, epoch: 2 })], NOW);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), ["ROUTE_MISMATCH", "REMOTE_AUTH_INVALID", "REMOTE_AUTH_INVALID"]);
  const revoked = core(dispatcher, [revokeDevice(DEVICE, 1, NOW, "lost")]);
  revoked.receive([frame({ sequence: 1 })], NOW);
  assert.deepEqual(errors(revoked.drainOutbox(NOW)), ["DEVICE_REVOKED"]);
  assert.equal(dispatcher.calls.length, 0);
});

test("negative: scopes beyond the paired ceiling and tools beyond token scopes are denied before dispatch", () => {
  const dispatcher = new StubDispatcher();
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 1, scopes: ["orcel.read", "orcel.execute"] })], NOW);
  uplink.receive([frame({ sequence: 1, payload: call(1, "fs_write") })], NOW);
  uplink.receive([frame({ sequence: 2, payload: call(2, "run_anything") })], NOW);
  uplink.receive([frame({ sequence: 3, payload: call(3, "process_spawn") })], NOW);
  uplink.receive([frame({ sequence: 4, scopes: ["orcel.read", "orcel.write"] })], NOW);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), [
    "REMOTE_SCOPE_DENIED",
    "REMOTE_SCOPE_DENIED",
    "TOOL_SURFACE_DENIED",
    "REMOTE_SCOPE_DENIED",
    "ROUTE_MISMATCH"
  ]);
  assert.equal(dispatcher.calls.length, 0);
});

test("negative: queue-after-revoke and queue-after-expiry never execute", async () => {
  const dispatcher = new StubDispatcher();
  const revocations: RevocationRecord[] = [];
  const uplink = core(dispatcher, revocations);
  uplink.receive([frame({ sequence: 1 })], NOW);
  revocations.push(revokeDevice(DEVICE, 1, NOW + 10, "revoked while queued"));
  await settle(uplink.pump(NOW + 20));
  const late = core(dispatcher);
  late.receive([frame({ sequence: 1, expiresAt: NOW + 120_000 })], NOW);
  await settle(late.pump(NOW + RELAY_BOUNDS.queueLifetimeSeconds * 1000 + 1));
  const expired = core(dispatcher);
  expired.receive([frame({ sequence: 1, expiresAt: NOW + 5_000 })], NOW);
  await settle(expired.pump(NOW + 5_001));
  assert.equal(dispatcher.calls.length, 0);
  assert.deepEqual(errors(uplink.drainOutbox(NOW + 20)), ["DEVICE_REVOKED"]);
  assert.deepEqual(errors(late.drainOutbox(NOW + 60_001)), ["REMOTE_QUEUE_EXPIRED"]);
  assert.deepEqual(errors(expired.drainOutbox(NOW + 5_001)), ["REMOTE_QUEUE_EXPIRED"]);
});

test("bounded queue, per-connection concurrency, device rate, and connection count apply backpressure", async () => {
  const dispatcher = new StubDispatcher();
  dispatcher.hold = true;
  const uplink = core(dispatcher);
  const frames = [];
  for (let i = 1; i <= RELAY_BOUNDS.maxQueuedFrames + 1; i += 1) {
    frames.push(frame({ sequence: i, payload: call(i, "fs_read") }));
  }
  uplink.receive(frames, NOW);
  assert.equal(uplink.queueLength(), RELAY_BOUNDS.maxQueuedFrames);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)), ["REMOTE_RATE_LIMITED"]);
  const running = uplink.pump(NOW);
  assert.equal(running.length, RELAY_BOUNDS.maxConcurrentRequestsPerConnection);
  assert.equal(uplink.pump(NOW).length, 0, "no fifth concurrent request on one connection");
  dispatcher.release();
  await settle(running);
  uplink.receive([frame({ sequence: 1, connectionId: "conn-0002" })], NOW);
  uplink.receive([frame({ sequence: 1, connectionId: "conn-0003", paired: OTHER })], NOW);
  assert.deepEqual(errors(uplink.drainOutbox(NOW)).slice(-1), ["REMOTE_RATE_LIMITED"]);

  // Transient backpressure does not consume the sequence: the relay retries
  // the same sequence with a fresh nonce once capacity returns.
  const retry = core(new StubDispatcher());
  const blocked = [];
  for (let i = 1; i <= RELAY_BOUNDS.maxQueuedFrames; i += 1) {
    blocked.push(frame({ sequence: i, payload: call(i, "fs_read") }));
  }
  retry.receive(blocked, NOW);
  retry.receive([frame({ sequence: 17, correlationId: "late" })], NOW);
  assert.deepEqual(errors(retry.drainOutbox(NOW)), ["REMOTE_RATE_LIMITED"]);
  while (retry.queueLength() > 0) {
    await settle(retry.pump(NOW));
  }
  retry.receive([frame({ sequence: 17, correlationId: "late" })], NOW);
  assert.equal(retry.queueLength(), 1, "the retried sequence is accepted after backpressure clears");

  const rate = core(new StubDispatcher());
  for (let i = 1; i <= RELAY_BOUNDS.maxRequestsPerMinutePerDevice; i += 1) {
    rate.receive([frame({ sequence: i, payload: call(i, "fs_read") })], NOW);
    await settle(rate.pump(NOW));
  }
  rate.receive([frame({ sequence: 61, payload: call(61, "fs_read") })], NOW);
  assert.deepEqual(errors(rate.drainOutbox(NOW)), ["REMOTE_RATE_LIMITED"]);
  rate.receive(
    [frame({ sequence: 61, payload: call(61, "fs_read"), createdAt: NOW + 60_001, expiresAt: NOW + 90_000 })],
    NOW + 60_001
  );
  assert.equal(rate.queueLength(), 1, "the per-device window recovers after one minute");
});

test("cancel removes queued work and suppresses in-flight results", async () => {
  const dispatcher = new StubDispatcher();
  dispatcher.hold = true;
  const uplink = core(dispatcher);
  uplink.receive([frame({ sequence: 1 }), frame({ sequence: 2 })], NOW);
  const running = uplink.pump(NOW);
  uplink.receive([frame({ sequence: 3, kind: "cancel", correlationId: "corr-1" })], NOW);
  dispatcher.release();
  await settle(running);
  const out = uplink.drainOutbox(NOW);
  assert.deepEqual(out.map((f) => f.correlationId), ["corr-2"]);
  const queued = core(new StubDispatcher());
  queued.receive([frame({ sequence: 1 }), frame({ sequence: 2, kind: "cancel", correlationId: "corr-1" })], NOW);
  assert.equal(queued.queueLength(), 0);
  uplink.receive([frame({ sequence: 4, kind: "heartbeat" })], NOW);
  assert.equal(uplink.drainOutbox(NOW).length, 0, "heartbeats carry no request and no reply");
});

test("reconnect grace is bounded and responses are re-authenticated with the new channel", async () => {
  const uplink = core(new StubDispatcher());
  uplink.receive([frame({ sequence: 1 })], NOW);
  await settle(uplink.pump(NOW));
  uplink.setChannelToken(null);
  assert.deepEqual(uplink.drainOutbox(NOW), [], "nothing is sent without an authenticated channel");
  uplink.setChannelToken("N".repeat(43));
  const out = uplink.drainOutbox(NOW + 1000);
  assert.equal(out.length, 1);
  assert.equal(out[0]?.channelAuth, "N".repeat(43));
  uplink.receive([frame({ sequence: 2, channelAuth: "N".repeat(43) })], NOW);
  await settle(uplink.pump(NOW));
  assert.equal(uplink.drainOutbox(NOW + RELAY_BOUNDS.reconnectGraceSeconds * 1000 + 1).length, 0);
  assert.throws(() => uplink.setChannelToken("short"));
});

test("pairing records, relay origins, and kernel remote context are strict", () => {
  assert.ok(isPairedConnection(PAIRED));
  assert.ok(!isPairedConnection({ ...PAIRED, scopeCeiling: ["orcel.admin"] }));
  assert.ok(!isPairedConnection({ ...PAIRED, toolSurfaceProfile: "developer" }));
  assert.ok(!isPairedConnection({ ...PAIRED, principal: "alice@example.com" }));
  assert.ok(!isPairedConnection({ ...PAIRED, extra: 1 }));
  assert.ok(isRelayOrigin("https://relay.orcel.example"));
  assert.ok(isRelayOrigin("http://127.0.0.1:8787"));
  assert.ok(!isRelayOrigin("http://relay.orcel.example"));
  assert.ok(!isRelayOrigin("https://relay.orcel.example/path"));
  assert.ok(!isRelayOrigin("https://user:pw@relay.orcel.example"));
  assert.ok(!isRelayOrigin("socks5://relay.orcel.example"));
  const remote: RemoteDispatchContext = {
    principal: PAIRED.principal,
    remoteConnectionId: PAIRED.remoteConnectionId,
    connectionId: "conn-0001",
    deviceId: DEVICE,
    deviceEpoch: 1,
    providerKind: "generic",
    clientProfileId: "profile-1",
    clientProfileRevision: 1,
    toolSurfaceProfile: "core",
    scopes: ["orcel.read"]
  };
  const request = buildRequest({ sessionId: "s", workspaceId: "default", capability: "fs.read", operation: "read", target: "a" });
  assert.equal(request.remote, undefined, "local requests carry no remote context");
  const attached: KernelRequest = attachRemoteContext(request, remote);
  assert.deepEqual(attached.remote, remote);
  assert.ok(!JSON.stringify(attached.arguments).includes("remote"));
  assert.throws(() => new DeviceUplinkCore({ deviceId: "dev-x", deviceEpoch: 1 }, [PAIRED], new StubDispatcher(), () => []));
  assert.throws(() => new DeviceUplinkCore({ deviceId: DEVICE, deviceEpoch: 1 }, [PAIRED, PAIRED], new StubDispatcher(), () => []));
});

test("uplink state loading fails closed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "orcel-uplink-"));
  const secrets = new Map<string, string>();
  const store = {
    get: async (name: string) => secrets.get(name) ?? null,
    put: async (name: string, value: string) => void secrets.set(name, value)
  };
  assert.throws(() => loadDeviceRecord(join(dir, "missing.json")), /PAIRING_REQUIRED/);
  writeFileSync(join(dir, "bad.json"), "{");
  assert.throws(() => loadDeviceRecord(join(dir, "bad.json")), /PAIRING_REQUIRED/);
  const pair = generateDeviceKeyPair(DEVICE, NOW, 1);
  writeFileSync(join(dir, "key.json"), JSON.stringify(publicDeviceIdentity(pair)));
  assert.equal(loadDeviceRecord(join(dir, "key.json")).deviceId, DEVICE);
  await assert.rejects(loadDeviceKey(join(dir, "key.json"), store), /not in the secret store/);
  secrets.set("device.key", pair.privateKeyJwkBase64);
  assert.equal((await loadDeviceKey(join(dir, "key.json"), store)).privateKeyJwkBase64, pair.privateKeyJwkBase64);
  assert.deepEqual(loadRevocations(join(dir, "none.json")), []);
  writeFileSync(join(dir, "revocations.json"), "not json");
  const failClosed = loadRevocations(join(dir, "revocations.json"));
  assert.equal(failClosed[0]?.kind, "emergency");
  writeFileSync(join(dir, "uplink.json"), JSON.stringify({ schema: "orcel-uplink/1", relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", connections: [PAIRED] }));
  assert.equal(parseUplinkFile(readFileSync(join(dir, "uplink.json"), "utf8")).connections.length, 1);
  for (const bad of [
    { schema: "orcel-uplink/1", relayOrigin: "http://relay.orcel.example", defaultWorkspace: "default", connections: [PAIRED] },
    { schema: "orcel-uplink/1", relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", connections: [] },
    { schema: "orcel-uplink/1", relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", connections: [PAIRED], listen: 80 }
  ]) {
    assert.throws(() => parseUplinkFile(JSON.stringify(bad)), /PAIRING_REQUIRED/);
  }
});

function stubKernel(remotes: RemoteDispatchContext[]): (remote: RemoteDispatchContext) => KernelClient {
  return (remote) => {
    remotes.push(remote);
    return {
      sessionId: "stub",
      remote,
      call: async (input: { capability: string }) => ({
        version: 1,
        request_id: "r",
        ok: false,
        error: { code: "REMOTE_SESSION_INACTIVE", message: `no lease for ${input.capability}` }
      }),
      close: () => {},
      pending: new Map(),
      child: {} as never
    } as unknown as KernelClient;
  };
}

test("the MCP frame dispatcher serves the authoritative catalog and surfaces typed lease denials", async () => {
  const remotes: RemoteDispatchContext[] = [];
  const dispatcher = createMcpFrameDispatcher({ defaultWorkspace: "default", kernelFactory: stubKernel(remotes) });
  const uplink = core(dispatcher);
  const init = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "relay-test", version: "1" } }
  });
  const initialized = JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" });
  const list = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  uplink.receive([frame({ sequence: 1, payload: init })], NOW);
  await settle(uplink.pump(NOW));
  uplink.receive([frame({ sequence: 2, payload: initialized })], NOW);
  await settle(uplink.pump(NOW));
  uplink.receive([frame({ sequence: 3, payload: list })], NOW);
  await settle(uplink.pump(NOW));
  uplink.receive([frame({ sequence: 4, payload: call(4, "fs_read") })], NOW);
  await settle(uplink.pump(NOW));
  const out = uplink.drainOutbox(NOW);
  assert.deepEqual(out.map((f) => f.messageKind), ["mcp_response", "mcp_response", "mcp_response"]);
  const tools = (JSON.parse(out[1]?.payload ?? "{}") as { result: { tools: Array<{ name: string }> } }).result.tools;
  // SG-000065: the relay advertises only the remote `core` profile.
  assert.deepEqual(tools.map((t) => t.name).sort(), [...REMOTE_TOOL_NAMES].sort());
  assert.ok(CANONICAL_TOOL_NAMES.length > REMOTE_TOOL_NAMES.length);
  assert.ok((out[2]?.payload ?? "").includes("REMOTE_SESSION_INACTIVE"));
  assert.equal(remotes.length, 1);
  assert.equal(remotes[0]?.connectionId, "conn-0001");
  dispatcher.closeConnection("conn-0001");
});

class FakeRelay {
  readonly requests: Array<{ url: string; method: string | undefined; redirect: string | undefined }> = [];
  readonly pushed: OutboundFrame[] = [];
  private challenge: DeviceChallenge | null = null;
  private pending: Record<string, unknown>[] = [];
  polls = 0;
  readonly token = "R".repeat(43);

  constructor(
    private readonly identity: ReturnType<typeof publicDeviceIdentity>,
    private readonly origin: string
  ) {}

  enqueue(frames: Record<string, unknown>[]): void {
    this.pending.push(...frames);
  }

  fetch = async (url: string, init: RequestInit): Promise<Response> => {
    this.requests.push({ url, method: init.method, redirect: init.redirect });
    assert.ok(url.startsWith(this.origin + "/device/v1/"), `outbound request stays on the relay origin: ${url}`);
    const body = JSON.parse(String(init.body)) as Record<string, unknown>;
    const json = (value: unknown, status = 200) =>
      new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
    if (url.endsWith(UPLINK_PATHS.challenge)) {
      this.challenge = createDeviceChallenge(String(body.deviceId), Number(body.epoch), NOW);
      return json({ challenge: this.challenge });
    }
    if (url.endsWith(UPLINK_PATHS.session)) {
      const check = verifyChallengeResponse(this.identity, this.challenge as DeviceChallenge, body.response as ChallengeResponse, NOW);
      return check.ok ? json({ channelToken: this.token }) : json({ error: "denied" }, 401);
    }
    if (url.endsWith(UPLINK_PATHS.poll)) {
      this.polls += 1;
      if (body.channelToken !== this.token) {
        return json({ error: "denied" }, 401);
      }
      const frames = this.pending.splice(0, RELAY_BOUNDS.maxQueuedFrames);
      return json({ frames });
    }
    if (url.endsWith(UPLINK_PATHS.push)) {
      assert.equal(body.channelToken, this.token);
      this.pushed.push(...(body.frames as OutboundFrame[]));
      return new Response(null, { status: 204 });
    }
    return json({ error: "unknown" }, 404);
  };
}

test("the outbound-only client authenticates with the device key, long-polls, and pushes responses", async () => {
  const pair = generateDeviceKeyPair(DEVICE, NOW, 1);
  const origin = "https://relay.orcel.example";
  const relay = new FakeRelay(publicDeviceIdentity(pair), origin);
  const controller = new AbortController();
  relay.enqueue([
    frame({ sequence: 1, channelAuth: relay.token }),
    frame({ sequence: 2, channelAuth: relay.token, payload: call(2, "fs_list") })
  ]);
  const dispatcher = new StubDispatcher();
  const run = runDeviceUplink(
    { relayOrigin: origin, identity: { deviceId: DEVICE, deviceEpoch: 1 }, privateKeyJwkBase64: pair.privateKeyJwkBase64, connections: [PAIRED] },
    {
      fetch: async (url, init) => {
        const response = await relay.fetch(url, init);
        if (relay.pushed.length >= 2 || relay.polls > 20) {
          controller.abort();
        }
        return response;
      },
      dispatcher,
      revocations: () => [],
      signal: controller.signal,
      now: () => NOW,
      sleep: async () => {}
    }
  );
  await run;
  assert.equal(dispatcher.calls.length, 2);
  assert.deepEqual(relay.pushed.map((f) => f.correlationId).sort(), ["corr-1", "corr-2"]);
  assert.ok(relay.requests.every((r) => r.method === "POST" && r.redirect === "error"));
  assert.deepEqual(relay.requests.slice(0, 2).map((r) => r.url), [origin + UPLINK_PATHS.challenge, origin + UPLINK_PATHS.session]);
});

test("a relay that cannot prove the device challenge binding never gets a channel", async () => {
  const pair = generateDeviceKeyPair(DEVICE, NOW, 1);
  const origin = "https://relay.orcel.example";
  const controller = new AbortController();
  let attempts = 0;
  await runDeviceUplink(
    { relayOrigin: origin, identity: { deviceId: DEVICE, deviceEpoch: 1 }, privateKeyJwkBase64: pair.privateKeyJwkBase64, connections: [PAIRED] },
    {
      fetch: async (url) => {
        attempts += 1;
        if (attempts > 6) {
          controller.abort();
        }
        if (url.endsWith(UPLINK_PATHS.challenge)) {
          const wrong = createDeviceChallenge("dev-" + "d".repeat(32), 1, NOW);
          return new Response(JSON.stringify({ challenge: wrong }), { status: 200 });
        }
        throw new Error("the device must never reach the session step");
      },
      dispatcher: new StubDispatcher(),
      revocations: () => [],
      signal: controller.signal,
      now: () => NOW,
      sleep: async () => {}
    }
  );
  assert.ok(attempts > 1, "the client retries with bounded backoff");
  await assert.rejects(
    runDeviceUplink(
      { relayOrigin: "http://relay.orcel.example", identity: { deviceId: DEVICE, deviceEpoch: 1 }, privateKeyJwkBase64: pair.privateKeyJwkBase64, connections: [PAIRED] },
      { fetch: async () => new Response(null), dispatcher: new StubDispatcher(), revocations: () => [], signal: new AbortController().signal }
    ),
    /TRANSPORT_UNAVAILABLE/
  );
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const delay = backoffMs(attempt, () => 0.999);
    assert.ok(delay <= 30_000 && delay >= 0);
  }
});

test("uplink sources open no listener and carry no generic proxy capability", () => {
  for (const rel of ["device_uplink.ts", "uplink_state.ts", "transports/relay_device.ts", "entrypoints/relay_device.ts"]) {
    const text = readSource(rel);
    for (const token of DENIED_RELAY_CAPABILITIES) {
      assert.ok(!text.toLowerCase().includes(token), `${rel} must not contain ${token}`);
    }
    for (const forbidden of [
      "node:net",
      "node:http",
      "node:https",
      "node:dgram",
      "node:tls",
      "node:child_process",
      "createServer",
      ".listen(",
      "registerTool(",
      "WebSocket"
    ]) {
      assert.ok(!text.includes(forbidden), `${rel} must not reference ${forbidden}`);
    }
  }
});

test("the relay transport fails closed with PAIRING_REQUIRED when protected pairing state is absent", async () => {
  const { startRelayTransport } = await import("./transports/relay_device.js");
  const saved = {
    config: process.env.ORCEL_UPLINK_CONFIG,
    key: process.env.ORCEL_DEVICE_KEY_PATH,
    revocations: process.env.ORCEL_DEVICE_REVOCATIONS_PATH
  };
  const dir = mkdtempSync(join(tmpdir(), "orcel-relay-transport-"));
  try {
    delete process.env.ORCEL_UPLINK_CONFIG;
    await assert.rejects(startRelayTransport(), /PAIRING_REQUIRED/);
    process.env.ORCEL_UPLINK_CONFIG = join(dir, "missing.json");
    await assert.rejects(startRelayTransport(), /PAIRING_REQUIRED/);
    writeFileSync(join(dir, "uplink.json"), JSON.stringify({ schema: "orcel-uplink/1", relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", connections: [PAIRED] }));
    process.env.ORCEL_UPLINK_CONFIG = join(dir, "uplink.json");
    process.env.ORCEL_DEVICE_KEY_PATH = join(dir, "no-key.json");
    process.env.ORCEL_DEVICE_REVOCATIONS_PATH = join(dir, "revocations.json");
    await assert.rejects(startRelayTransport(), /PAIRING_REQUIRED/);
  } finally {
    for (const [name, value] of [
      ["ORCEL_UPLINK_CONFIG", saved.config],
      ["ORCEL_DEVICE_KEY_PATH", saved.key],
      ["ORCEL_DEVICE_REVOCATIONS_PATH", saved.revocations]
    ] as const) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
});

test("refresh proofs are signed only for this exact device, epoch, and a fresh bounded challenge", async () => {
  const { signRefreshProofs } = await import("./device_uplink.js");
  const { createDeviceChallenge: challengeFor } = await import("./device_identity.js");
  const pair = generateDeviceKeyPair(DEVICE, NOW, 1);
  const config = { relayOrigin: "https://relay.orcel.example", identity: { deviceId: DEVICE, deviceEpoch: 1 }, privateKeyJwkBase64: pair.privateKeyJwkBase64, connections: [PAIRED] };
  const good = challengeFor(DEVICE, 1, NOW);
  const signed = signRefreshProofs(config, [good], NOW + 1000);
  assert.equal(signed.length, 1);
  assert.ok(verifyChallengeResponse(publicDeviceIdentity(pair), good, signed[0] as ChallengeResponse, NOW + 1000).ok);
  const rejected = signRefreshProofs(
    config,
    [
      challengeFor("dev-" + "d".repeat(32), 1, NOW),
      challengeFor(DEVICE, 2, NOW),
      { ...good, expiresAtMs: good.createdAtMs + 10 * 60_000 },
      { ...good, nonceBase64: "x" },
      "not a challenge"
    ],
    NOW + 1000
  );
  assert.equal(rejected.length, 0);
  assert.equal(signRefreshProofs(config, [good], good.expiresAtMs + 1).length, 0, "expired challenges are never signed");
  assert.equal(signRefreshProofs(config, "nope", NOW).length, 0);
  assert.equal(signRefreshProofs(config, new Array(40).fill(good), NOW + 1).length, 16, "bounded per poll");
});
