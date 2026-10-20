import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  createMcpFrameDispatcher,
  runDeviceUplink,
  type PairedConnection
} from "@orcel/mcp/dist/device_uplink.js";
import type { KernelClient, RemoteDispatchContext } from "@orcel/mcp/dist/kernel.js";
import { generatePkceVerifier, pkceS256Challenge } from "@orcel/mcp/dist/oauth_authorization.js";
import { enableRemote, pairRemote } from "@orcel/mcp/dist/remote_enrollment.js";
import type { DeviceKeyPair } from "@orcel/mcp/dist/device_identity.js";
import { DEVICE_KEY_SECRET, type SecretStore } from "@orcel/mcp/dist/secret_store.js";
import { loadDeviceRecord } from "@orcel/mcp/dist/uplink_state.js";

interface KernelCall {
  readonly capability: string;
  readonly arguments: unknown;
  readonly remote: RemoteDispatchContext;
}

const relayLog: string[] = [];
const uplinkLog: string[] = [];
import { FileRelayStore } from "./file_store.js";
import { DEFAULT_QUOTAS } from "./quotas.js";
import { createRelayServer, type RelayServer } from "./server.js";

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      probe.close(() => resolve(typeof address === "object" && address !== null ? address.port : 0));
    });
  });
}

async function waitFor(condition: () => boolean, label: string, timeoutMs = 10_000): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(`timed out waiting for ${label}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

interface Relay {
  readonly origin: string;
  readonly port: number;
  readonly stateDir: string;
  readonly relay: RelayServer;
  readonly store: FileRelayStore;
  close(): Promise<void>;
}

async function startRelay(stateDir: string, port?: number, quotas = DEFAULT_QUOTAS): Promise<Relay> {
  const listenPort = port ?? (await freePort());
  const origin = `http://127.0.0.1:${listenPort}`;
  const store = new FileRelayStore(stateDir);
  const relay = createRelayServer({ publicOrigin: origin, issuer: origin, allowedOrigins: [], store, quotas, pollWaitMs: 300, log: (event) => relayLog.push(event) });
  await new Promise<void>((resolve) => relay.server.listen(listenPort, "127.0.0.1", resolve));
  return {
    origin,
    port: listenPort,
    stateDir,
    relay,
    store,
    async close() {
      relay.server.closeAllConnections();
      await new Promise<void>((resolve) => relay.server.close(() => resolve()));
    }
  };
}

const fetchImpl = (url: string, init: RequestInit) => fetch(url, init);

async function form(origin: string, path: string, fields: Record<string, string>): Promise<{ status: number; json: Record<string, unknown> }> {
  const response = await fetch(origin + path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
    redirect: "manual"
  });
  const text = await response.text();
  const isJson = (response.headers.get("content-type") ?? "").includes("application/json");
  return { status: response.status, json: isJson && text !== "" ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

interface Linked {
  readonly code: string;
  readonly verifier: string;
  readonly clientId: string;
  readonly redirect: string;
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly paired: PairedConnection;
  readonly devicePaths: { key: string; uplink: string };
}

/**
 * XP-19: the device keeps its private key in the orceld secret store; these
 * tests stand in for it with one in-memory store per device key record.
 */
const deviceSecrets = new Map<string, Map<string, string>>();
function secretsFor(keyPath: string): SecretStore {
  let values = deviceSecrets.get(keyPath);
  if (values === undefined) {
    values = new Map();
    deviceSecrets.set(keyPath, values);
  }
  const store = values;
  return {
    get: async (name) => store.get(name) ?? null,
    put: async (name, value) => void store.set(name, value)
  };
}
function devicePair(keyPath: string): DeviceKeyPair {
  const privateKeyJwkBase64 = deviceSecrets.get(keyPath)?.get(DEVICE_KEY_SECRET);
  assert.ok(privateKeyJwkBase64 !== undefined, "the device key is in the secret store");
  return { ...loadDeviceRecord(keyPath), privateKeyJwkBase64 };
}
/** No file the device side wrote holds its private key (XP-19 acceptance). */
function assertNoSecretFile(dir: string, keyPath: string): void {
  const secret = devicePair(keyPath).privateKeyJwkBase64;
  for (const name of readdirSync(dir)) {
    assert.ok(!readFileSync(join(dir, name), "utf8").includes(secret), `${name} holds the device private key`);
  }
}

/** Run the complete standards-based linking flow against a self-hosted relay. */
async function link(r: Relay, approve = true): Promise<Linked | { denied: string }> {
  const deviceDir = mkdtempSync(join(tmpdir(), "orcel-device-"));
  const devicePaths = { key: join(deviceDir, "device_key.json"), uplink: join(deviceDir, "uplink.json") };
  await enableRemote({ relayOrigin: r.origin, defaultWorkspace: "default", deviceKeyPath: devicePaths.key, uplinkPath: devicePaths.uplink, secrets: secretsFor(devicePaths.key), fetch: fetchImpl, nowMs: Date.now() });
  const redirect = "http://127.0.0.1:9/callback";
  const registered = await fetch(`${r.origin}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [redirect], client_name: "Test client", token_endpoint_auth_method: "none", scope: "orcel.read orcel.write" })
  });
  assert.equal(registered.status, 201);
  const clientId = ((await registered.json()) as { client_id: string }).client_id;
  const verifier = generatePkceVerifier();
  const state = "state-" + "s".repeat(24);
  const authorize = new URL(`${r.origin}/oauth/authorize`);
  for (const [key, value] of Object.entries({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirect,
    code_challenge: pkceS256Challenge(verifier),
    code_challenge_method: "S256",
    resource: `${r.origin}/mcp`,
    scope: "orcel.read",
    state
  })) {
    authorize.searchParams.set(key, value);
  }
  const pageResponse = await fetch(authorize, { redirect: "manual" });
  assert.equal(pageResponse.status, 200);
  const pageText = await pageResponse.text();
  assert.ok(pageResponse.headers.get("content-security-policy")?.includes("default-src 'none'"));
  const transaction = /name="transaction" value="([^"]+)"/.exec(pageText)?.[1] ?? "";
  assert.ok(transaction.length >= 43);
  let codeEntered: Promise<void> = Promise.resolve();
  const paired = await pairRemote({
    deviceKeyPath: devicePaths.key,
    uplinkPath: devicePaths.uplink,
    secrets: secretsFor(devicePaths.key),
    fetch: fetchImpl,
    now: Date.now,
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, Math.min(ms, 50))),
    pollIntervalMs: 50,
    display: (code) => {
      codeEntered = form(r.origin, "/oauth/authorize", { transaction, pairing_code: code }).then((reply) => assert.equal(reply.status, 200));
    },
    confirm: async (request) => {
      await codeEntered;
      assert.equal(request.clientName, "Test client");
      assert.equal(request.redirectOrigin, "http://127.0.0.1:9");
      assert.deepEqual(request.scopes, ["orcel.read"]);
      return approve;
    }
  });
  const status = await fetch(`${r.origin}/oauth/authorize/status?transaction=${encodeURIComponent(transaction)}`, { redirect: "manual" });
  assert.equal(status.status, 302);
  const location = new URL(status.headers.get("location") ?? "");
  assert.equal(location.searchParams.get("state"), state);
  assert.equal(location.searchParams.get("iss"), r.origin);
  if (!approve) {
    assert.equal(paired, null);
    return { denied: location.searchParams.get("error") ?? "" };
  }
  assert.ok(paired !== null);
  assertNoSecretFile(dirname(devicePaths.key), devicePaths.key);
  const code = location.searchParams.get("code") ?? "";
  const tokens = await form(r.origin, "/oauth/token", {
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: redirect,
    code_verifier: verifier,
    resource: `${r.origin}/mcp`
  });
  assert.equal(tokens.status, 200, JSON.stringify(tokens.json));
  return {
    code,
    verifier,
    clientId,
    redirect,
    accessToken: String(tokens.json.access_token),
    refreshToken: String(tokens.json.refresh_token),
    paired,
    devicePaths
  };
}

function startUplink(r: Relay, linked: Linked): { stop: () => Promise<void>; calls: KernelCall[] } {
  const calls: KernelCall[] = [];
  const pair = devicePair(linked.devicePaths.key);
  const uplink = JSON.parse(readFileSync(linked.devicePaths.uplink, "utf8")) as { connections: PairedConnection[] };
  const controller = new AbortController();
  const done = runDeviceUplink(
    { relayOrigin: r.origin, identity: { deviceId: pair.deviceId, deviceEpoch: pair.epoch }, privateKeyJwkBase64: pair.privateKeyJwkBase64, connections: uplink.connections },
    {
      fetch: fetchImpl,
      dispatcher: createMcpFrameDispatcher({
        defaultWorkspace: "default",
        kernelFactory: (remote) =>
          ({
            sessionId: "stub",
            remote,
            call: async (input: { capability: string; arguments?: unknown }) => {
              calls.push({ capability: input.capability, arguments: input.arguments ?? {}, remote });
              return { version: 1, request_id: "r", ok: false, error: { code: "REMOTE_SESSION_INACTIVE", message: "no lease" } };
            },
            close: () => {},
            pending: new Map(),
            child: {} as never
          }) as unknown as KernelClient
      }),
      revocations: () => [],
      signal: controller.signal,
      log: (event) => uplinkLog.push(event),
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, Math.min(ms, 50)))
    }
  );
  return {
    calls,
    async stop() {
      controller.abort();
      r.relay.hub.closeChannel(pair.deviceId);
      await done;
    }
  };
}

async function mcp(r: Relay, token: string, body: unknown, session?: string): Promise<Response> {
  return fetch(`${r.origin}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
      ...(session === undefined ? {} : { "mcp-session-id": session })
    },
    body: JSON.stringify(body)
  });
}

interface Tenant {
  readonly linked: Linked;
  readonly uplink: { stop: () => Promise<void>; calls: KernelCall[] };
  readonly deviceId: string;
}

async function tenant(r: Relay): Promise<Tenant> {
  const linked = await link(r);
  if ("denied" in linked) {
    throw new Error("unexpected denial");
  }
  const uplink = startUplink(r, linked);
  const deviceId = devicePair(linked.devicePaths.key).deviceId;
  await waitFor(() => r.relay.hub.isOnline(deviceId), "device channel");
  return { linked, uplink, deviceId };
}

async function session(r: Relay, token: string): Promise<string> {
  const init = await mcp(r, token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "adv", version: "1" } } });
  assert.equal(init.status, 200, await init.clone().text());
  const id = init.headers.get("mcp-session-id") ?? "";
  await init.text();
  const ack = await mcp(r, token, { jsonrpc: "2.0", method: "notifications/initialized" }, id);
  assert.equal(ack.status, 202);
  return id;
}

function call(id: number, name: string, args: Record<string, unknown> = { path: "README.md" }, meta?: Record<string, unknown>) {
  return { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args, ...(meta === undefined ? {} : { _meta: meta }) } };
}

test("adversarial: two tenants on one relay never cross principal, device, route, client, or session", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-adv-")));
  const a = await tenant(r);
  const b = await tenant(r);
  try {
    const sa = await session(r, a.linked.accessToken);
    const sb = await session(r, b.linked.accessToken);
    const ra = await mcp(r, a.linked.accessToken, call(2, "fs_read"), sa);
    const rb = await mcp(r, b.linked.accessToken, call(3, "fs_read"), sb);
    assert.equal(ra.status, 200);
    assert.equal(rb.status, 200);
    await ra.text();
    await rb.text();
    assert.equal(a.uplink.calls.length, 1);
    assert.equal(b.uplink.calls.length, 1);
    assert.equal(a.uplink.calls[0]?.remote.principal, a.linked.paired.principal);
    assert.equal(b.uplink.calls[0]?.remote.principal, b.linked.paired.principal);
    assert.notEqual(a.linked.paired.principal, b.linked.paired.principal);
    assert.equal(a.uplink.calls[0]?.remote.deviceId, a.deviceId);
    assert.equal(b.uplink.calls[0]?.remote.deviceId, b.deviceId);
    // Tenant A's token cannot use tenant B's session, and vice versa.
    for (const [token, foreign] of [[a.linked.accessToken, sb], [b.linked.accessToken, sa]] as const) {
      const reply = await mcp(r, token, call(9, "fs_read"), foreign);
      assert.equal(reply.status, 404);
      await reply.text();
    }
    // Tenant A's refresh token cannot be redeemed by tenant B's client.
    const crossClient = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: a.linked.refreshToken, client_id: b.linked.clientId, resource: `${r.origin}/mcp` });
    assert.equal(crossClient.status, 400);
    assert.equal(crossClient.json.error_description, "client_mismatch");
    // Revoking tenant B's device at the relay never affects tenant A.
    r.store.revokeDevice(b.deviceId);
    const revoked = await mcp(r, b.linked.accessToken, call(4, "fs_read"), sb);
    assert.equal(revoked.status, 401);
    await revoked.text();
    const still = await mcp(r, a.linked.accessToken, call(5, "fs_read"), sa);
    assert.equal(still.status, 200);
    await still.text();
    assert.equal(b.uplink.calls.length, 1, "nothing reached the revoked tenant after revocation");
  } finally {
    await a.uplink.stop();
    await b.uplink.stop();
    await r.close();
  }
});

test("adversarial: metadata and arguments can never select remote identity, and management tools do not exist", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-adv-")));
  const a = await tenant(r);
  try {
    const sa = await session(r, a.linked.accessToken);
    const forged = await mcp(
      r,
      a.linked.accessToken,
      call(2, "fs_read", { path: "README.md", principal: "rp-" + "f".repeat(32), remote: { deviceId: "dev-" + "f".repeat(32) }, workspace_id: "default" }, { principal: "rp-" + "f".repeat(32), deviceId: "dev-" + "f".repeat(32), scopes: ["orcel.execute"] }),
      sa
    );
    assert.equal(forged.status, 200);
    await forged.text();
    const seen = a.uplink.calls[0];
    assert.ok(seen !== undefined);
    assert.equal(seen.remote.principal, a.linked.paired.principal);
    assert.equal(seen.remote.deviceId, a.deviceId);
    assert.deepEqual(seen.remote.scopes, ["orcel.read"]);
    assert.ok(!JSON.stringify(seen.arguments).includes("rp-ffff"), "unknown tool arguments are stripped before the kernel");
    for (const name of ["remote_lease_create", "workspace_trust_grant", "emergency_revoke", "shell", "run_anything", "process_spawn"]) {
      const reply = await mcp(r, a.linked.accessToken, call(7, name), sa);
      assert.equal(reply.status, 403, name);
      await reply.text();
    }
    assert.equal(a.uplink.calls.length, 1);
  } finally {
    await a.uplink.stop();
    await r.close();
  }
});

test("adversarial: relay restart drops sessions, devices reconnect, and nothing replays or extends", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "orcel-adv-"));
  const first = await startRelay(stateDir);
  const linked = await link(first);
  if ("denied" in linked) {
    throw new Error("unexpected denial");
  }
  const pair = devicePair(linked.devicePaths.key);
  const port = first.port;
  let uplink = startUplink(first, linked);
  await waitFor(() => first.relay.hub.isOnline(pair.deviceId), "device channel");
  const before = await session(first, linked.accessToken);
  await uplink.stop();
  await first.close();
  const second = await startRelay(stateDir, port);
  uplink = startUplink(second, linked);
  try {
    await waitFor(() => second.relay.hub.isOnline(pair.deviceId), "device reconnect");
    let stale: Response;
    try {
      stale = await mcp(second, linked.accessToken, call(2, "fs_read"), before);
    } catch {
      stale = await mcp(second, linked.accessToken, call(2, "fs_read"), before);
    }
    assert.equal(stale.status, 404, "sessions never survive a relay restart");
    await stale.text();
    assert.equal(uplink.calls.length, 0, "no request replayed after restart");
    const fresh = await session(second, linked.accessToken);
    const reply = await mcp(second, linked.accessToken, call(3, "fs_read"), fresh);
    assert.equal(reply.status, 200);
    assert.ok((await reply.text()).includes("REMOTE_SESSION_INACTIVE"), "the local lease still decides after restart");
  } finally {
    await uplink.stop();
    await second.close();
  }
});

test("adversarial: per-route quota exhaustion fails closed before the device", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-adv-")), undefined, { ...DEFAULT_QUOTAS, mcpRequestsPerMinutePerRoute: 3 });
  const a = await tenant(r);
  try {
    const sa = await session(r, a.linked.accessToken);
    const ok = await mcp(r, a.linked.accessToken, call(2, "fs_read"), sa);
    assert.equal(ok.status, 200);
    await ok.text();
    const limited = await mcp(r, a.linked.accessToken, call(3, "fs_read"), sa);
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);
    assert.ok((await limited.text()).includes("REMOTE_RATE_LIMITED"));
    assert.equal(a.uplink.calls.length, 1);
  } finally {
    await a.uplink.stop();
    await r.close();
  }
});

test("adversarial: relay and uplink logs carry classes only, never tokens, codes, identifiers, or payloads", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-adv-")));
  const a = await tenant(r);
  try {
    const sa = await session(r, a.linked.accessToken);
    const reply = await mcp(r, a.linked.accessToken, call(2, "fs_read", { path: "secret-plan.txt" }), sa);
    await reply.text();
    const all = [...relayLog, ...uplinkLog];
    assert.ok(all.length > 0);
    for (const event of all) {
      assert.match(event, /^[a-z0-9_]+$/, event);
    }
    const joined = all.join("\n");
    for (const secret of [a.linked.accessToken, a.linked.refreshToken, a.linked.paired.principal, a.linked.paired.remoteConnectionId, a.deviceId, "secret-plan", sa]) {
      assert.ok(!joined.includes(secret));
    }
    const state = readFileSync(join(r.stateDir, "relay-state.json"), "utf8");
    for (const secret of [a.linked.accessToken, a.linked.refreshToken, "secret-plan"]) {
      assert.ok(!state.includes(secret), "relay state holds no tokens or payloads");
    }
    assert.ok(!state.includes(devicePair(a.linked.devicePaths.key).privateKeyJwkBase64), "relay state never holds device private keys");
  } finally {
    await a.uplink.stop();
    await r.close();
  }
});
