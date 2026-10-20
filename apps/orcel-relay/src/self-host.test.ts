import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  createMcpFrameDispatcher,
  runDeviceUplink,
  type PairedConnection
} from "@orcel/mcp/dist/device_uplink.js";
import type { KernelClient } from "@orcel/mcp/dist/kernel.js";
import { generatePkceVerifier, pkceS256Challenge } from "@orcel/mcp/dist/oauth_authorization.js";
import { enableRemote, pairRemote } from "@orcel/mcp/dist/remote_enrollment.js";
import type { DeviceKeyPair } from "@orcel/mcp/dist/device_identity.js";
import { DEVICE_KEY_SECRET, type SecretStore } from "@orcel/mcp/dist/secret_store.js";
import { loadDeviceRecord } from "@orcel/mcp/dist/uplink_state.js";
import { CANONICAL_TOOL_NAMES } from "@orcel/mcp/dist/server.js";
import { REMOTE_TOOL_NAMES, securitySchemesFor } from "@orcel/mcp/dist/tool_contract.js";
import { parseRelayConfig } from "./config.js";
import { FileRelayStore, RelayStateError, STATE_FILE } from "./file_store.js";
import { DEFAULT_QUOTAS, QUOTA_CEILINGS, validateQuotas } from "./quotas.js";
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
  const relay = createRelayServer({ publicOrigin: origin, issuer: origin, allowedOrigins: [], store, quotas, pollWaitMs: 300 });
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

/** Run the complete standards-based linking flow against a self-hosted relay. */
interface LinkOptions {
  readonly registerRedirect?: string;
  readonly useRedirect?: string;
  readonly clientName?: string;
  /** Reuse an existing device (a second provider pairing the same computer). */
  readonly devicePaths?: { readonly key: string; readonly uplink: string };
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

async function link(r: Relay, approve = true, options: LinkOptions = {}): Promise<Linked | { denied: string }> {
  const deviceDir = mkdtempSync(join(tmpdir(), "orcel-device-"));
  const devicePaths = options.devicePaths ?? { key: join(deviceDir, "device_key.json"), uplink: join(deviceDir, "uplink.json") };
  await enableRemote({ relayOrigin: r.origin, defaultWorkspace: "default", deviceKeyPath: devicePaths.key, uplinkPath: devicePaths.uplink, secrets: secretsFor(devicePaths.key), fetch: fetchImpl, nowMs: Date.now() });
  const registerRedirect = options.registerRedirect ?? "http://127.0.0.1:9/callback";
  const redirect = options.useRedirect ?? registerRedirect;
  const clientName = options.clientName ?? "Test client";
  const registered = await fetch(`${r.origin}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [registerRedirect], client_name: clientName, token_endpoint_auth_method: "none", scope: "orcel.read orcel.write" })
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
      assert.equal(request.clientName, clientName);
      assert.equal(request.redirectOrigin, new URL(redirect).origin);
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

function startUplink(r: Relay, linked: Linked): { stop: () => Promise<void>; calls: string[] } {
  const calls: string[] = [];
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
            call: async (input: { capability: string }) => {
              calls.push(input.capability);
              return { version: 1, request_id: "r", ok: false, error: { code: "REMOTE_SESSION_INACTIVE", message: "no lease" } };
            },
            close: () => {},
            pending: new Map(),
            child: {} as never
          }) as unknown as KernelClient
      }),
      revocations: () => [],
      signal: controller.signal,
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

test("a standards OAuth client links through device pairing and reaches the device via a self-hosted relay", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "orcel-relay-state-"));
  const r = await startRelay(stateDir);
  let uplink: { stop: () => Promise<void>; calls: string[] } | null = null;
  try {
    const metadata = (await (await fetch(`${r.origin}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    assert.equal(metadata.issuer, r.origin);
    assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
    const linked = await link(r);
    assert.ok(!("denied" in linked));
    if ("denied" in linked) {
      return;
    }
    uplink = startUplink(r, linked);
    const deviceId = devicePair(linked.devicePaths.key).deviceId;
    await waitFor(() => r.relay.hub.isOnline(deviceId), "device channel");
    const init = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    assert.equal(init.status, 200, await init.clone().text());
    const session = init.headers.get("mcp-session-id") ?? "";
    await init.text();
    assert.equal((await mcp(r, linked.accessToken, { jsonrpc: "2.0", method: "notifications/initialized" }, session)).status, 202);
    const list = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 2, method: "tools/list" }, session);
    const listed = ((await list.json()) as { result: { tools: Array<{ name: string; _meta?: Record<string, unknown> }> } }).result.tools;
    const tools = listed.map((t) => t.name).sort();
    // SG-000065: remote discovery lists exactly the core profile.
    assert.deepEqual(tools, [...REMOTE_TOOL_NAMES].sort());
    // SG-000067: every remote tool declares its exact OAuth scheme in _meta.
    for (const tool of listed) {
      assert.deepEqual(tool._meta?.securitySchemes, securitySchemesFor(tool.name), tool.name);
    }
    assert.ok(CANONICAL_TOOL_NAMES.length > REMOTE_TOOL_NAMES.length);

    // Refresh requires a fresh device proof over the live channel and rotates.
    const refreshed = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: linked.refreshToken, client_id: linked.clientId, resource: `${r.origin}/mcp` });
    assert.equal(refreshed.status, 200, JSON.stringify(refreshed.json));
    const rotated = String(refreshed.json.refresh_token);
    assert.notEqual(rotated, linked.refreshToken);
    // Replaying the rotated-away refresh token revokes the whole family.
    const replay = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: linked.refreshToken, client_id: linked.clientId, resource: `${r.origin}/mcp` });
    assert.equal(replay.status, 400);
    assert.equal(replay.json.error_description, "refresh_replayed");
    const afterReplay = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: rotated, client_id: linked.clientId, resource: `${r.origin}/mcp` });
    assert.equal(afterReplay.status, 400);
    assert.equal(afterReplay.json.error_description, "family_revoked");

    // Revoking an access token takes effect at the edge.
    assert.equal((await form(r.origin, "/oauth/revoke", { token: linked.accessToken, client_id: linked.clientId })).status, 200);
    assert.equal((await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 3, method: "tools/list" }, session)).status, 401);
  } finally {
    await uplink?.stop();
    await r.close();
  }
});

test("SG-000068: Claude web and Claude Code connector flows reach the device with the core profile only", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-claude-")));
  try {
    for (const options of [
      { registerRedirect: "https://claude.ai/api/mcp/auth_callback", clientName: "Claude" },
      { registerRedirect: "http://localhost/callback", useRedirect: "http://localhost:61264/callback", clientName: "Claude Code MCP Client" }
    ]) {
      const linked = await link(r, true, options);
      assert.ok(!("denied" in linked), options.clientName);
      if ("denied" in linked) continue;
      const uplink = startUplink(r, linked);
      try {
        const deviceId = devicePair(linked.devicePaths.key).deviceId;
        await waitFor(() => r.relay.hub.isOnline(deviceId), "device channel");
        const init = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: options.clientName, version: "1" } } });
        assert.equal(init.status, 200);
        const session = init.headers.get("mcp-session-id") ?? "";
        await init.text();
        await (await mcp(r, linked.accessToken, { jsonrpc: "2.0", method: "notifications/initialized" }, session)).text();
        const list = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 2, method: "tools/list" }, session);
        const listed = ((await list.json()) as { result: { tools: Array<{ name: string; _meta?: Record<string, unknown> }> } }).result.tools;
        assert.deepEqual(listed.map((t) => t.name).sort(), [...REMOTE_TOOL_NAMES].sort(), options.clientName);
        for (const tool of listed) {
          assert.deepEqual(tool._meta?.securitySchemes, securitySchemesFor(tool.name));
        }
        // A local-only tool is refused at the edge for this connector too.
        const local = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "clipboard_read", arguments: {} } }, session);
        assert.equal(local.status, 403);
        await local.text();
      } finally {
        await uplink.stop();
      }
    }
    // Negative: a redirect that differs in anything but the loopback port is refused before any page renders.
    const registered = await fetch(`${r.origin}/oauth/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://localhost/callback", "https://claude.ai/api/mcp/auth_callback"], client_name: "Claude", token_endpoint_auth_method: "none", scope: "orcel.read" })
    });
    const clientId = ((await registered.json()) as { client_id: string }).client_id;
    for (const bad of [
      "http://localhost:61264/other",
      "https://localhost:61264/callback",
      "http://127.0.0.1:61264/callback",
      "http://localhost.evil.example:61264/callback",
      "https://claude.ai:8443/api/mcp/auth_callback",
      "https://evil.example/api/mcp/auth_callback"
    ]) {
      const authorize = new URL(`${r.origin}/oauth/authorize`);
      for (const [key, value] of Object.entries({
        response_type: "code",
        client_id: clientId,
        redirect_uri: bad,
        code_challenge: pkceS256Challenge(generatePkceVerifier()),
        code_challenge_method: "S256",
        resource: `${r.origin}/mcp`,
        scope: "orcel.read",
        state: "state-" + "s".repeat(24)
      })) {
        authorize.searchParams.set(key, value);
      }
      const reply = await fetch(authorize, { redirect: "manual" });
      assert.equal(reply.status, 400, bad);
      assert.equal(reply.headers.get("location"), null, bad);
      await reply.text();
    }
  } finally {
    await r.close();
  }
});

test("SG-000069: a Vibe Work-style OAuth connector reaches the core profile and static bearer credentials are refused", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-mistral-")));
  try {
    // Vibe Work registers dynamically with an https callback; the exact Mistral
    // callback is not published, so a representative https callback is used.
    const linked = await link(r, true, { registerRedirect: "https://vibe-work.example/oauth/callback", clientName: "Vibe Work" });
    assert.ok(!("denied" in linked));
    if ("denied" in linked) return;
    const uplink = startUplink(r, linked);
    try {
      const deviceId = devicePair(linked.devicePaths.key).deviceId;
      await waitFor(() => r.relay.hub.isOnline(deviceId), "device channel");
      const init = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "Vibe Work", version: "1" } } });
      assert.equal(init.status, 200);
      const session = init.headers.get("mcp-session-id") ?? "";
      await init.text();
      await (await mcp(r, linked.accessToken, { jsonrpc: "2.0", method: "notifications/initialized" }, session)).text();
      const list = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 2, method: "tools/list" }, session);
      const listed = ((await list.json()) as { result: { tools: Array<{ name: string }> } }).result.tools;
      assert.deepEqual(listed.map((t) => t.name).sort(), [...REMOTE_TOOL_NAMES].sort());
    } finally {
      await uplink.stop();
    }
    // A static API key or loopback-style bearer is not an OAuth access token.
    for (const credential of ["Q".repeat(40), "orcel-loopback-token-" + "x".repeat(32), "Basic " + Buffer.from("user:pass").toString("base64")]) {
      const reply = await fetch(`${r.origin}/mcp`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: credential.startsWith("Basic ") ? credential : `Bearer ${credential}`
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })
      });
      assert.equal(reply.status, 401, credential.slice(0, 8));
      assert.ok((reply.headers.get("www-authenticate") ?? "").startsWith("Bearer "), "OAuth challenge");
      await reply.text();
    }
  } finally {
    await r.close();
  }
});

test("SG-000070: a Codex-style OAuth client with a loopback redirect reaches the core profile", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-codex-")));
  try {
    const linked = await link(r, true, {
      registerRedirect: "http://127.0.0.1/callback",
      useRedirect: "http://127.0.0.1:1455/callback",
      clientName: "Codex"
    });
    assert.ok(!("denied" in linked));
    if ("denied" in linked) return;
    const uplink = startUplink(r, linked);
    try {
      const deviceId = devicePair(linked.devicePaths.key).deviceId;
      await waitFor(() => r.relay.hub.isOnline(deviceId), "device channel");
      const init = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "codex", version: "1" } } });
      assert.equal(init.status, 200);
      const session = init.headers.get("mcp-session-id") ?? "";
      await init.text();
      await (await mcp(r, linked.accessToken, { jsonrpc: "2.0", method: "notifications/initialized" }, session)).text();
      const list = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 2, method: "tools/list" }, session);
      const listed = ((await list.json()) as { result: { tools: Array<{ name: string }> } }).result.tools;
      assert.deepEqual(listed.map((t) => t.name).sort(), [...REMOTE_TOOL_NAMES].sort());
    } finally {
      await uplink.stop();
    }
  } finally {
    await r.close();
  }
});

test("SG-000071: two providers on one device never share credentials, sessions, routes, or revocation", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-isolation-")));
  const deviceDir = mkdtempSync(join(tmpdir(), "orcel-device-shared-"));
  const devicePaths = { key: join(deviceDir, "device_key.json"), uplink: join(deviceDir, "uplink.json") };
  const controller = new AbortController();
  let done: Promise<void> = Promise.resolve();
  try {
    const gpt = await link(r, true, { registerRedirect: "https://chatgpt.com/connector_platform_oauth_redirect", clientName: "ChatGPT", devicePaths });
    const claude = await link(r, true, { registerRedirect: "https://claude.ai/api/mcp/auth_callback", clientName: "Claude", devicePaths });
    assert.ok(!("denied" in gpt) && !("denied" in claude));
    if ("denied" in gpt || "denied" in claude) return;
    assert.notEqual(gpt.clientId, claude.clientId);
    assert.notEqual(gpt.paired.remoteConnectionId, claude.paired.remoteConnectionId);

    // One uplink serves both connections; record which connection each
    // dispatched call carries.
    const pair = devicePair(devicePaths.key);
    const uplinkDocument = JSON.parse(readFileSync(devicePaths.uplink, "utf8")) as { connections: PairedConnection[] };
    assert.equal(uplinkDocument.connections.length, 2);
    const dispatched: string[] = [];
    done = runDeviceUplink(
      { relayOrigin: r.origin, identity: { deviceId: pair.deviceId, deviceEpoch: pair.epoch }, privateKeyJwkBase64: pair.privateKeyJwkBase64, connections: uplinkDocument.connections },
      {
        fetch: fetchImpl,
        dispatcher: createMcpFrameDispatcher({
          defaultWorkspace: "default",
          kernelFactory: (remote) =>
            ({
              sessionId: "stub",
              remote,
              call: async () => {
                dispatched.push(remote.remoteConnectionId);
                return { version: 1, request_id: "r", ok: false, error: { code: "REMOTE_SESSION_INACTIVE", message: "no lease" } };
              },
              close: () => {},
              pending: new Map(),
              child: {} as never
            }) as unknown as KernelClient
        }),
        revocations: () => [],
        signal: controller.signal,
        sleep: (ms) => new Promise((resolve) => setTimeout(resolve, Math.min(ms, 50)))
      }
    );
    await waitFor(() => r.relay.hub.isOnline(pair.deviceId), "device channel");

    const open = async (token: string): Promise<string> => {
      const init = await mcp(r, token, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "iso", version: "1" } } });
      assert.equal(init.status, 200);
      const id = init.headers.get("mcp-session-id") ?? "";
      await init.text();
      await (await mcp(r, token, { jsonrpc: "2.0", method: "notifications/initialized" }, id)).text();
      return id;
    };
    const read = (id: number) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "fs_read", arguments: { path: "README.md" } } });
    const sg = await open(gpt.accessToken);
    const sc = await open(claude.accessToken);

    const ok1 = await mcp(r, gpt.accessToken, read(2), sg);
    const ok2 = await mcp(r, claude.accessToken, read(3), sc);
    assert.equal(ok1.status, 200);
    assert.equal(ok2.status, 200);
    await ok1.text();
    await ok2.text();
    assert.deepEqual(dispatched, [gpt.paired.remoteConnectionId, claude.paired.remoteConnectionId], "each call carries its own provider connection");

    // A provider token on the other provider's session is unknown.
    for (const [token, foreign] of [[gpt.accessToken, sc], [claude.accessToken, sg]] as const) {
      const reply = await mcp(r, token, read(4), foreign);
      assert.equal(reply.status, 404);
      await reply.text();
    }
    // A provider's refresh token cannot be redeemed by the other provider's client.
    for (const [refresh, client] of [[gpt.refreshToken, claude.clientId], [claude.refreshToken, gpt.clientId]] as const) {
      const cross = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: refresh, client_id: client, resource: `${r.origin}/mcp` });
      assert.equal(cross.status, 400);
      assert.equal(cross.json.error_description, "client_mismatch");
    }
    // A provider's spent authorization code cannot be redeemed by the other provider.
    const crossCode = await form(r.origin, "/oauth/token", {
      grant_type: "authorization_code",
      code: gpt.code,
      client_id: claude.clientId,
      redirect_uri: claude.redirect,
      code_verifier: gpt.verifier,
      resource: `${r.origin}/mcp`
    });
    assert.equal(crossCode.status, 400);

    // Revoking one provider's connection leaves the other provider working.
    const before = dispatched.length;
    r.store.revokeConnection(gpt.paired.remoteConnectionId);
    const revoked = await mcp(r, gpt.accessToken, read(5), sg);
    assert.notEqual(revoked.status, 200);
    await revoked.text();
    const still = await mcp(r, claude.accessToken, read(6), sc);
    assert.equal(still.status, 200);
    await still.text();
    assert.deepEqual(dispatched.slice(before), [claude.paired.remoteConnectionId], "nothing reached the device for the revoked provider");

    // Only an explicit device revoke ends every provider on that computer.
    r.store.revokeDevice(pair.deviceId);
    const gone = await mcp(r, claude.accessToken, read(7), sc);
    assert.notEqual(gone.status, 200);
    await gone.text();
  } finally {
    controller.abort();
    r.relay.hub.closeChannel(devicePair(devicePaths.key).deviceId);
    await done;
    await r.close();
  }
});

test("negative: authorization code replay is refused and revokes every token issued from the code", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-state-")));
  try {
    const linked = await link(r);
    if ("denied" in linked) {
      throw new Error("unexpected denial");
    }
    const replay = await form(r.origin, "/oauth/token", {
      grant_type: "authorization_code",
      code: linked.code,
      client_id: linked.clientId,
      redirect_uri: linked.redirect,
      code_verifier: linked.verifier,
      resource: `${r.origin}/mcp`
    });
    assert.equal(replay.status, 400);
    assert.equal(replay.json.error_description, "code_replayed");
    const refresh = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: linked.refreshToken, client_id: linked.clientId, resource: `${r.origin}/mcp` });
    assert.equal(refresh.status, 400, "the family issued from a replayed code is revoked");
    const edge = await mcp(r, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.equal(edge.status, 401, "access tokens from that family are rejected");
    await edge.text();
  } finally {
    await r.close();
  }
});

test("negative: a stolen refresh token cannot renew while the bound device is offline", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-state-")));
  try {
    const linked = await link(r);
    if ("denied" in linked) {
      throw new Error("unexpected denial");
    }
    const started = Date.now();
    const offline = await form(r.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: linked.refreshToken, client_id: linked.clientId, resource: `${r.origin}/mcp` });
    assert.equal(offline.status, 400);
    assert.equal(offline.json.error_description, "device_proof_missing");
    assert.ok(Date.now() - started < 5_000, "an offline device is refused immediately");
  } finally {
    await r.close();
  }
});

test("negative: the device can decline, and the client receives access_denied", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-state-")));
  try {
    const result = await link(r, false);
    assert.deepEqual(result, { denied: "access_denied" });
  } finally {
    await r.close();
  }
});

test("negative: authorization requests and pairing codes are strictly validated", async () => {
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-state-")));
  try {
    const unknown = await fetch(`${r.origin}/oauth/authorize?client_id=nope&redirect_uri=https://evil.example/cb`, { redirect: "manual" });
    assert.equal(unknown.status, 400, "unknown clients never redirect");
    await unknown.text();
    const registered = await fetch(`${r.origin}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client.example/cb"] }) });
    const clientId = ((await registered.json()) as { client_id: string }).client_id;
    for (const bad of [
      { redirect_uris: ["http://client.example/cb"] },
      { redirect_uris: ["https://client.example/cb"], token_endpoint_auth_method: "client_secret_basic" },
      { redirect_uris: ["https://client.example/cb"], grant_types: ["password"] },
      { redirect_uris: ["https://client.example/cb"], scope: "orcel.root" },
      { redirect_uris: ["https://client.example/cb"], jwks_uri: "https://evil.example" }
    ]) {
      const reply = await fetch(`${r.origin}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bad) });
      assert.equal(reply.status, 400, JSON.stringify(bad));
      await reply.text();
    }
    const authorize = new URL(`${r.origin}/oauth/authorize`);
    for (const [key, value] of Object.entries({
      response_type: "code",
      client_id: clientId,
      redirect_uri: "https://client.example/cb",
      code_challenge: pkceS256Challenge(generatePkceVerifier()),
      code_challenge_method: "S256",
      resource: `${r.origin}/mcp`,
      scope: "orcel.read",
      state: "s".repeat(32)
    })) {
      authorize.searchParams.set(key, value);
    }
    const wrongResource = new URL(authorize);
    wrongResource.searchParams.set("resource", "https://other.example/mcp");
    const redirected = await fetch(wrongResource, { redirect: "manual" });
    assert.equal(redirected.status, 302);
    assert.equal(new URL(redirected.headers.get("location") ?? "").searchParams.get("error"), "invalid_request");
    const pageText = await (await fetch(authorize, { redirect: "manual" })).text();
    const transaction = /name="transaction" value="([^"]+)"/.exec(pageText)?.[1] ?? "";
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const reply = await fetch(`${r.origin}/oauth/authorize`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ transaction, pairing_code: "0".repeat(64) }).toString()
      });
      assert.equal(reply.status, 400);
      await reply.text();
    }
    const locked = await fetch(`${r.origin}/oauth/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ transaction, pairing_code: "0".repeat(64) }).toString()
    });
    assert.ok((await locked.text()).includes("Too many attempts"));
    const token = await form(r.origin, "/oauth/token", { grant_type: "password", client_id: clientId, username: "u", password: "p" });
    assert.equal(token.json.error, "unsupported_grant_type");
    const forged = await form(r.origin, "/oauth/token", { grant_type: "authorization_code", code: "A".repeat(43), client_id: clientId });
    assert.equal(forged.json.error, "invalid_grant");
  } finally {
    await r.close();
  }
});

test("relay state survives restart, keeps its signing key, and refuses corrupt state", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "orcel-relay-state-"));
  const first = await startRelay(stateDir);
  const linked = await link(first);
  if ("denied" in linked) {
    throw new Error("unexpected denial");
  }
  const port = first.port;
  await first.close();
  const second = await startRelay(stateDir, port);
  try {
    // Same signing key, client, route, and device: the token authenticates and
    // the request fails only because the device is offline.
    let reply: Response;
    try {
      reply = await mcp(second, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    } catch {
      // A pooled keep-alive socket to the stopped server is reset once.
      reply = await mcp(second, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    }
    assert.equal(reply.status, 503);
    assert.ok((await reply.text()).includes("DEVICE_OFFLINE"));
  } finally {
    await second.close();
  }
  const path = join(stateDir, STATE_FILE);
  const text = readFileSync(path, "utf8");
  writeFileSync(path, text.replace('"revoked":false', '"revoked":true'));
  assert.throws(() => new FileRelayStore(stateDir), RelayStateError);
  writeFileSync(path, "{");
  assert.throws(() => new FileRelayStore(stateDir), RelayStateError);
});

test("quotas are explicit, bounded by hard ceilings, and fail closed without overflow", async () => {
  assert.throws(() => validateQuotas({ dailyRequestBudget: QUOTA_CEILINGS.dailyRequestBudget + 1 }));
  assert.throws(() => validateQuotas({ autoscale: true }));
  assert.throws(() => validateQuotas({ registrationsPerHour: 0 }));
  const r = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-state-")), undefined, { ...DEFAULT_QUOTAS, registrationsPerHour: 1 });
  try {
    const register = () =>
      fetch(`${r.origin}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client.example/cb"] }) });
    assert.equal((await register()).status, 201);
    const limited = await register();
    assert.equal(limited.status, 429);
    assert.ok(Number(limited.headers.get("retry-after")) >= 1);
    assert.ok((await limited.text()).includes("REMOTE_RATE_LIMITED"));
  } finally {
    await r.close();
  }
  const budget = await startRelay(mkdtempSync(join(tmpdir(), "orcel-relay-state-")), undefined, { ...DEFAULT_QUOTAS, dailyRequestBudget: 2 });
  try {
    const register = () =>
      fetch(`${budget.origin}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["https://client.example/cb"] }) });
    assert.equal((await register()).status, 201);
    assert.equal((await register()).status, 201);
    assert.equal((await register()).status, 429, "the daily budget fails closed instead of overflowing");
  } finally {
    await budget.close();
  }
});

test("self-host configuration is strict", () => {
  const ok = parseRelayConfig(JSON.stringify({ publicOrigin: "https://relay.example.com", stateDir: "/var/lib/orcel-relay" }));
  assert.equal(ok.listenHost, "127.0.0.1");
  assert.equal(ok.listenPort, 8787);
  assert.deepEqual(ok.quotas, DEFAULT_QUOTAS);
  for (const bad of [
    { publicOrigin: "http://relay.example.com", stateDir: "/s" },
    { publicOrigin: "https://relay.example.com/path", stateDir: "/s" },
    { publicOrigin: "https://relay.example.com" },
    { publicOrigin: "https://relay.example.com", stateDir: "/s", billing: "auto" },
    { publicOrigin: "https://relay.example.com", stateDir: "/s", listenHost: "example.com" },
    { publicOrigin: "https://relay.example.com", stateDir: "/s", allowedOrigins: ["*"] }
  ]) {
    assert.throws(() => parseRelayConfig(JSON.stringify(bad)), JSON.stringify(bad));
  }
  // SG-000067 domain-verification token: optional, URL-safe, bounded.
  assert.equal(ok.openaiAppsChallenge, null);
  const withChallenge = parseRelayConfig(
    JSON.stringify({ publicOrigin: "https://relay.example.com", stateDir: "/s", openaiAppsChallenge: "abcDEF123._~-token" })
  );
  assert.equal(withChallenge.openaiAppsChallenge, "abcDEF123._~-token");
  for (const challenge of ["short", "has space token", "<script>alert(1)</script>", "x".repeat(513), 12345678, "line\nbreak-token"]) {
    assert.throws(
      () => parseRelayConfig(JSON.stringify({ publicOrigin: "https://relay.example.com", stateDir: "/s", openaiAppsChallenge: challenge })),
      String(challenge)
    );
  }
});

test("SG-000067: the domain-verification path returns only the configured token and grants nothing", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "orcel-relay-challenge-"));
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const token = "openai-domain-token_1234.abc~";
  const relay = createRelayServer({
    publicOrigin: origin,
    issuer: origin,
    allowedOrigins: [],
    store: new FileRelayStore(stateDir),
    openaiAppsChallenge: token
  });
  await new Promise<void>((resolve) => relay.server.listen(port, "127.0.0.1", resolve));
  try {
    const challenge = await fetch(`${origin}/.well-known/openai-apps-challenge`);
    assert.equal(challenge.status, 200);
    assert.equal(challenge.headers.get("content-type"), "text/plain; charset=utf-8");
    assert.equal(challenge.headers.get("cache-control"), "no-store");
    assert.equal(await challenge.text(), token);
    for (const method of ["POST", "PUT", "DELETE"]) {
      const other = await fetch(`${origin}/.well-known/openai-apps-challenge`, { method });
      assert.notEqual(other.status, 200, method);
      await other.text();
    }
    // Knowing the token is not authority: the MCP edge still requires OAuth.
    const unauthenticated = await fetch(`${origin}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })
    });
    assert.equal(unauthenticated.status, 401);
    await unauthenticated.text();
    const metadata = (await (await fetch(`${origin}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    assert.equal(metadata.client_id_metadata_document_supported, false);
    assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
    assert.equal(metadata.authorization_response_iss_parameter_supported, true);
  } finally {
    relay.server.closeAllConnections();
    await new Promise<void>((resolve) => relay.server.close(() => resolve()));
  }
  const unconfiguredPort = await freePort();
  const unconfiguredOrigin = `http://127.0.0.1:${unconfiguredPort}`;
  const unconfigured = createRelayServer({
    publicOrigin: unconfiguredOrigin,
    issuer: unconfiguredOrigin,
    allowedOrigins: [],
    store: new FileRelayStore(mkdtempSync(join(tmpdir(), "orcel-relay-challenge-"))),
    openaiAppsChallenge: null
  });
  await new Promise<void>((resolve) => unconfigured.server.listen(unconfiguredPort, "127.0.0.1", resolve));
  try {
    const missing = await fetch(`${unconfiguredOrigin}/.well-known/openai-apps-challenge`);
    assert.equal(missing.status, 404);
    await missing.text();
  } finally {
    unconfigured.server.closeAllConnections();
    await new Promise<void>((resolve) => unconfigured.server.close(() => resolve()));
  }
});

test("relay backup restores device identities, client registrations, and revocations into a clean instance", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "orcel-relay-backup-"));
  const first = await startRelay(stateDir);
  const kept = await link(first);
  if ("denied" in kept) {
    throw new Error("unexpected denial");
  }
  const revoked = await link(first);
  if ("denied" in revoked) {
    throw new Error("unexpected denial");
  }
  const keptId = devicePair(kept.devicePaths.key).deviceId;
  const revokedId = devicePair(revoked.devicePaths.key).deviceId;
  first.store.revokeDevice(revokedId);
  const port = first.port;
  await first.close();
  // Canonical backup: copy the single state file while the relay is stopped.
  const backupDir = mkdtempSync(join(tmpdir(), "orcel-relay-restore-"));
  writeFileSync(join(backupDir, STATE_FILE), readFileSync(join(stateDir, STATE_FILE)));
  // The restore reuses the same origin so token audience still matches.
  const second = await startRelay(backupDir, port);
  try {
    assert.equal(second.store.device(keptId)?.revoked, false);
    assert.equal(second.store.device(revokedId)?.revoked, true);
    assert.ok(second.store.clients().size >= 2);
    assert.deepEqual(second.store.verificationKeys(), first.store.verificationKeys());
    // The revoked device stays revoked after the restore: its family was
    // deleted with the revocation, so its tokens no longer verify.
    // A pooled keep-alive socket to the stopped server is reset once.
    let denied: Response;
    try {
      denied = await mcp(second, revoked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    } catch {
      denied = await mcp(second, revoked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    }
    assert.equal(denied.status, 401);
    await denied.text();
    // The surviving device still authenticates (offline, so nothing dispatches).
    const offline = await mcp(second, kept.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.equal(offline.status, 503);
    assert.ok((await offline.text()).includes("DEVICE_OFFLINE"));
  } finally {
    await second.close();
  }
});

test("a tampered backup fails closed and a fresh state mints a new signing key", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "orcel-relay-tamper-"));
  const first = await startRelay(stateDir);
  const linked = await link(first);
  if ("denied" in linked) {
    throw new Error("unexpected denial");
  }
  const before = first.store.verificationKeys();
  const port = first.port;
  await first.close();
  const bytes = readFileSync(join(stateDir, STATE_FILE), "utf8");
  const tamperedDir = mkdtempSync(join(tmpdir(), "orcel-relay-tampered-"));
  writeFileSync(join(tamperedDir, STATE_FILE), bytes.replace('"revoked":false', '"revoked":true'));
  assert.throws(() => new FileRelayStore(tamperedDir), RelayStateError);
  // Signing-key compromise response: a fresh state mints a new key and never
  // trusts tokens from the compromised state (same origin, unknown key).
  const freshDir = mkdtempSync(join(tmpdir(), "orcel-relay-fresh-"));
  const fresh = await startRelay(freshDir, port);
  try {
    assert.notDeepEqual(fresh.store.verificationKeys(), before);
    // A pooled keep-alive socket to the stopped server is reset once.
    let refused: Response;
    try {
      refused = await mcp(fresh, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    } catch {
      refused = await mcp(fresh, linked.accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    }
    assert.equal(refused.status, 401);
    await refused.text();
  } finally {
    await fresh.close();
  }
});
