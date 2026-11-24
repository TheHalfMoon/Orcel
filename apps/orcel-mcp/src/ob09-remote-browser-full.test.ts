/**
 * SG-000135 OB-09 part 2: the remote `browser_full` profile through the
 * ChatGPT Secure MCP Tunnel only (engineering-chosen 2026-11-22; the relay
 * serves `core` only).
 *
 * - The remote tool list is exactly the part-1 remote-safe broker tools,
 *   each with its `orcel.read` or `orcel.execute` scope, and agrees with
 *   orceld's gate and scope table.
 * - A tunnel serves one profile; `core` is unchanged.
 * - Remote requests carry the remote context with profile `browser_full`.
 * - A remote caller's `client_session_id` is the server-assigned MCP session
 *   id (a server-side randomUUID per remote kernel), never caller-chosen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONRPCMessage, Transport } from "@modelcontextprotocol/server";
import { createMcpFrameDispatcher, isPairedConnection, type ConnectionBinding } from "./device_uplink.js";
import { KernelClient, type KernelRequest, type RemoteDispatchContext } from "./kernel.js";
import {
  OAUTH_BROWSER_FULL_SCOPE_MATRIX,
  OAUTH_PROFILE_TOOL_CEILINGS,
  OAUTH_SCOPE_TOOL_MATRIX,
  authorizeToolByScopes
} from "./oauth_authorization.js";
import { allowedToolsFor } from "./server.js";
import {
  BROWSER_FULL_CONTRACT,
  REMOTE_BROWSER_FULL_TOOLS,
  REMOTE_TOOL_NAMES,
  TOOL_CONTRACT,
  isRemoteProfileAllowed,
  remoteProfileTools,
  securitySchemesFor
} from "./tool_contract.js";
import { stdioServerFactory, stdioSessionConfig, type StdioSessionConfig } from "./transports/stdio.js";
import { parseTunnelRoute } from "./tunnel_route.js";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** A browser_full tunnel route in the shape `orcel-mcp-host` passes down. */
const BROWSER_ROUTE = {
  principal: "rp-182110eb5d85d5ccd3f34df5dba41e1a",
  remoteConnectionId: "rc-" + "4".repeat(32),
  deviceId: "dev-0872269746857073deab118978d116a0",
  deviceEpoch: 1,
  providerKind: "openai",
  clientProfileId: "chatgpt-secure-mcp-tunnel-browser-full",
  clientProfileRevision: 1,
  toolSurfaceProfile: "browser_full",
  scopeCeiling: ["orcel.read", "orcel.execute"]
};

const READS = ["browser_snapshot", "browser_verify", "browser_extract", "browser_screenshot", "browser_task_status"];
const ACTIONS = ["browser_session_create", "browser_open", "browser_click", "browser_fill", "browser_select", "browser_tabs", "browser_close"];

function rustBody(path: string, start: string, end: string): string {
  const text = readFileSync(join(repo, path), "utf8");
  const at = text.indexOf(start);
  assert.ok(at >= 0, `${start} in ${path}`);
  return text.slice(at, text.indexOf(end, at));
}

test("ob09: the remote browser_full tools are the remote-safe broker tools with their scopes, as orceld maps them", () => {
  assert.deepEqual([...REMOTE_BROWSER_FULL_TOOLS].sort(), [...READS, ...ACTIONS].sort());
  for (const tool of READS) {
    assert.deepEqual(BROWSER_FULL_CONTRACT[tool]?.remote, ["orcel.read"], tool);
    assert.deepEqual(OAUTH_BROWSER_FULL_SCOPE_MATRIX[tool], ["orcel.read"], tool);
  }
  for (const tool of ACTIONS) {
    assert.deepEqual(BROWSER_FULL_CONTRACT[tool]?.remote, ["orcel.execute"], tool);
    assert.deepEqual(OAUTH_BROWSER_FULL_SCOPE_MATRIX[tool], ["orcel.execute"], tool);
  }
  for (const tool of ["browser_profiles", "browser_profile_create", "browser_profile_delete"]) {
    assert.equal(BROWSER_FULL_CONTRACT[tool]?.remote, "local_only", tool);
    assert.equal(REMOTE_BROWSER_FULL_TOOLS.includes(tool), false, tool);
  }
  // orceld's gate (REMOTE_BROWSER_FULL_SHAPES) lists the same shapes...
  const gate = rustBody("crates/orceld/src/profile_gate.rs", "pub const REMOTE_BROWSER_FULL_SHAPES", "];");
  const gateShapes = [...gate.matchAll(/\("browser\.session", "([a-z_]+)"\)/g)].map((m) => m[1] ?? "");
  assert.deepEqual(
    gateShapes.sort(),
    REMOTE_BROWSER_FULL_TOOLS.map((tool) => BROWSER_FULL_CONTRACT[tool]?.operation ?? "").sort()
  );
  // ...and its scope table gives each the contract's scope.
  const scopes = rustBody("crates/orcel-policy/src/remote_session.rs", "pub fn required_browser_full_scopes", "_ => return None");
  const read = /"([a-z_|" ]+)" => READ/.exec(scopes.replace(/\s+/g, " "))?.[0] ?? "";
  const execute = /"([a-z_|" ]+)" => EXECUTE/.exec(scopes.replace(/\s+/g, " "))?.[0] ?? "";
  for (const tool of READS) {
    assert.ok(read.includes(`"${BROWSER_FULL_CONTRACT[tool]?.operation}"`), tool);
  }
  for (const tool of ACTIONS) {
    assert.ok(execute.includes(`"${BROWSER_FULL_CONTRACT[tool]?.operation}"`), tool);
  }
  // Every remote browser tool declares its exact OAuth scheme under browser_full.
  for (const tool of REMOTE_BROWSER_FULL_TOOLS) {
    assert.deepEqual(securitySchemesFor(tool, "browser_full"), [{ type: "oauth2", scopes: BROWSER_FULL_CONTRACT[tool]?.remote }]);
  }
});

test("ob09: core is unchanged and the two remote profiles never overlap", () => {
  assert.deepEqual([...remoteProfileTools("core")].sort(), [...REMOTE_TOOL_NAMES].sort());
  assert.deepEqual(OAUTH_PROFILE_TOOL_CEILINGS.core, Object.keys(OAUTH_SCOPE_TOOL_MATRIX));
  for (const [tool, scopes] of Object.entries(OAUTH_SCOPE_TOOL_MATRIX)) {
    assert.deepEqual(scopes, TOOL_CONTRACT[tool]?.remote, tool);
  }
  const all = ["orcel.read", "orcel.write", "orcel.execute"];
  for (const tool of REMOTE_TOOL_NAMES) {
    assert.equal(remoteProfileTools("browser_full").has(tool), false, tool);
    assert.equal(authorizeToolByScopes(tool, "browser_full", all, all).ok, false, tool);
  }
  for (const tool of REMOTE_BROWSER_FULL_TOOLS) {
    assert.equal(remoteProfileTools("core").has(tool) && TOOL_CONTRACT[tool]?.remote !== "local_only", false, tool);
    assert.equal(authorizeToolByScopes(tool, "core", all, all).ok, false, tool);
  }
  // Scope checks per tool: a read needs orcel.read, an action orcel.execute.
  assert.equal(authorizeToolByScopes("browser_snapshot", "browser_full", ["orcel.read"], ["orcel.read"]).ok, true);
  assert.equal(authorizeToolByScopes("browser_click", "browser_full", ["orcel.read"], ["orcel.read", "orcel.execute"]).ok, false);
  assert.equal(authorizeToolByScopes("browser_click", "browser_full", ["orcel.execute"], ["orcel.execute"]).ok, true);
  assert.equal(authorizeToolByScopes("browser_profile_delete", "browser_full", all, all).ok, false);
  // ChatGPT's tunnel only; unknown providers and profiles deny.
  assert.equal(isRemoteProfileAllowed("openai", "browser_full"), true);
  for (const provider of ["generic", "anthropic", "mistral", "codex", "unknown", "__proto__"]) {
    assert.equal(isRemoteProfileAllowed(provider, "browser_full"), false, provider);
  }
  for (const profile of ["browser_structured", "desktop_structured", "", "Browser_Full"]) {
    assert.equal(isRemoteProfileAllowed("openai", profile), false, profile);
    assert.throws(() => allowedToolsFor({ transportKind: "tunnel", providerKind: "openai", toolSurfaceProfile: profile as "core" }));
  }
  // A relay paired connection is core only; a tunnel route names one known
  // profile.
  const paired = { ...BROWSER_ROUTE } as Record<string, unknown>;
  delete paired.deviceId;
  delete paired.deviceEpoch;
  assert.equal(isPairedConnection({ ...paired, toolSurfaceProfile: "core" }), true);
  assert.equal(isPairedConnection(paired), false, "a relay connection never holds browser_full");
  assert.equal(parseTunnelRoute(JSON.stringify(BROWSER_ROUTE)).paired.toolSurfaceProfile, "browser_full");
  for (const profile of ["browser_structured", "core browser_full", ["core", "browser_full"], null]) {
    assert.throws(() => parseTunnelRoute(JSON.stringify({ ...BROWSER_ROUTE, toolSurfaceProfile: profile })), /malformed/, String(profile));
  }
});

/** In-memory MCP transport: one response per request id. */
class TestTransport implements Transport {
  onclose?: (() => void) | undefined;
  onerror?: ((error: Error) => void) | undefined;
  onmessage?: ((message: JSONRPCMessage) => void) | undefined;
  private readonly pending = new Map<string, (message: Record<string, unknown>) => void>();
  async start(): Promise<void> {}
  async send(message: JSONRPCMessage): Promise<void> {
    const record = message as unknown as Record<string, unknown>;
    if (!("id" in record) || "method" in record) {
      return;
    }
    const resolve = this.pending.get(JSON.stringify(record.id));
    if (resolve !== undefined) {
      this.pending.delete(JSON.stringify(record.id));
      resolve(record);
    }
  }
  async close(): Promise<void> {
    this.onclose?.();
  }
  request(id: number, method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    return new Promise((resolve) => {
      this.pending.set(JSON.stringify(id), resolve);
      this.onmessage?.({ jsonrpc: "2.0", id, method, params } as JSONRPCMessage);
    });
  }
  notify(method: string): void {
    this.onmessage?.({ jsonrpc: "2.0", method } as JSONRPCMessage);
  }
}

const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "ob09-test", version: "1" } };

/** A fake orceld that answers each request with what it received. */
function echoDaemon(dir: string): string {
  const daemon = join(dir, "echo-orceld.mjs");
  writeFileSync(
    daemon,
    [
      'import { createInterface } from "node:readline";',
      "createInterface({ input: process.stdin }).on('line', (line) => {",
      "  const request = JSON.parse(line);",
      "  process.stdout.write(JSON.stringify({ version: 1, ok: false, request_id: request.request_id, error: { code: 'REMOTE_SESSION_INACTIVE', message: JSON.stringify({ session: request.client_session_id, remote: request.remote, profile: request.profile ?? null, capability: request.capability, operation: request.operation }) } }) + '\\n');",
      "});"
    ].join("\n")
  );
  return daemon;
}

/** What the echo daemon says it received, from a tool result. */
function seen(response: Record<string, unknown>): Record<string, unknown> {
  try {
    const result = response.result as { content?: Array<{ text?: string }> } | undefined;
    const body = JSON.parse(result?.content?.[0]?.text ?? "{}") as { error?: { message?: string } };
    return JSON.parse(body.error?.message ?? "{}") as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function tunnelSession(config: StdioSessionConfig, daemon: string) {
  const kernels: KernelClient[] = [];
  const server = stdioServerFactory(config, (c) => {
    const kernel = new KernelClient(process.execPath, c.remote, c.profile, [daemon]);
    kernels.push(kernel);
    return kernel;
  })();
  const transport = new TestTransport();
  await server.connect(transport);
  await transport.request(1, "initialize", INIT);
  transport.notify("notifications/initialized");
  return { transport, kernels, close: () => void server.close() };
}

test("ob09: a browser_full tunnel serves only the remote browser tools and every request carries the remote context, profile browser_full, and the server's own session id", async () => {
  const dir = mkdtempSync(join(tmpdir(), "orcel-ob09-"));
  const daemon = echoDaemon(dir);
  const env = {
    ORCEL_DEFAULT_WORKSPACE: "default",
    ORCEL_MCP_TRANSPORT: "tunnel",
    ORCEL_TUNNEL_ROUTE_JSON: JSON.stringify(BROWSER_ROUTE),
    // A local profile left in the environment changes nothing.
    ORCEL_TOOL_SURFACE_PROFILE: "desktop_structured"
  };
  const config = stdioSessionConfig(env);
  assert.equal(config.context.transportKind, "tunnel");
  assert.equal(config.context.toolSurfaceProfile, "browser_full");
  assert.equal(config.remote?.toolSurfaceProfile, "browser_full");
  const first = await tunnelSession(config, daemon);
  const second = await tunnelSession(config, daemon);
  try {
    const listed = (await first.transport.request(2, "tools/list")) as { result?: { tools?: Array<{ name: string }> } };
    const names = (listed.result?.tools ?? []).map((tool) => tool.name).sort();
    assert.deepEqual(names, [...REMOTE_BROWSER_FULL_TOOLS].sort());
    // A core tool is not served through a browser_full tunnel.
    const core = await first.transport.request(3, "tools/call", { name: "fs_read", arguments: { path: "README.md" } });
    assert.match(JSON.stringify(core), /not found|unknown tool/i);
    // A caller cannot name a session id: the tool refuses the field before
    // anything reaches orceld.
    const named = await first.transport.request(6, "tools/call", {
      name: "browser_open",
      arguments: { session_id: "bs-0123456789abcdef-1-0001020304050607", url: "https://example.com/", client_session_id: "attacker-chosen" }
    });
    assert.match(JSON.stringify(named), /Unrecognized key: \\"client_session_id\\"/);
    // A broker tool reaches orceld with the remote context and the server's
    // own session id.
    const opened = await first.transport.request(4, "tools/call", {
      name: "browser_open",
      arguments: { session_id: "bs-0123456789abcdef-1-0001020304050607", url: "https://example.com/" }
    });
    const request = seen(opened);
    assert.equal(request.capability, "browser.session", JSON.stringify(opened));
    assert.equal(request.operation, "open");
    assert.equal(request.profile, null, "no local profile is stamped on a remote request");
    const remote = request.remote as RemoteDispatchContext;
    assert.equal(remote.toolSurfaceProfile, "browser_full");
    assert.equal(remote.remoteConnectionId, BROWSER_ROUTE.remoteConnectionId);
    assert.deepEqual(remote.scopes, BROWSER_ROUTE.scopeCeiling);
    const kernel = first.kernels[0];
    assert.ok(kernel !== undefined);
    assert.equal(request.session, kernel.sessionId);
    assert.notEqual(request.session, "attacker-chosen");
    assert.match(String(request.session), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    // Each remote MCP session gets its own server-side id.
    const other = seen(await second.transport.request(5, "tools/call", { name: "browser_task_status", arguments: { session_id: "bs-0123456789abcdef-1-0001020304050607" } }));
    assert.notEqual(other.session, request.session);
  } finally {
    first.close();
    second.close();
    for (const kernel of [...first.kernels, ...second.kernels]) kernel.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ob09: the relay never serves browser_full: its server, its uplink check and its pairing record stay core", async () => {
  // The relay transport refuses the profile for every provider...
  for (const provider of ["openai", "generic", "anthropic", "codex", "mistral"]) {
    assert.throws(
      () => allowedToolsFor({ transportKind: "relay", providerKind: provider, toolSurfaceProfile: "browser_full" }),
      /TOOL_SURFACE_DENIED/,
      provider
    );
    // ...and a relay core route never serves a broker tool.
    const served = allowedToolsFor({ transportKind: "relay", providerKind: provider, toolSurfaceProfile: "core" });
    for (const tool of REMOTE_BROWSER_FULL_TOOLS) {
      assert.equal(served.has(tool) && TOOL_CONTRACT[tool]?.remote !== "local_only", false, `${tool} ${provider}`);
    }
  }
  // The device uplink, the enrollment and the dispatcher name only core.
  for (const file of ["device_uplink.ts", "remote_enrollment.ts"]) {
    const text = readFileSync(join(repo, "apps", "orcel-mcp", "src", file), "utf8");
    assert.equal(/browser_full/.test(text), false, file);
  }
  // A relay session dispatches with the core server: a browser tool is unknown there.
  const wire: KernelRequest[] = [];
  const route = parseTunnelRoute(JSON.stringify({ ...BROWSER_ROUTE, toolSurfaceProfile: "core", scopeCeiling: ["orcel.read", "orcel.write", "orcel.execute"] }));
  const relay = createMcpFrameDispatcher({
    defaultWorkspace: "default",
    kernelFactory: (remote) =>
      ({
        sessionId: "relay-server-side",
        remote,
        profile: null,
        call: async (input: { capability: string; operation: string }) => {
          wire.push({ capability: input.capability, operation: input.operation } as KernelRequest);
          return { version: 1, request_id: "r", ok: false, error: { code: "REMOTE_SESSION_INACTIVE", message: "no lease" } };
        },
        isolated() {
          return this;
        },
        close: () => {},
        pending: new Map(),
        child: {} as never
      }) as unknown as KernelClient
  });
  const paired = { ...route.paired, toolSurfaceProfile: "core" as const };
  const binding: ConnectionBinding = {
    paired,
    connectionId: "conn-ob09",
    scopes: paired.scopeCeiling,
    remote: {
      principal: paired.principal,
      remoteConnectionId: paired.remoteConnectionId,
      connectionId: "conn-ob09",
      deviceId: route.deviceId,
      deviceEpoch: route.deviceEpoch,
      providerKind: paired.providerKind,
      clientProfileId: paired.clientProfileId,
      clientProfileRevision: paired.clientProfileRevision,
      toolSurfaceProfile: "core",
      scopes: [...paired.scopeCeiling]
    }
  };
  const send = async (message: Record<string, unknown>) =>
    JSON.parse((await relay.dispatch(binding, JSON.stringify(message))) ?? "null") as Record<string, unknown>;
  try {
    await send({ jsonrpc: "2.0", id: 1, method: "initialize", params: INIT });
    await relay.dispatch(binding, JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
    const listed = (await send({ jsonrpc: "2.0", id: 2, method: "tools/list" })) as { result?: { tools?: Array<{ name: string }> } };
    assert.deepEqual((listed.result?.tools ?? []).map((t) => t.name).sort(), [...REMOTE_TOOL_NAMES].sort());
    const refused = await send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "browser_snapshot", arguments: { session_id: "bs-0123456789abcdef-1-0001020304050607" } } });
    assert.match(JSON.stringify(refused), /not found|unknown tool/i);
    assert.deepEqual(wire, [], "no browser shape reaches orceld through the relay");
  } finally {
    relay.closeConnection("conn-ob09");
  }
});

test("ob09: a remote kernel's client_session_id is its own server-side randomUUID and no input changes it", () => {
  const source = readFileSync(join(repo, "apps", "orcel-mcp", "src", "kernel.ts"), "utf8");
  // The one source of the id: a readonly server-side randomUUID per kernel...
  assert.match(source, /readonly sessionId = randomUUID\(\);/);
  // ...which every request uses; no call input names a session.
  assert.match(source, /sessionId: this\.sessionId,/);
  const call = source.slice(source.indexOf("async call(input: {"), source.indexOf("}): Promise<KernelResponse>"));
  assert.equal(/session/i.test(call), false, call);
});
