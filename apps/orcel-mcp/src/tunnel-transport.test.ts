/**
 * #395: the ChatGPT Secure MCP Tunnel launches this app through the
 * lifecycle tunnel host, which sets `ORCEL_MCP_TRANSPORT=tunnel` and the tunnel's
 * remote route. These tests drive the exact server factory the stdio
 * transport serves, from that launch environment.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { JSONRPCMessage, Transport } from "@modelcontextprotocol/server";
import { createMcpFrameDispatcher, type ConnectionBinding } from "./device_uplink.js";
import { KernelClient, type KernelRequest, type RemoteDispatchContext } from "./kernel.js";
import { CANONICAL_TOOL_NAMES } from "./server.js";
import { REMOTE_TOOL_NAMES, profileTools } from "./tool_contract.js";
import { stdioServerFactory, stdioSessionConfig, type StdioSessionConfig } from "./transports/stdio.js";
import { parseTunnelRoute } from "./tunnel_route.js";

// What `orcel_lifecycle::tunnel_route::route` derives for
// tunnel_0123456789abcdefghijklmnopqrstuv (pinned there and in orceld's
// fix395 test too).
const ROUTE = {
  principal: "rp-182110eb5d85d5ccd3f34df5dba41e1a",
  remoteConnectionId: "rc-8d11a8282860ff1df26aeee0949a7bf9",
  deviceId: "dev-0872269746857073deab118978d116a0",
  deviceEpoch: 1,
  providerKind: "openai",
  clientProfileId: "chatgpt-secure-mcp-tunnel",
  clientProfileRevision: 1,
  toolSurfaceProfile: "core",
  scopeCeiling: ["orcel.read", "orcel.write", "orcel.execute"]
};

/** The launch environment `orcel-mcp-host` builds, plus hostile leftovers. */
function tunnelEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ORCEL_DEFAULT_WORKSPACE: "default",
    ORCEL_MCP_TRANSPORT: "tunnel",
    ORCEL_TUNNEL_ROUTE_JSON: JSON.stringify(ROUTE),
    ...extra
  };
}

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

const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "tunnel-test", version: "1" } };

/**
 * A real `KernelClient` whose `orceld` child is replaced by an in-memory
 * stdin: `call` runs unchanged, so the recorded lines are exactly what the
 * tunnel host writes to `orceld`. Every request is answered as `orceld`
 * answers a remote request without a lease.
 */
function recordingKernel(config: StdioSessionConfig, wire: KernelRequest[]): KernelClient {
  const kernel = Object.create(KernelClient.prototype) as KernelClient;
  const respond = (line: string) => (kernel as unknown as { handleLine(line: string): void }).handleLine(line);
  Object.assign(kernel, {
    sessionId: "tunnel-test",
    pending: new Map(),
    remote: config.remote,
    profile: config.profile,
    child: {
      stdin: {
        write(payload: string, _encoding: string, callback: (error?: Error) => void) {
          const request = JSON.parse(payload) as KernelRequest;
          wire.push(request);
          callback();
          queueMicrotask(() =>
            respond(
              JSON.stringify({
                version: 1,
                request_id: request.request_id,
                ok: false,
                error: { code: "REMOTE_SESSION_INACTIVE", message: "no remote-session lease exists for this connection" }
              })
            )
          );
          return true;
        },
        end() {}
      },
      killed: true,
      kill() {}
    }
  });
  return kernel;
}

async function tunnelSession(env: NodeJS.ProcessEnv = tunnelEnv()) {
  const config = stdioSessionConfig(env);
  const wire: KernelRequest[] = [];
  const server = stdioServerFactory(config, (c) => recordingKernel(c, wire))();
  const transport = new TestTransport();
  await server.connect(transport);
  await transport.request(1, "initialize", INIT);
  transport.notify("notifications/initialized");
  return { config, wire, transport };
}

function toolNames(response: Record<string, unknown>): string[] {
  return ((response.result as { tools: Array<{ name: string }> }).tools ?? []).map((t) => t.name).sort();
}

test("a tunnel-launched host serves exactly the core profile", async () => {
  // A local profile variable left in the environment changes nothing.
  for (const profile of [undefined, "desktop_structured", "browser_structured"]) {
    const { config, transport } = await tunnelSession(tunnelEnv({ ORCEL_TOOL_SURFACE_PROFILE: profile }));
    assert.equal(config.context.transportKind, "tunnel");
    assert.equal(config.context.toolSurfaceProfile, "core");
    const names = toolNames(await transport.request(2, "tools/list"));
    assert.deepEqual(names, [...profileTools("core")].sort());
    assert.deepEqual(names, [...REMOTE_TOOL_NAMES].sort());
    for (const local of ["web_fetch", "clipboard_read", "clipboard_write"]) {
      assert.ok(CANONICAL_TOOL_NAMES.includes(local), local);
      assert.ok(!names.includes(local), `${local} is not served through the tunnel`);
    }
  }
});

test("a desktop tool called through the tunnel is refused with the relay's error", async () => {
  const { wire, transport } = await tunnelSession();
  const relayRemotes: RemoteDispatchContext[] = [];
  const relay = createMcpFrameDispatcher({
    defaultWorkspace: "default",
    kernelFactory: (remote) => {
      relayRemotes.push(remote);
      return recordingKernel({ ...stdioSessionConfig(tunnelEnv()), remote }, []);
    }
  });
  const route = parseTunnelRoute(JSON.stringify(ROUTE));
  const binding: ConnectionBinding = {
    paired: route.paired,
    connectionId: "conn-0001",
    scopes: route.paired.scopeCeiling,
    remote: { ...stdioSessionConfig(tunnelEnv()).remote!, connectionId: "conn-0001" }
  };
  await relay.dispatch(binding, JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: INIT }));
  await relay.dispatch(binding, JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
  for (const [id, name] of [
    [10, "clipboard_read"],
    [11, "clipboard_write"],
    [12, "web_fetch"]
  ] as const) {
    const params = { name, arguments: { text: "x", url: "https://example.com/" } };
    const viaTunnel = await transport.request(id, "tools/call", params);
    const viaRelay = JSON.parse(
      (await relay.dispatch(binding, JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params }))) ?? "null"
    ) as Record<string, unknown>;
    assert.deepEqual(viaTunnel, viaRelay, name);
    const text = JSON.stringify(viaTunnel);
    assert.ok(text.includes(name) && /not found|unknown tool/i.test(text), text);
  }
  assert.deepEqual(wire, [], "a refused desktop tool never reaches orceld");
  relay.closeConnection("conn-0001");
});

test("requests through the tunnel carry the remote context into orceld", async () => {
  const { config, wire, transport } = await tunnelSession();
  const response = await transport.request(3, "tools/call", { name: "fs_read", arguments: { path: "README.md" } });
  assert.ok(JSON.stringify(response).includes("REMOTE_SESSION_INACTIVE"), JSON.stringify(response));
  assert.equal(wire.length, 1);
  const request = wire[0] as KernelRequest;
  assert.equal(request.capability, "fs.read");
  assert.equal(request.profile, undefined, "no local profile is stamped on a tunnel request");
  assert.deepEqual(request.remote, config.remote);
  const remote = request.remote as RemoteDispatchContext;
  assert.equal(remote.principal, ROUTE.principal);
  assert.equal(remote.remoteConnectionId, ROUTE.remoteConnectionId);
  assert.equal(remote.deviceId, ROUTE.deviceId);
  assert.equal(remote.deviceEpoch, 1);
  assert.equal(remote.providerKind, "openai");
  assert.equal(remote.toolSurfaceProfile, "core");
  assert.deepEqual(remote.scopes, ROUTE.scopeCeiling);
  assert.match(remote.connectionId, /^tunnel-[0-9a-f]{32}$/);
});

test("local stdio clients keep their configured profile and no remote context", () => {
  const plain = stdioSessionConfig({});
  assert.equal(plain.context.transportKind, "stdio");
  assert.equal(plain.context.toolSurfaceProfile, "desktop_structured");
  assert.equal(plain.remote, null);
  assert.equal(plain.profile, "desktop_structured");
  const browser = stdioSessionConfig({ ORCEL_TOOL_SURFACE_PROFILE: "browser_structured" });
  assert.equal(browser.context.toolSurfaceProfile, "browser_structured");
  assert.equal(browser.remote, null);
});

test("the tunnel transport fails closed on a missing or malformed route or an unknown transport", () => {
  assert.throws(() => stdioSessionConfig({ ORCEL_MCP_TRANSPORT: "tunnel" }), /TRANSPORT_UNAVAILABLE/);
  assert.throws(() => stdioSessionConfig({ ORCEL_MCP_TRANSPORT: "stdio" }), /TRANSPORT_UNAVAILABLE/);
  assert.throws(() => stdioSessionConfig({ ORCEL_MCP_TRANSPORT: "" }), /TRANSPORT_UNAVAILABLE/);
  for (const bad of [
    "not json",
    "[]",
    JSON.stringify({ ...ROUTE, toolSurfaceProfile: "desktop_structured" }),
    JSON.stringify({ ...ROUTE, providerKind: "bad kind" }),
    JSON.stringify({ ...ROUTE, deviceEpoch: 0 }),
    JSON.stringify({ ...ROUTE, deviceId: "dev-x" }),
    JSON.stringify({ ...ROUTE, extra: true }),
    JSON.stringify({ ...ROUTE, scopeCeiling: ["orcel.admin"] })
  ]) {
    assert.throws(() => stdioSessionConfig(tunnelEnv({ ORCEL_TUNNEL_ROUTE_JSON: bad })), /TRANSPORT_UNAVAILABLE/, bad);
  }
});
