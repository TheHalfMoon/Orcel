/**
 * Regression tests for the MCP TypeScript SDK advisories fixed by
 * @modelcontextprotocol/server 2.3.x:
 * - GHSA-46jr-4wx8-v453: unbounded tool-input validation;
 * - GHSA-jm63-cq47-j5jp: responses delivered across HTTP clients;
 * - GHSA-rvq5-wwqv-78pq: SDK bearer auth without an audience check.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { JSONRPCMessage, Transport } from "@modelcontextprotocol/server";
import { KernelClient, type KernelResponse } from "./kernel.js";
import { MAX_TOOL_INPUT_ELEMENTS, buildOrcelServer, defaultTransportContext } from "./server.js";
import { startLoopbackTransport } from "./transports/loopback_http.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");
const TOKEN = "0123456789abcdef0123456789abcdef";
const INIT = { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "advisory-test", version: "1" } };

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

/** A kernel that records each call and answers it as a denial. */
function recordingKernel(calls: string[]): KernelClient {
  const kernel = Object.create(KernelClient.prototype) as KernelClient;
  Object.assign(kernel, {
    sessionId: "advisory-test",
    pending: new Map(),
    async call(input: { capability: string; operation: string }): Promise<KernelResponse> {
      calls.push(`${input.capability}.${input.operation}`);
      return { version: 1, request_id: "r", ok: false, error: { code: "POLICY_DENIED", message: "denied" } };
    },
    close() {}
  });
  return kernel;
}

async function session(calls: string[]): Promise<TestTransport> {
  const server = buildOrcelServer(recordingKernel(calls), "default", defaultTransportContext());
  const transport = new TestTransport();
  await server.connect(transport);
  await transport.request(1, "initialize", INIT);
  transport.notify("notifications/initialized");
  return transport;
}

const HEAD = "0".repeat(40);

/** The SDK's element-limit refusal, not a later schema failure. */
function refusedForSize(response: Record<string, unknown>): boolean {
  const result = response.result as { isError?: boolean } | undefined;
  return result?.isError === true && JSON.stringify(response).includes(`more than the maximum of ${MAX_TOOL_INPUT_ELEMENTS} elements`);
}

test("GHSA-46jr: an oversized tool input is refused before it reaches orceld", async () => {
  const calls: string[] = [];
  const transport = await session(calls);

  const paths = Array.from({ length: 200_000 }, (_, i) => `f${i}`);
  const hugeArray = await transport.request(2, "tools/call", { name: "git_stage", arguments: { expected_head: HEAD, paths } });
  assert.ok(refusedForSize(hugeArray), JSON.stringify(hugeArray).slice(0, 400));

  const keys = Object.fromEntries(Array.from({ length: MAX_TOOL_INPUT_ELEMENTS + 1 }, (_, i) => [`k${i}`, i]));
  const hugeObject = await transport.request(3, "tools/call", { name: "fs_read", arguments: { path: "README.md", ...keys } });
  assert.ok(refusedForSize(hugeObject), JSON.stringify(hugeObject).slice(0, 400));
  assert.deepEqual(calls, [], "an over-limit input never reaches the kernel");

  // The largest legitimate input still dispatches.
  const legitimate = Array.from({ length: 128 }, (_, i) => `f${i}`);
  const accepted = await transport.request(4, "tools/call", {
    name: "git_stage",
    arguments: { expected_head: HEAD, paths: legitimate }
  });
  assert.ok(!refusedForSize(accepted), JSON.stringify(accepted).slice(0, 400));
  assert.equal(calls.length, 1, "the largest legitimate git_stage input reaches the kernel");
});

async function post(url: string, body: unknown, headers: Record<string, string> = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${TOKEN}`,
      ...headers
    },
    body: JSON.stringify(body)
  });
  return { status: response.status, headers: response.headers, text: await response.text() };
}

test("GHSA-jm63: loopback clients get their own session and their own responses", async () => {
  const handle = await startLoopbackTransport({ token: TOKEN });
  try {
    // Both clients number requests from 0, the collision the advisory describes.
    const opened = await Promise.all(
      ["client-a", "client-b"].map((name) =>
        post(handle.url, {
          jsonrpc: "2.0",
          id: 0,
          method: "initialize",
          params: { ...INIT, protocolVersion: "2025-11-25", clientInfo: { name, version: "1" } }
        })
      )
    );
    const ids = opened.map((response) => {
      assert.equal(response.status, 200);
      const id = response.headers.get("mcp-session-id");
      assert.ok(id);
      return id;
    });
    assert.notEqual(ids[0], ids[1], "each client gets its own session");

    for (const id of ids) {
      const initialized = await post(handle.url, { jsonrpc: "2.0", method: "notifications/initialized" }, { "mcp-session-id": id });
      assert.equal(initialized.status, 202);
    }
    const listed = await Promise.all(
      ids.map((id) => post(handle.url, { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, { "mcp-session-id": id }))
    );
    for (const response of listed) {
      assert.equal(response.status, 200);
      const payload = JSON.parse(response.text) as { id: number; result: { tools: unknown[] } };
      assert.equal(payload.id, 1);
      assert.ok(payload.result.tools.length > 0);
    }

    // Closing one session leaves the other one serving.
    const closed = await fetch(handle.url, {
      method: "DELETE",
      headers: { authorization: `Bearer ${TOKEN}`, "mcp-session-id": ids[0] as string }
    });
    assert.equal(closed.status, 200);
    const stale = await post(handle.url, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, { "mcp-session-id": ids[0] as string });
    assert.equal(stale.status, 404);
    const alive = await post(handle.url, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, { "mcp-session-id": ids[1] as string });
    assert.equal(alive.status, 200);
  } finally {
    await handle.close();
  }
});

function sources(dir: string): string[] {
  return readdirSync(join(repo, dir), { recursive: true, encoding: "utf8" })
    .filter((name) => name.endsWith(".ts") && !name.endsWith(".test.ts"))
    .map((name) => join(repo, dir, name));
}

test("GHSA-rvq5: bearer tokens are verified only by Orcel's audience-checking verifier", () => {
  // The SDK's bearer middleware is not used anywhere, so the audience check
  // (`wrong_audience` in oauth-authorization.test.ts) stays the only path.
  for (const file of [...sources("apps/orcel-mcp/src"), ...sources("apps/orcel-relay/src")]) {
    const text = readFileSync(file, "utf8");
    assert.ok(!/\b(requireBearerAuth|verifyBearerToken)\b/.test(text), `${file} uses the SDK bearer middleware`);
  }
});
