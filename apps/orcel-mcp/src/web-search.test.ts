import assert from "node:assert/strict";
import test from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_SEARCH_QUERY_CHARS, SEARCH_PROVIDERS, webSearchSchema } from "./web_search.js";
import { TOOL_CONTRACT } from "./tool_contract.js";
import type { KernelClient } from "./kernel.js";
import { buildDaemonEnv } from "./kernel.js";
import { allowedToolsFor, buildOrcelServer, localTransportContext, tunnelTransportContext } from "./server.js";
import { TRANSPORT_ENV, TUNNEL_TRANSPORT } from "./tunnel_route.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");

/**
 * WI-06: exactly the closed search/query shape reaches the kernel, only
 * from web_search.ts, with query, provider and max_results. No origin,
 * key, header or network primitive exists on the MCP surface.
 */
test("wi06 only web_search.ts forwards search/query, with no origin or key", () => {
  const forwarded: string[] = [];
  for (const name of readdirSync(srcDir).filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts") && n !== "tool_contract.ts")) {
    const text = readFileSync(join(srcDir, name), "utf8");
    for (const match of text.matchAll(/capability:\s*["'](search[a-z_.]*)["'],\s*operation:\s*["']([a-z_]+)["']/g)) {
      forwarded.push(`${name}:${match[1] ?? ""}/${match[2] ?? ""}`);
    }
  }
  assert.deepEqual(forwarded, ["web_search.ts:search/query"]);
  const source = readFileSync(join(srcDir, "web_search.ts"), "utf8");
  assert.doesNotMatch(source, /node:net|node:http|node:https|node:tls|node:dgram|fetch\(|new Socket/);
  assert.doesNotMatch(source, /\b(origin|headers|api_?key|token|secret)\s*:/i);
});

test("wi06 the search tool accepts only a bounded query, a known provider and 1..10 results", () => {
  const schema = webSearchSchema("w");
  assert.equal(schema.safeParse({ query: "rust ownership" }).success, true);
  for (const provider of SEARCH_PROVIDERS) {
    assert.equal(schema.safeParse({ query: "q", provider, max_results: 10 }).success, true, provider);
  }
  for (const input of [
    {},
    { query: "" },
    { query: "   " },
    { query: "a".repeat(MAX_SEARCH_QUERY_CHARS + 1) },
    { query: "line\nbreak" },
    { query: "q", provider: "google" },
    { query: "q", provider: "https://evil.example" },
    { query: "q", max_results: 0 },
    { query: "q", max_results: 11 },
    { query: "q", max_results: 2.5 }
  ]) {
    assert.equal(schema.safeParse(input).success, false, JSON.stringify(input));
  }
  // Unknown fields such as an origin or a key are dropped, never forwarded.
  const parsed = schema.parse({ query: "q", origin: "https://evil.example", api_key: "k" });
  assert.deepEqual(Object.keys(parsed).sort(), ["query", "workspace_id"]);
});

test("wi06 web_search is local-only SOFT network egress", () => {
  const entry = TOOL_CONTRACT.web_search;
  assert.ok(entry);
  assert.equal(entry.capability, "search");
  assert.equal(entry.operation, "query");
  assert.equal(entry.approval, "SOFT");
  assert.equal(entry.remote, "local_only");
  assert.equal(entry.effect, "network");
  assert.equal(entry.annotations.openWorldHint, true);
});

type Message = { jsonrpc: "2.0"; id?: number; method?: string; params?: unknown; result?: unknown; error?: unknown };

class MemoryTransport {
  onmessage?: (message: Message) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  private readonly pending = new Map<number, (message: Message) => void>();
  async start(): Promise<void> {}
  async send(message: Message): Promise<void> {
    if (message.id !== undefined && message.method === undefined) {
      this.pending.get(message.id)?.(message);
      this.pending.delete(message.id);
    }
  }
  async close(): Promise<void> {
    this.onclose?.();
  }
  request(id: number, method: string, params: unknown): Promise<Message> {
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.onmessage?.({ jsonrpc: "2.0", id, method, params });
    });
  }
  notify(method: string): void {
    this.onmessage?.({ jsonrpc: "2.0", method });
  }
}

/**
 * WI-06 with #395: the ChatGPT Secure MCP Tunnel is a remote transport that
 * serves `core`. web_search is local-only, so the tunnel never lists it, a
 * call to it is refused without reaching the kernel, and the transport
 * marker reaches orceld, which refuses search/* on its own.
 */
test("wi06 a tunnel-launched host neither lists nor serves web_search", async () => {
  let kernelCalls = 0;
  const kernel = {
    sessionId: "wi06-tunnel",
    call: async () => {
      kernelCalls += 1;
      return { ok: true, result: {} };
    },
    close: () => {},
    pending: new Map(),
    child: {} as never
  } as unknown as KernelClient;
  const tunnel = tunnelTransportContext("openai");
  assert.equal(allowedToolsFor(tunnel).has("web_search"), false);
  assert.equal(allowedToolsFor(localTransportContext({})).has("web_search"), true);

  const server = buildOrcelServer(kernel, "default", tunnel);
  const transport = new MemoryTransport();
  await server.connect(transport as never);
  await transport.request(1, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "wi06", version: "1" }
  });
  transport.notify("notifications/initialized");
  const listed = await transport.request(2, "tools/list", {});
  const names = (listed.result as { tools: Array<{ name: string }> }).tools.map((tool) => tool.name);
  assert.equal(names.includes("web_search"), false);
  assert.ok(names.includes("fs_read"), "the rest of the surface is served");
  const called = await transport.request(3, "tools/call", { name: "web_search", arguments: { query: "q" } });
  const refused =
    called.error !== undefined || (called.result as { isError?: boolean } | undefined)?.isError === true;
  assert.ok(refused, JSON.stringify(called));
  assert.equal(kernelCalls, 0);
  await server.close();

  assert.equal(buildDaemonEnv({ [TRANSPORT_ENV]: TUNNEL_TRANSPORT })[TRANSPORT_ENV], "tunnel");
});
