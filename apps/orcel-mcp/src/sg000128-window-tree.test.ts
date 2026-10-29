import assert from "node:assert/strict";
import test from "node:test";
import type { KernelClient } from "./kernel.js";
import { REMOTE_PROVIDER_PROFILES, SURFACE_PROFILES, TOOL_CONTRACT } from "./tool_contract.js";
import { allowedToolsFor, buildOrcelServer, localTransportContext, tunnelTransportContext } from "./server.js";

/**
 * SG-000128 slice 2: desktop_window_tree gains an optional subtree root,
 * root_element_id with its tree_generation (both or neither), forwarded to
 * orceld as uia.tree/observe root_element_id and expected_tree_generation.
 * The tool stays local-only, read-only and bounded exactly as before.
 */

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

interface Forwarded {
  workspaceId: string;
  capability: string;
  operation: string;
  arguments: Record<string, unknown>;
}

function recordingKernel(calls: Forwarded[]): KernelClient {
  return {
    sessionId: "sg128",
    call: async (input: Forwarded) => {
      calls.push(input);
      return { ok: true, result: { state: "observed" } };
    },
    close: () => {},
    pending: new Map(),
    child: {} as never
  } as unknown as KernelClient;
}

async function session(kernel: KernelClient, context: ReturnType<typeof localTransportContext>) {
  const server = buildOrcelServer(kernel, "default", context);
  const transport = new MemoryTransport();
  await server.connect(transport as never);
  await transport.request(1, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "sg128", version: "1" }
  });
  transport.notify("notifications/initialized");
  return { server, transport };
}

const WINDOW = { window_id: "uia-win-0123456789abcdef", window_generation: 3 };
const ROOT = { root_element_id: "uia-el-0123456789abcdef", tree_generation: 4 };

test("sg128 desktop_window_tree forwards an optional subtree root and nothing else", async () => {
  const calls: Forwarded[] = [];
  const { server, transport } = await session(recordingKernel(calls), localTransportContext({}));
  const listed = await transport.request(2, "tools/list", {});
  const tool = (listed.result as { tools: Array<{ name: string; inputSchema: { properties: Record<string, unknown> } }> })
    .tools.find((entry) => entry.name === "desktop_window_tree");
  assert.ok(tool, "desktop_window_tree is listed locally");
  assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), [
    "max_depth",
    "max_nodes",
    "root_element_id",
    "tree_generation",
    "window_generation",
    "window_id",
    "workspace_id"
  ]);

  await transport.request(3, "tools/call", { name: "desktop_window_tree", arguments: WINDOW });
  await transport.request(4, "tools/call", { name: "desktop_window_tree", arguments: { ...WINDOW, ...ROOT } });
  // Kernel field names and native identities sent by a caller are never
  // forwarded: only the named arguments build the kernel payload.
  await transport.request(5, "tools/call", {
    name: "desktop_window_tree",
    arguments: { ...WINDOW, ...ROOT, runtime_id: "42.1", hwnd: 1312, selector: "//Edit", expected_tree_generation: 9 }
  });
  let id = 6;
  for (const half of [{ root_element_id: ROOT.root_element_id }, { tree_generation: ROOT.tree_generation }]) {
    const called = await transport.request(id++, "tools/call", { name: "desktop_window_tree", arguments: { ...WINDOW, ...half } });
    const refused =
      called.error !== undefined || (called.result as { isError?: boolean } | undefined)?.isError === true;
    assert.ok(refused, `half a root is refused before orceld: ${JSON.stringify(half)}`);
  }
  await server.close();

  // The injected call forwarded exactly the clean scoped payload.
  assert.equal(calls.length, 3);
  const injected = calls.pop();
  assert.deepEqual(injected?.arguments, calls[1]?.arguments);
  assert.deepEqual(
    calls.map((call) => [call.capability, call.operation, call.arguments]),
    [
      ["uia.tree", "observe", { window_id: WINDOW.window_id, expected_window_generation: 3, max_depth: 8, max_nodes: 256 }],
      [
        "uia.tree",
        "observe",
        {
          window_id: WINDOW.window_id,
          expected_window_generation: 3,
          max_depth: 8,
          max_nodes: 256,
          root_element_id: ROOT.root_element_id,
          expected_tree_generation: 4
        }
      ]
    ]
  );
});

test("sg128 desktop_window_tree stays local-only, read-only and bounded as before", () => {
  const entry = TOOL_CONTRACT.desktop_window_tree;
  assert.ok(entry);
  assert.equal(entry.remote, "local_only");
  assert.equal(entry.approval, "none");
  assert.equal(entry.effect, "desktop_observe");
  assert.equal(entry.outputBound, "depth 8 and at most 256 elements within 64 KiB");
  assert.equal(allowedToolsFor(tunnelTransportContext("openai")).has("desktop_window_tree"), false);
  // Every remote provider maps to a profile that omits the tool.
  for (const [provider, profile] of Object.entries(REMOTE_PROVIDER_PROFILES)) {
    assert.equal(SURFACE_PROFILES[profile].includes("desktop_window_tree"), false, provider);
  }
});
