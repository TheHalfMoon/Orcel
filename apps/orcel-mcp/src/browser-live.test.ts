import assert from "node:assert/strict";
import test from "node:test";
import type { McpServer } from "@modelcontextprotocol/server";
import { registerLiveBrowserTools } from "./browser_live.js";
import type { KernelClient } from "./kernel.js";
import { LIVE_BROWSER_TOOLS, TOOL_CONTRACT } from "./tool_contract.js";

// SG-000108 slice 3c (judge): each live browser tool forwards exactly its
// contract shape, with exactly the arguments it was given.

test("each live browser tool forwards exactly its contract shape", async () => {
  const handlers = new Map<string, (args: Record<string, unknown>) => Promise<unknown>>();
  const server = {
    registerTool(name: string, _config: unknown, handler: (args: Record<string, unknown>) => Promise<unknown>) {
      handlers.set(name, handler);
    }
  } as unknown as McpServer;
  const sent: Array<{ capability: string; operation: string; arguments?: Record<string, unknown> }> = [];
  const kernel = {
    call: async (input: { capability: string; operation: string; arguments?: Record<string, unknown> }) => {
      sent.push(input);
      return { ok: true, result: {} };
    }
  } as unknown as KernelClient;
  registerLiveBrowserTools(server, kernel, "default");
  assert.deepEqual([...handlers.keys()].sort(), [...LIVE_BROWSER_TOOLS].sort());
  const args: Record<string, Record<string, unknown>> = {
    browser_page_open: {},
    browser_navigate: { page_id: "pg-a1", url: "https://example.org/", expected_generation: 0 },
    browser_observe: { page_id: "pg-a1", expected_generation: 1 },
    browser_click: { page_id: "pg-a1", node_id: "d1-e2", expected_generation: 1 },
    browser_download_preview: { page_id: "pg-a1", node_id: "d1-e2", file_name: "r.pdf", expected_generation: 1 },
    browser_download: { page_id: "pg-a1", node_id: "d1-e2", file_name: "r.pdf", expected_generation: 1 }
  };
  for (const tool of LIVE_BROWSER_TOOLS) {
    sent.length = 0;
    const handler = handlers.get(tool);
    assert.ok(handler, tool);
    await handler({ workspace_id: "default", ...args[tool] });
    assert.equal(sent.length, 1, tool);
    const entry = TOOL_CONTRACT[tool];
    assert.equal(`${sent[0]?.capability}/${sent[0]?.operation}`, `${entry?.capability}/${entry?.operation}`, tool);
    assert.deepEqual(sent[0]?.arguments, args[tool], tool);
  }
});
