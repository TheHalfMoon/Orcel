import assert from "node:assert/strict";
import test from "node:test";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  browserFillSchema,
  browserVerifySchema,
  browserWaitTextSchema,
  registerLiveBrowserTools
} from "./browser_live.js";
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
    browser_download: { page_id: "pg-a1", node_id: "d1-e2", file_name: "r.pdf", expected_generation: 1 },
    // SG-000122 slice A3 (the same arguments orceld's
    // sg122_a3_mcp_shapes_route_to_the_live_dispatch test sends).
    browser_fill: { page_id: "pg-a1", node_id: "d1-e2", value: "Ada Lovelace", expected_generation: 1 },
    browser_wait_text: { page_id: "pg-a1", text: "Saved", appear: true, timeout_ms: 5000, expected_generation: 1 },
    browser_verify: {
      page_id: "pg-a1",
      checks: [
        { kind: "element_visible", node_id: "d1-e2" },
        { kind: "text_visible", text: "Saved" },
        { kind: "value_equals", node_id: "d1-e2", value: "Ada Lovelace" },
        { kind: "checked", node_id: "d1-e4", checked: true },
        { kind: "url_is", url: "https://example.org/done" }
      ],
      expected_generation: 1
    }
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

// SG-000122 slice A3: the schemas are a first filter (orceld's live policy
// and the host decide); each takes exactly its fields within the bounds.

test("sg122 browser_fill's schema takes one bounded, one-line value", () => {
  const schema = browserFillSchema("default");
  const base = { page_id: "pg-a1", node_id: "d1-e2", expected_generation: 1 };
  const parsed = schema.parse({ ...base, value: "Ada Lovelace" });
  assert.deepEqual(parsed, { workspace_id: "default", ...base, value: "Ada Lovelace" });
  assert.equal(schema.safeParse({ ...base, value: "" }).success, true);
  assert.equal(schema.safeParse({ ...base, value: "a".repeat(1024) }).success, true);
  for (const value of ["a".repeat(1025), "line\nbreak", "tab\there", "nul\u0000", "c1\u0085", 7, null]) {
    assert.equal(schema.safeParse({ ...base, value }).success, false, JSON.stringify(value));
  }
  for (const missing of ["page_id", "node_id", "value", "expected_generation"]) {
    const args: Record<string, unknown> = { ...base, value: "x" };
    delete args[missing];
    assert.equal(schema.safeParse(args).success, false, missing);
  }
  assert.equal(schema.safeParse({ ...base, value: "x", page_id: "tab-1" }).success, false);
  assert.equal(schema.safeParse({ ...base, value: "x", node_id: "#id .class" }).success, false);
});

test("sg122 browser_wait_text's schema bounds the text and the timeout", () => {
  const schema = browserWaitTextSchema("default");
  const base = { page_id: "pg-a1", appear: true, timeout_ms: 1000, expected_generation: 1 };
  assert.equal(schema.safeParse({ ...base, text: "Saved" }).success, true);
  assert.equal(schema.safeParse({ ...base, text: "Gone", appear: false, timeout_ms: 8000 }).success, true);
  for (const text of ["", "a".repeat(1025), "two\nlines", "esc\u001b"]) {
    assert.equal(schema.safeParse({ ...base, text }).success, false, JSON.stringify(text));
  }
  for (const timeout_ms of [0, 8001, 1.5, -1]) {
    assert.equal(schema.safeParse({ ...base, text: "Saved", timeout_ms }).success, false, String(timeout_ms));
  }
  assert.equal(schema.safeParse({ ...base, text: "Saved", appear: "yes" }).success, false);
  assert.equal(
    schema.safeParse({ page_id: "pg-a1", text: "Saved", timeout_ms: 1000, expected_generation: 1 }).success,
    false
  );
});

test("sg122 browser_verify's schema takes 1 to 16 of the five check kinds, each exactly", () => {
  const schema = browserVerifySchema("default");
  const base = { page_id: "pg-a1", expected_generation: 1 };
  const ok = [
    { kind: "element_visible", node_id: "d1-e2" },
    { kind: "text_visible", text: "Saved" },
    { kind: "value_equals", node_id: "d1-e2", value: "" },
    { kind: "checked", node_id: "d1-e4", checked: false },
    { kind: "url_is", url: "https://example.org/done" }
  ];
  assert.equal(schema.safeParse({ ...base, checks: ok }).success, true);
  assert.equal(schema.safeParse({ ...base, checks: Array(16).fill(ok[1]) }).success, true);
  assert.equal(schema.safeParse({ ...base, checks: [] }).success, false);
  assert.equal(schema.safeParse({ ...base, checks: Array(17).fill(ok[1]) }).success, false);
  for (const check of [
    // Outside this slice's verifier: the download digest and unknown kinds.
    { kind: "download_sha256", sha256: "a".repeat(64) },
    { kind: "list", node_id: "d1-e2" },
    { kind: "script", source: "1" },
    // An extra field, a missing one, or a value out of bounds.
    { kind: "text_visible", text: "Saved", node_id: "d1-e2" },
    { kind: "element_visible" },
    { kind: "checked", node_id: "d1-e4" },
    { kind: "value_equals", node_id: "d1-e2", value: "two\nlines" },
    { kind: "text_visible", text: "" },
    { kind: "url_is", url: "" }
  ]) {
    assert.equal(schema.safeParse({ ...base, checks: [check] }).success, false, JSON.stringify(check));
  }
});

test("sg122 the A3 tool descriptions state the approval, the caps and what is page-supplied", () => {
  const descriptions = new Map<string, string>();
  const server = {
    registerTool(name: string, config: { description: string }) {
      descriptions.set(name, config.description);
    }
  } as unknown as McpServer;
  registerLiveBrowserTools(server, {} as KernelClient, "default");
  const fill = descriptions.get("browser_fill") ?? "";
  for (const phrase of [
    "fresh local Orcel approval bound to the page generation, the field and the value",
    "text, search, email, url or tel",
    "shows the value exactly and in full",
    "is refused, never cut or altered",
    "1024 displayed characters",
    "labelled page-supplied",
    "untrusted",
    "Values are not checked for secrets",
    "Windows development builds only"
  ]) {
    assert.ok(fill.includes(phrase), `browser_fill: ${phrase}`);
  }
  const wait = descriptions.get("browser_wait_text") ?? "";
  for (const phrase of [
    "at most 8000",
    "Only the main frame's committed document is checked, never a child frame",
    "no approval",
    "at most 16 distinct awaited texts",
    "refused without probing the page",
    "Windows development builds only"
  ]) {
    assert.ok(wait.includes(phrase), `browser_wait_text: ${phrase}`);
  }
  const verify = descriptions.get("browser_verify") ?? "";
  for (const phrase of [
    "1 to 16 postconditions",
    "no approval",
    "only at the main frame's committed document, never a child frame",
    "16 distinct awaited texts",
    "at most 3 distinct values",
    "never page text, names or values",
    "Windows development builds only"
  ]) {
    assert.ok(verify.includes(phrase), `browser_verify: ${phrase}`);
  }
});
