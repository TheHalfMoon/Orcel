import assert from "node:assert/strict";
import test from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  MAX_REPORT_BYTES,
  MAX_REPORT_NAME_CHARS,
  MAX_REPORT_SOURCES,
  MAX_REPORT_TITLE_CHARS,
  reportCommitSchema,
  reportPreviewSchema,
  reportStartSchema
} from "./report.js";
import { SURFACE_PROFILES, TOOL_CONTRACT } from "./tool_contract.js";
import type { KernelClient } from "./kernel.js";
import { allowedToolsFor, buildOrcelServer, localTransportContext, tunnelTransportContext } from "./server.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");
const repo = join(here, "..", "..", "..");

const REPORT_TOOLS = ["report_commit", "report_preview", "report_start"];
const TASK = "rpt-0123456789abcdef0123456789abcdef";
const SHA = "a".repeat(64);

/**
 * SG-000127 slice 3: exactly the three closed report shapes reach the
 * kernel, only from report.ts, and the edge carries no approval of its own.
 */
test("sg127 only report.ts forwards report/*, and it carries no approval", () => {
  const forwarded: string[] = [];
  for (const name of readdirSync(srcDir).filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts") && n !== "tool_contract.ts")) {
    const text = readFileSync(join(srcDir, name), "utf8");
    for (const match of text.matchAll(/capability:\s*["'](report[a-z_.]*)["'],\s*operation:\s*["']([a-z_]+)["']/g)) {
      forwarded.push(`${name}:${match[1] ?? ""}/${match[2] ?? ""}`);
    }
  }
  assert.deepEqual(forwarded, ["report.ts:report/start", "report.ts:report/preview", "report.ts:report/commit"]);
  const source = readFileSync(join(srcDir, "report.ts"), "utf8");
  assert.doesNotMatch(source, /node:net|node:http|node:https|node:fs|fetch\(|child_process/);
  // No argument or forwarded field can approve, overwrite or carry a token.
  assert.doesNotMatch(source, /\b(approv\w*|approval_id|token|secret|overwrite|force|presence)\s*:/i);
});

test("sg127 the kernel shapes match orcel-policy's admitted report shapes", () => {
  const policy = readFileSync(join(repo, "crates", "orcel-policy", "src", "report.rs"), "utf8");
  for (const operation of ["start", "preview", "commit"]) {
    assert.ok(policy.includes(`("report", "${operation}")`), operation);
  }
  for (const [name, value] of [
    ["MAX_REPORT_TITLE_CHARS", MAX_REPORT_TITLE_CHARS],
    ["MAX_REPORT_SOURCES", MAX_REPORT_SOURCES],
    ["MAX_REPORT_NAME_CHARS", MAX_REPORT_NAME_CHARS]
  ] as const) {
    assert.match(policy, new RegExp(`pub const ${name}: usize = ${value};`), name);
  }
  assert.match(policy, /pub const MAX_REPORT_BYTES: usize = 256 \* 1024;/);
  assert.equal(MAX_REPORT_BYTES, 256 * 1024);
});

test("sg127 report schemas are bounded and drop unknown fields", () => {
  const start = reportStartSchema("w");
  assert.equal(start.safeParse({ title: "Q3", sources: ["data/a.csv"], folder: "out" }).success, true);
  for (const input of [
    {},
    { title: "", sources: ["a.txt"], folder: "out" },
    { title: "   ", sources: ["a.txt"], folder: "out" },
    { title: "a".repeat(MAX_REPORT_TITLE_CHARS + 1), sources: ["a.txt"], folder: "out" },
    { title: "line\nbreak", sources: ["a.txt"], folder: "out" },
    { title: "t", sources: [], folder: "out" },
    { title: "t", sources: Array.from({ length: MAX_REPORT_SOURCES + 1 }, (_, i) => `s${i}.txt`), folder: "out" },
    { title: "t", sources: ["a.txt", "a.txt"], folder: "out" },
    { title: "t", sources: ["a.txt"], folder: "" }
  ]) {
    assert.equal(start.safeParse(input).success, false, JSON.stringify(input));
  }

  const preview = reportPreviewSchema("w");
  assert.equal(preview.safeParse({ task_id: TASK, name: "q3.md", content: "x" }).success, true);
  assert.equal(preview.safeParse({ task_id: TASK, name: "Q3-summary.TXT", content: "" }).success, true);
  for (const input of [
    { task_id: "rpt-1", name: "q3.md", content: "x" },
    { task_id: TASK, name: ".hidden.md", content: "x" },
    { task_id: TASK, name: "../q3.md", content: "x" },
    { task_id: TASK, name: "dir/q3.md", content: "x" },
    { task_id: TASK, name: "q3.exe", content: "x" },
    { task_id: TASK, name: `${"a".repeat(MAX_REPORT_NAME_CHARS)}.md`, content: "x" },
    { task_id: TASK, name: "q3.md", content: "é".repeat(MAX_REPORT_BYTES / 2 + 1) }
  ]) {
    assert.equal(preview.safeParse(input).success, false, JSON.stringify(input));
  }

  const commit = reportCommitSchema("w");
  assert.equal(commit.safeParse({ task_id: TASK, name: "q3.md", content: "x", expected_sha256: SHA }).success, true);
  assert.equal(commit.safeParse({ task_id: TASK, name: "q3.md", content: "x", expected_sha256: SHA.toUpperCase() }).success, false);
  assert.equal(commit.safeParse({ task_id: TASK, name: "q3.md", content: "x" }).success, false);
  const parsed = commit.parse({
    task_id: TASK,
    name: "q3.md",
    content: "x",
    expected_sha256: SHA,
    approved: true,
    approval_id: "apr-1",
    overwrite: true
  });
  assert.deepEqual(Object.keys(parsed).sort(), ["content", "expected_sha256", "name", "task_id", "workspace_id"]);
});

test("sg127 report tools are local-only and only commit needs SOFT approval", () => {
  const expected = {
    report_start: { operation: "start", effect: "read", approval: "none" },
    report_preview: { operation: "preview", effect: "preview", approval: "none" },
    report_commit: { operation: "commit", effect: "write", approval: "SOFT" }
  } as const;
  for (const [name, want] of Object.entries(expected)) {
    const entry = TOOL_CONTRACT[name];
    assert.ok(entry, name);
    assert.equal(entry.capability, "report", name);
    assert.equal(entry.operation, want.operation, name);
    assert.equal(entry.effect, want.effect, name);
    assert.equal(entry.approval, want.approval, name);
    assert.equal(entry.remote, "local_only", name);
    assert.equal(entry.annotations.destructiveHint, false, `${name} never overwrites`);
    assert.equal(entry.annotations.openWorldHint, false, name);
  }
  // Exact profile membership: core (the remote ceiling) never lists them;
  // both local profiles do.
  for (const name of REPORT_TOOLS) {
    assert.equal(SURFACE_PROFILES.core.includes(name), false, name);
    assert.equal(SURFACE_PROFILES.desktop_structured.includes(name), true, name);
    assert.equal(SURFACE_PROFILES.browser_structured.includes(name), true, name);
  }
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

interface Forwarded {
  workspaceId: string;
  capability: string;
  operation: string;
  arguments: Record<string, unknown>;
  target?: unknown;
}

function recordingKernel(calls: Forwarded[]): KernelClient {
  return {
    sessionId: "sg127",
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
    clientInfo: { name: "sg127", version: "1" }
  });
  transport.notify("notifications/initialized");
  return { server, transport };
}

test("sg127 a local host forwards exactly the admitted fields and nothing else", async () => {
  const calls: Forwarded[] = [];
  const { server, transport } = await session(recordingKernel(calls), localTransportContext({}));
  const listed = await transport.request(2, "tools/list", {});
  const names = (listed.result as { tools: Array<{ name: string }> }).tools.map((tool) => tool.name);
  for (const name of REPORT_TOOLS) {
    assert.ok(names.includes(name), name);
  }
  await transport.request(3, "tools/call", {
    name: "report_start",
    arguments: { title: "Q3", sources: ["data/a.csv"], folder: "out", approved: true }
  });
  await transport.request(4, "tools/call", {
    name: "report_preview",
    arguments: { task_id: TASK, name: "q3.md", content: "x", overwrite: true }
  });
  await transport.request(5, "tools/call", {
    name: "report_commit",
    arguments: { task_id: TASK, name: "q3.md", content: "x", expected_sha256: SHA, approval_id: "apr-1" }
  });
  await server.close();
  assert.deepEqual(
    calls.map((call) => [call.capability, call.operation, Object.keys(call.arguments).sort(), call.target]),
    [
      ["report", "start", ["folder", "sources", "title"], undefined],
      ["report", "preview", ["content", "name", "task_id"], undefined],
      ["report", "commit", ["content", "expected_sha256", "name", "task_id"], undefined]
    ]
  );
  assert.ok(calls.every((call) => call.workspaceId === "default"));
});

/**
 * The ChatGPT Secure MCP Tunnel serves `core`: it never lists a report
 * tool, a call is refused before the kernel, and orceld refuses a
 * remote-context report request on its own (report_task.rs).
 */
test("sg127 a tunnel-launched host neither lists nor serves the report tools", async () => {
  const calls: Forwarded[] = [];
  const tunnel = tunnelTransportContext("openai");
  for (const name of REPORT_TOOLS) {
    assert.equal(allowedToolsFor(tunnel).has(name), false, name);
    assert.equal(allowedToolsFor(localTransportContext({})).has(name), true, name);
  }
  const { server, transport } = await session(recordingKernel(calls), tunnel);
  const listed = await transport.request(2, "tools/list", {});
  const names = (listed.result as { tools: Array<{ name: string }> }).tools.map((tool) => tool.name);
  for (const name of REPORT_TOOLS) {
    assert.equal(names.includes(name), false, name);
  }
  assert.ok(names.includes("fs_read"), "the rest of the surface is served");
  let id = 10;
  for (const name of REPORT_TOOLS) {
    const called = await transport.request(id++, "tools/call", {
      name,
      arguments: { title: "t", sources: ["a.txt"], folder: "out", task_id: TASK, name: "q3.md", content: "x", expected_sha256: SHA }
    });
    const refused =
      called.error !== undefined || (called.result as { isError?: boolean } | undefined)?.isError === true;
    assert.ok(refused, `${name}: ${JSON.stringify(called)}`);
  }
  assert.equal(calls.length, 0);
  await server.close();
});
