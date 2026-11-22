import assert from "node:assert/strict";
import test from "node:test";
import type { KernelClient } from "./kernel.js";
import {
  FULL_CONTROL_KERNEL_SHAPES,
  fcBranchSchema,
  fcCommitSchema,
  fcListSchema,
  fcPathSchema,
  fcPathsSchema,
  fcReadSchema,
  fcRunSchema,
  fcStatusSchema,
  fcWriteSchema
} from "./full_control.js";
import { LOCAL_ONLY_TOOL_NAMES, authorizeToolByScopes } from "./oauth_authorization.js";
import { buildOrcelServer, localTransportContext, type TransportContext } from "./server.js";
import { FULL_CONTROL_TOOLS, TOOL_CONTRACT, profileTools } from "./tool_contract.js";

const ALL_SCOPES = ["orcel.read", "orcel.write", "orcel.execute"];

/**
 * SG132_SLICE9.md: the Full Control MCP tools. Schemas repeat orceld's
 * bounds; every tool is local only and listed in desktop_structured alone;
 * approval classes follow the founder decision of 2026-11-19; orceld's
 * answers (refusals included) pass through unchanged.
 */

const ASKING = ["fc_process_run", "fc_git_stage", "fc_git_unstage", "fc_git_commit", "fc_git_branch_create"];
const LEASE_COVERED = ["fc_fs_write", "fc_fs_mkdir"];

test("fc: the contract lists the 14 tools, local only, with the decided approvals", () => {
  assert.equal(FULL_CONTROL_TOOLS.length, 14);
  assert.deepEqual(
    FULL_CONTROL_TOOLS.map((name) => {
      const entry = TOOL_CONTRACT[name];
      assert.ok(entry, name);
      return [entry.capability, entry.operation];
    }).sort(),
    FULL_CONTROL_KERNEL_SHAPES.map(([capability, operation]) => [capability, operation]).sort()
  );
  for (const name of FULL_CONTROL_TOOLS) {
    const entry = TOOL_CONTRACT[name];
    assert.ok(entry, name);
    assert.equal(entry.remote, "local_only", name);
    assert.ok(LOCAL_ONLY_TOOL_NAMES.includes(name), name);
    assert.equal(authorizeToolByScopes(name, "core", ALL_SCOPES, ALL_SCOPES).ok, false, name);
    if (ASKING.includes(name)) {
      assert.equal(entry.approval, "SOFT", `${name} asks on every call`);
    } else if (LEASE_COVERED.includes(name)) {
      assert.equal(entry.approval, "none", `${name} is covered by the lease`);
      assert.equal(entry.effect, "lease_write", name);
      assert.equal(entry.annotations.readOnlyHint, false, name);
    } else {
      assert.equal(entry.approval, "none", name);
      assert.equal(entry.effect, "read", name);
      assert.equal(entry.annotations.readOnlyHint, true, name);
    }
  }
  assert.equal(TOOL_CONTRACT.fc_git_stage?.operation, "git_add");
  assert.equal(TOOL_CONTRACT.fc_process_run?.annotations.openWorldHint, true);
});

test("fc: listed in desktop_structured only, never in a browser or remote profile", () => {
  const desktop = profileTools("desktop_structured");
  for (const name of FULL_CONTROL_TOOLS) {
    assert.ok(desktop.has(name), name);
    for (const profile of ["core", "browser_structured", "browser_full"]) {
      assert.equal(profileTools(profile).has(name), false, `${name} in ${profile}`);
    }
  }
});

test("fc: schemas repeat orceld's bounds", () => {
  const ok = (schema: { safeParse: (v: unknown) => { success: boolean } }, value: unknown) =>
    assert.equal(schema.safeParse(value).success, true, JSON.stringify(value).slice(0, 120));
  const bad = (schema: { safeParse: (v: unknown) => { success: boolean } }, value: unknown) =>
    assert.equal(schema.safeParse(value).success, false, JSON.stringify(value).slice(0, 120));
  const path = fcPathSchema("default");
  ok(path, { path: "C:\\work\\a.txt" });
  ok(path, { path: "D:/work" });
  for (const p of ["work\\a.txt", "\\\\server\\share\\a", "", "C:", "C:\\a\nb", `C:\\${"a".repeat(1100)}`]) {
    bad(path, { path: p });
  }
  const list = fcListSchema("default");
  ok(list, { path: "C:\\work" });
  bad(list, { path: "C:\\work", max_entries: 0 });
  bad(list, { path: "C:\\work", max_entries: 1001 });
  const read = fcReadSchema("default");
  bad(read, { path: "C:\\work\\a", max_bytes: 262145 });
  const write = fcWriteSchema("default");
  ok(write, { path: "C:\\work\\a.txt", text: "hello" });
  bad(write, { path: "C:\\work\\a.txt", text: "x".repeat(256 * 1024 + 1) });
  // UTF-8 bytes, not characters.
  bad(write, { path: "C:\\work\\a.txt", text: "\u00e9".repeat(131073) });
  const run = fcRunSchema("default");
  const program = { program: "C:\\work\\tool.exe", cwd: "C:\\work" };
  ok(run, program);
  ok(run, { ...program, args: Array(64).fill("x"), timeout_ms: 50000, max_output_bytes: 65536 });
  bad(run, { ...program, program: "C:\\work\\tool.bat" });
  bad(run, { ...program, args: Array(65).fill("x") });
  bad(run, { ...program, args: ["a\0b"] });
  bad(run, { ...program, args: ["x".repeat(8193)] });
  bad(run, { ...program, timeout_ms: 0 });
  bad(run, { ...program, timeout_ms: 50001 });
  bad(run, { ...program, max_output_bytes: 65537 });
  const paths = fcPathsSchema("default");
  const repository = "C:\\work\\repo";
  ok(paths, { repository, paths: ["a.txt", "src/b.rs"] });
  bad(paths, { repository, paths: [] });
  bad(paths, { repository, paths: Array.from({ length: 129 }, (_, i) => `f${i}`) });
  bad(paths, { repository, paths: ["a.txt", "a.txt"] });
  bad(paths, { repository, paths: [":(glob)*"] });
  bad(paths, { repository, paths: ["a\tb"] });
  const commit = fcCommitSchema("default");
  ok(commit, { repository, message: "change" });
  bad(commit, { repository, message: "   " });
  bad(commit, { repository, message: "x".repeat(8193) });
  const branch = fcBranchSchema("default");
  ok(branch, { repository, branch: "topic/one" });
  bad(branch, { repository, branch: "-delete" });
  bad(branch, { repository, branch: "a\nb" });
  bad(branch, { repository, branch: "b".repeat(256) });
  ok(fcStatusSchema("default"), {});
});

interface Forwarded {
  workspaceId: string;
  capability: string;
  operation: string;
  arguments: Record<string, unknown>;
  target?: unknown;
}

type Message = { jsonrpc: "2.0"; id?: number; method?: string; params?: unknown; result?: unknown };

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

function refusingKernel(calls: Forwarded[], code: string): KernelClient {
  return {
    sessionId: "fc-test",
    call: async (input: Forwarded) => {
      calls.push(input);
      return {
        version: 1,
        request_id: "r",
        ok: false,
        error: { code, message: "no active Full User lease covers filesystem" }
      };
    },
    close: () => {},
    pending: new Map(),
    child: {} as never
  } as unknown as KernelClient;
}

async function session(kernel: KernelClient, context: TransportContext) {
  const server = buildOrcelServer(kernel, "default", context);
  const transport = new MemoryTransport();
  await server.connect(transport as never);
  await transport.request(1, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "fc-test", version: "1" }
  });
  transport.notify("notifications/initialized");
  return { server, transport };
}

test("fc: each tool forwards exactly one worker operation and orceld's refusal passes through", async () => {
  const calls: Forwarded[] = [];
  const { server, transport } = await session(refusingKernel(calls, "LEASE_REQUIRED"), localTransportContext({}));
  const listed = await transport.request(2, "tools/list", {});
  const names = (listed.result as { tools: Array<{ name: string }> }).tools.map((tool) => tool.name);
  for (const name of FULL_CONTROL_TOOLS) {
    assert.ok(names.includes(name), name);
  }
  const repository = "C:\\work\\repo";
  const cases: Array<[string, Record<string, unknown>, string, string, Record<string, unknown>]> = [
    ["fc_status", {}, "fc.status", "get", {}],
    ["fc_fs_stat", { path: "C:\\work\\a" }, "fc.fs", "stat", { op: "stat", path: "C:\\work\\a" }],
    ["fc_fs_list", { path: "C:\\work" }, "fc.fs", "list", { op: "list", path: "C:\\work", max_entries: 200 }],
    ["fc_fs_read", { path: "C:\\work\\a" }, "fc.fs", "read_text", { op: "read_text", path: "C:\\work\\a", max_bytes: 65536 }],
    [
      "fc_fs_write",
      { path: "C:\\work\\a", text: "hi" },
      "fc.fs",
      "write_text",
      { op: "write_text", path: "C:\\work\\a", text: "hi", create_new: false }
    ],
    ["fc_fs_mkdir", { path: "C:\\work\\n" }, "fc.fs", "mkdir", { op: "mkdir", path: "C:\\work\\n" }],
    [
      "fc_process_run",
      { program: "C:\\work\\t.exe", cwd: "C:\\work", args: ["--x"] },
      "fc.process",
      "run",
      { op: "run", program: "C:\\work\\t.exe", args: ["--x"], cwd: "C:\\work", timeout_ms: 30000, max_output_bytes: 65536 }
    ],
    ["fc_git_status", { repository }, "fc.git", "git_status", { op: "git_status", repository }],
    ["fc_git_diff", { repository }, "fc.git", "git_diff", { op: "git_diff", repository, staged: false }],
    ["fc_git_log", { repository }, "fc.git", "git_log", { op: "git_log", repository, max_count: 20 }],
    ["fc_git_stage", { repository, paths: ["a"] }, "fc.git", "git_add", { op: "git_add", repository, paths: ["a"] }],
    ["fc_git_unstage", { repository, paths: ["a"] }, "fc.git", "git_unstage", { op: "git_unstage", repository, paths: ["a"] }],
    ["fc_git_commit", { repository, message: "m" }, "fc.git", "git_commit", { op: "git_commit", repository, message: "m" }],
    [
      "fc_git_branch_create",
      { repository, branch: "t" },
      "fc.git",
      "git_branch_create",
      { op: "git_branch_create", repository, branch: "t" }
    ]
  ];
  let id = 10;
  for (const [name, args, capability, operation, forwarded] of cases) {
    const before = calls.length;
    const answer = await transport.request(id++, "tools/call", { name, arguments: args });
    const result = answer.result as { isError?: boolean; content: Array<{ text: string }> };
    assert.equal(result.isError, true, name);
    const envelope = JSON.parse(result.content[0]?.text ?? "{}") as { error: { code: string } };
    assert.equal(envelope.error.code, "LEASE_REQUIRED", name);
    assert.equal(calls.length, before + 1, name);
    const call = calls[calls.length - 1];
    assert.ok(call, name);
    assert.deepEqual(
      [call.capability, call.operation, call.arguments, call.target, call.workspaceId],
      [capability, operation, forwarded, undefined, "default"],
      name
    );
  }
  // A malformed argument never reaches orceld.
  const before = calls.length;
  const rejected = await transport.request(id++, "tools/call", {
    name: "fc_process_run",
    arguments: { program: "C:\\work\\t.exe", cwd: "C:\\work", timeout_ms: 0 }
  });
  assert.equal((rejected.result as { isError?: boolean }).isError, true);
  assert.equal(calls.length, before);
  await server.close();
});

test("fc: a browser profile does not list the Full Control tools", async () => {
  for (const profile of ["browser_structured", "browser_full"]) {
    const { server, transport } = await session(
      refusingKernel([], "CAPABILITY_DENIED"),
      localTransportContext({ ORCEL_TOOL_SURFACE_PROFILE: profile })
    );
    const listed = await transport.request(2, "tools/list", {});
    const names = (listed.result as { tools: Array<{ name: string }> }).tools.map((tool) => tool.name);
    for (const name of FULL_CONTROL_TOOLS) {
      assert.equal(names.includes(name), false, `${name} under ${profile}`);
    }
    await server.close();
  }
});
