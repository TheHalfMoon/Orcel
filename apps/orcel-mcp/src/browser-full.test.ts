import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  browserExtractSchema,
  browserOpenSchema,
  browserSessionClickSchema,
  browserSessionCreateSchema,
  browserSessionFillSchema,
  browserSessionSchema,
  browserSessionSelectSchema,
  browserSessionVerifySchema,
  registerSessionBrokerTools
} from "./browser_full.js";
import type { KernelClient } from "./kernel.js";
import { OAUTH_PROFILE_TOOL_CEILINGS, OAUTH_SCOPE_TOOL_MATRIX, UNMAPPED_REMOTE_PROFILES, authorizeToolByScopes } from "./oauth_authorization.js";
import { allowedToolsFor, buildOrcelServer, localTransportContext, tunnelTransportContext, type TransportContext } from "./server.js";
import {
  BROWSER_FULL_CONTRACT,
  BROWSER_FULL_TOOLS,
  DESKTOP_STRUCTURED_TOOLS,
  LIVE_BROWSER_TOOLS,
  LOCAL_TOOL_SURFACE_PROFILES,
  REMOTE_PROVIDER_PROFILES,
  REMOTE_TOOL_NAMES,
  TOOL_CONTRACT,
  TOOL_SURFACE_PROFILE_ENV,
  contractEntryFor,
  localProfileFromConfig,
  profileTools,
  securitySchemesFor
} from "./tool_contract.js";

// SG-000135 OB-02: the local browser_full profile. Its tools agree across
// the MCP contract, orceld's profile gate and the browser host's exposure
// list; it is selected by local configuration only and never mapped remote.

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SESSION = "bs-0123456789abcdef-1-0001020304050607";
const SHARED = ["browser_click", "browser_fill", "browser_select", "browser_verify"];
const EXPECTED = [
  "browser_session_create",
  "browser_open",
  "browser_snapshot",
  "browser_click",
  "browser_fill",
  "browser_select",
  "browser_verify",
  "browser_extract",
  "browser_close",
  "browser_task_status"
];

/** Read a literal Rust table of string tuples (or strings) defined exactly once. */
function rustTuples(path: string, constant: string, width: number): string[][] {
  const text = readFileSync(join(repo, path), "utf8");
  const definitions = [...text.matchAll(new RegExp(`\\bconst ${constant}\\b`, "g"))];
  assert.equal(definitions.length, 1, `${constant} is defined exactly once in ${path}`);
  const match = new RegExp(`pub const ${constant}: [^=]+ = (&\\[[^\\]]*\\]);`).exec(text);
  assert.ok(match !== null, `${constant} in ${path} is a literal table`);
  const body = (match[1] ?? "").replace(/\s+/g, " ");
  const strings = [...body.matchAll(/"([^"\\]*)"/g)].map((found) => found[1] ?? "");
  const residue = body.replace(/"[^"\\]*"/g, "").replace(/[&\[\](), ]/g, "");
  assert.equal(residue, "", `${constant} holds only string literals`);
  assert.equal(strings.length % width, 0);
  const rows: string[][] = [];
  for (let index = 0; index < strings.length; index += width) {
    rows.push(strings.slice(index, index + width));
  }
  return rows;
}

test("the browser_full tools agree across the contract, orceld's gate and the host", () => {
  assert.deepEqual([...BROWSER_FULL_TOOLS], EXPECTED);
  const host = rustTuples("crates/orcel-browser-host/src/exposure.rs", "BROWSER_FULL_MCP_TOOLS", 1).map((row) => row[0]);
  assert.deepEqual(host, [...BROWSER_FULL_TOOLS]);
  const hostShapes = rustTuples("crates/orcel-browser-host/src/exposure.rs", "BROWSER_FULL_TOOL_SHAPES", 3);
  const gate = rustTuples("crates/orceld/src/profile_gate.rs", "BROWSER_FULL_SHAPES", 2).map((row) => row.join("/"));
  const contract = BROWSER_FULL_TOOLS.map((tool) => {
    const entry = BROWSER_FULL_CONTRACT[tool];
    assert.ok(entry !== undefined, tool);
    return `${entry.capability}/${entry.operation}`;
  });
  assert.deepEqual(gate, contract);
  assert.deepEqual(
    hostShapes.map((row) => `${row[0]} ${row[1]}/${row[2]}`),
    BROWSER_FULL_TOOLS.map((tool, index) => `${tool} ${contract[index]}`)
  );
  // The orceld profile name agrees too.
  const gateText = readFileSync(join(repo, "crates/orceld/src/profile_gate.rs"), "utf8");
  assert.match(gateText, /pub const BROWSER_FULL_PROFILE: &str = "browser_full";/);
  const hostText = readFileSync(join(repo, "crates/orcel-browser-host/src/exposure.rs"), "utf8");
  assert.match(hostText, /pub const BROWSER_FULL_PROFILE: &str = "browser_full";/);
  // Every broker shape is browser.session, and no browser_structured shape.
  const live = LIVE_BROWSER_TOOLS.map((tool) => `${TOOL_CONTRACT[tool]?.capability}/${TOOL_CONTRACT[tool]?.operation}`);
  for (const shape of contract) {
    assert.ok(shape.startsWith("browser.session/"), shape);
    assert.equal(live.includes(shape), false, shape);
  }
  // W2-03's outline and extract_schema stay without a tool.
  for (const shape of ["browser.session/outline", "browser.session/extract_schema"]) {
    assert.equal(contract.includes(shape), false, shape);
  }
});

test("browser_full is desktop_structured plus the broker tools, and only the four shared names overlap", () => {
  assert.deepEqual([...profileTools("browser_full")].sort(), [...DESKTOP_STRUCTURED_TOOLS, ...BROWSER_FULL_TOOLS].sort());
  assert.deepEqual(
    BROWSER_FULL_TOOLS.filter((tool) => LIVE_BROWSER_TOOLS.includes(tool)),
    SHARED
  );
  for (const tool of BROWSER_FULL_TOOLS) {
    assert.equal(profileTools("core").has(tool), false, tool);
    assert.equal(profileTools("desktop_structured").has(tool), false, tool);
    assert.equal(profileTools("browser_structured").has(tool), SHARED.includes(tool), tool);
    assert.equal(REMOTE_TOOL_NAMES.includes(tool), false, tool);
  }
  // The shared names resolve to the broker entries under browser_full only.
  for (const tool of SHARED) {
    assert.equal(contractEntryFor(tool, "browser_full"), BROWSER_FULL_CONTRACT[tool]);
    assert.equal(contractEntryFor(tool, "browser_structured"), TOOL_CONTRACT[tool]);
    assert.equal(contractEntryFor(tool, "browser_full")?.capability, "browser.session");
  }
  assert.equal(contractEntryFor("browser_session_create", "browser_structured"), undefined);
  assert.equal(contractEntryFor("browser_page_open", "browser_full"), TOOL_CONTRACT.browser_page_open);
});

test("the broker contract follows the annotation, effect and approval rules", () => {
  const soft = ["browser_open", "browser_click", "browser_fill", "browser_select"];
  for (const [name, entry] of Object.entries(BROWSER_FULL_CONTRACT)) {
    const a = entry.annotations;
    assert.equal(entry.remote, "local_only", name);
    assert.ok(entry.outputBound.length > 0, name);
    assert.deepEqual(Object.keys(entry).sort(), ["annotations", "approval", "capability", "effect", "operation", "outputBound", "remote"]);
    if (["read", "preview"].includes(entry.effect)) {
      assert.equal(a.readOnlyHint, true, name);
    }
    if (a.readOnlyHint) {
      assert.equal(a.destructiveHint, false, name);
    }
    assert.equal(a.openWorldHint, entry.effect === "network", name);
    assert.equal(entry.approval === "none", ["read", "preview"].includes(entry.effect), name);
    assert.equal(entry.approval, soft.includes(name) ? "SOFT" : "none", name);
    assert.notEqual(entry.approval, "STRONG", name);
    assert.equal(securitySchemesFor(name), null, name);
  }
  const titles = [...Object.values(TOOL_CONTRACT), ...Object.values(BROWSER_FULL_CONTRACT)].map((e) => e.annotations.title);
  assert.equal(new Set(titles).size, titles.length, "titles are unique across both contracts");
});

test("only local configuration selects browser_full, and no remote path maps it", () => {
  assert.equal(localProfileFromConfig("browser_full"), "browser_full");
  assert.deepEqual([...LOCAL_TOOL_SURFACE_PROFILES], ["desktop_structured", "browser_structured", "browser_full"]);
  for (const value of ["Browser_Full", " browser_full", "browser-full", "browser_full "]) {
    assert.throws(() => localProfileFromConfig(value), /TOOL_SURFACE_DENIED/, value);
  }
  const local = localTransportContext({ [TOOL_SURFACE_PROFILE_ENV]: "browser_full" });
  assert.equal(local.toolSurfaceProfile, "browser_full");
  assert.equal(local.transportKind, "stdio");
  assert.ok((UNMAPPED_REMOTE_PROFILES as readonly string[]).includes("browser_full"));
  assert.equal(Object.hasOwn(OAUTH_PROFILE_TOOL_CEILINGS, "browser_full"), false);
  const all = ["orcel.read", "orcel.write", "orcel.execute"];
  for (const provider of Object.keys(REMOTE_PROVIDER_PROFILES)) {
    assert.equal(REMOTE_PROVIDER_PROFILES[provider], "core");
    assert.equal(tunnelTransportContext(provider).toolSurfaceProfile, "core");
    for (const transportKind of ["tunnel", "relay"] as const) {
      assert.throws(
        () => allowedToolsFor({ transportKind, providerKind: provider, toolSurfaceProfile: "browser_full" }),
        /TOOL_SURFACE_DENIED/
      );
      const served = allowedToolsFor({ transportKind, providerKind: provider, toolSurfaceProfile: "core" });
      for (const tool of BROWSER_FULL_TOOLS) {
        assert.equal(served.has(tool), false, `${tool} ${transportKind} ${provider}`);
      }
    }
  }
  for (const tool of BROWSER_FULL_TOOLS) {
    assert.equal(Object.hasOwn(OAUTH_SCOPE_TOOL_MATRIX, tool), false, tool);
    assert.equal(authorizeToolByScopes(tool, "core", all, all).ok, false, tool);
    assert.equal(authorizeToolByScopes(tool, "browser_full", all, all).ok, false, tool);
  }
});

function fakeKernel(): KernelClient {
  return {
    sessionId: "browser-full-test",
    call: async () => {
      throw new Error("the kernel must not be called during discovery");
    },
    close: () => {},
    pending: new Map(),
    child: {} as never
  } as unknown as KernelClient;
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

interface ListedTool {
  name: string;
  title?: string;
  annotations?: Record<string, unknown>;
  inputSchema?: { properties?: Record<string, unknown>; required?: string[] };
}

async function listTools(context: TransportContext): Promise<ListedTool[]> {
  const server = buildOrcelServer(fakeKernel(), "default", context);
  const transport = new MemoryTransport();
  await server.connect(transport as never);
  await transport.request(1, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "browser-full-test", version: "1" }
  });
  transport.notify("notifications/initialized");
  const listed = await transport.request(2, "tools/list", {});
  await server.close();
  return (listed.result as { tools: ListedTool[] }).tools;
}

test("local discovery under browser_full lists the broker forms of the shared names", async () => {
  for (const transportKind of ["stdio", "loopback_http"] as const) {
    const tools = await listTools({ transportKind, providerKind: "generic", toolSurfaceProfile: "browser_full" });
    assert.deepEqual(tools.map((t) => t.name).sort(), [...DESKTOP_STRUCTURED_TOOLS, ...BROWSER_FULL_TOOLS].sort(), transportKind);
    for (const tool of tools) {
      const entry = contractEntryFor(tool.name, "browser_full");
      assert.ok(entry, tool.name);
      assert.equal(tool.title, entry.annotations.title, tool.name);
      assert.deepEqual(tool.annotations, { ...entry.annotations }, tool.name);
    }
    for (const tool of tools.filter((t) => BROWSER_FULL_TOOLS.includes(t.name))) {
      const properties = Object.keys(tool.inputSchema?.properties ?? {});
      assert.equal(properties.includes("page_id"), false, tool.name);
      assert.equal(properties.includes("session_id"), tool.name !== "browser_session_create", tool.name);
    }
    for (const name of ["browser_page_open", "browser_navigate", "browser_observe", "browser_enter", "browser_check", "browser_download"]) {
      assert.equal(tools.some((t) => t.name === name), false, name);
    }
  }
  // browser_structured keeps its own forms and gains no broker tool.
  const structured = await listTools({ transportKind: "stdio", providerKind: "generic", toolSurfaceProfile: "browser_structured" });
  assert.deepEqual(structured.map((t) => t.name).sort(), [...DESKTOP_STRUCTURED_TOOLS, ...LIVE_BROWSER_TOOLS].sort());
  const click = structured.find((t) => t.name === "browser_click");
  assert.ok(Object.keys(click?.inputSchema?.properties ?? {}).includes("page_id"));
  assert.equal(Object.keys(click?.inputSchema?.properties ?? {}).includes("session_id"), false);
});

test("each broker tool forwards exactly its broker shape and only its own fields", async () => {
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
  registerSessionBrokerTools(server, kernel, "default");
  assert.deepEqual([...handlers.keys()], [...BROWSER_FULL_TOOLS]);
  const args: Record<string, Record<string, unknown>> = {
    browser_session_create: { task: "fixture form" },
    browser_open: { session_id: SESSION, url: "https://example.org/" },
    browser_snapshot: { session_id: SESSION },
    browser_click: { session_id: SESSION, node_id: "d1-e2", expected_generation: 1 },
    browser_fill: { session_id: SESSION, node_id: "d1-e2", value: "Ada", expected_generation: 1 },
    browser_select: { session_id: SESSION, node_id: "d1-e3", option: "Porto", expected_generation: 1 },
    browser_verify: { session_id: SESSION, checks: [{ kind: "url_is", url: "https://example.org/done" }], expected_generation: 1 },
    browser_extract: { session_id: SESSION, expected_generation: 1 },
    browser_close: { session_id: SESSION },
    browser_task_status: { session_id: SESSION }
  };
  for (const tool of BROWSER_FULL_TOOLS) {
    sent.length = 0;
    const handler = handlers.get(tool);
    assert.ok(handler, tool);
    await handler({ workspace_id: "default", ...args[tool], page_id: "pg-a1", profile: "Default", selector: "#x" });
    assert.equal(sent.length, 1, tool);
    const entry = BROWSER_FULL_CONTRACT[tool];
    assert.equal(`${sent[0]?.capability}/${sent[0]?.operation}`, `${entry?.capability}/${entry?.operation}`, tool);
    assert.deepEqual(sent[0]?.arguments, args[tool], tool);
  }
  // Without a task, create sends nothing at all.
  sent.length = 0;
  await handlers.get("browser_session_create")?.({ workspace_id: "default" });
  assert.deepEqual(sent[0]?.arguments, {});
});

test("the broker schemas are strict and take a broker session id", () => {
  const ok: Array<[string, { safeParse: (v: unknown) => { success: boolean } }, Record<string, unknown>]> = [
    ["create", browserSessionCreateSchema("default"), {}],
    ["create task", browserSessionCreateSchema("default"), { task: "Book a table" }],
    ["session", browserSessionSchema("default"), { session_id: SESSION }],
    ["open", browserOpenSchema("default"), { session_id: SESSION, url: "https://example.org/" }],
    ["click", browserSessionClickSchema("default"), { session_id: SESSION, node_id: "d1-e2", expected_generation: 0 }],
    ["fill", browserSessionFillSchema("default"), { session_id: SESSION, node_id: "d1-e2", value: "Ada", expected_generation: 0 }],
    ["select", browserSessionSelectSchema("default"), { session_id: SESSION, node_id: "d1-e2", option: "A", expected_generation: 0 }],
    ["verify", browserSessionVerifySchema("default"), { session_id: SESSION, checks: [{ kind: "element_visible", node_id: "d1" }], expected_generation: 0 }],
    ["extract", browserExtractSchema("default"), { session_id: SESSION, expected_generation: 0 }]
  ];
  for (const [name, schema, value] of ok) {
    assert.equal(schema.safeParse(value).success, true, name);
    assert.equal(schema.safeParse({ ...value, page_id: "pg-a1" }).success, false, `${name} refuses page_id`);
    assert.equal(schema.safeParse({ ...value, profile_root: "C:\\Users" }).success, false, `${name} refuses a profile`);
  }
  for (const bad of ["", "bs-", "pg-0123456789abcdef-1-0001020304050607", "bs-0123456789ABCDEF-1-0001020304050607", "bs-0123456789abcdef-0-0001020304050607", `${SESSION}-x`]) {
    assert.equal(browserSessionSchema("default").safeParse({ session_id: bad }).success, false, bad);
  }
  assert.equal(browserOpenSchema("default").safeParse({ session_id: SESSION, url: "http://example.org/" }).success, false);
  assert.equal(browserSessionCreateSchema("default").safeParse({ task: "a\nb" }).success, false);
  assert.equal(browserSessionCreateSchema("default").safeParse({ task: "x".repeat(65) }).success, false);
  assert.equal(browserSessionFillSchema("default").safeParse({ session_id: SESSION, node_id: "d1", value: "a\u0007", expected_generation: 0 }).success, false);
  assert.equal(browserSessionVerifySchema("default").safeParse({ session_id: SESSION, checks: [], expected_generation: 0 }).success, false);
  assert.equal(browserExtractSchema("default").safeParse({ session_id: SESSION, expected_generation: 0, schema: {} }).success, false);
});

test("the contract document lists the browser_full profile and its broker tools", () => {
  const doc = readFileSync(join(repo, "docs", "p16", "TOOL_CONTRACT.md"), "utf8");
  const yes = (value: boolean): string => (value ? "yes" : "no");
  assert.ok(doc.includes("## browser_full (SG-000135, local only)"));
  assert.ok(doc.includes(`It holds ${String(profileTools("browser_full").size)} tools`));
  for (const [name, e] of Object.entries(BROWSER_FULL_CONTRACT)) {
    const a = e.annotations;
    const row = `| \`${name}\` | \`${e.capability}/${e.operation}\` | ${e.effect} | ${e.approval} | local-only | ${yes(a.readOnlyHint)} | ${yes(a.destructiveHint)} | ${yes(a.idempotentHint)} | ${yes(a.openWorldHint)} | ${e.outputBound} |`;
    assert.ok(doc.includes(row), `${name} row is current`);
  }
});
