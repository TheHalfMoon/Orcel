import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import type { McpServer } from "@modelcontextprotocol/server";
import {
  browserExtractSchema,
  browserOpenSchema,
  browserProfileNameArgsSchema,
  browserProfilesSchema,
  browserScreenshotSchema,
  browserTabsSchema,
  browserSessionClickSchema,
  browserSessionCreateSchema,
  browserSessionFillSchema,
  browserSessionSchema,
  browserSessionSelectSchema,
  browserSessionVerifySchema,
  registerSessionBrokerTools
} from "./browser_full.js";
import type { KernelClient, KernelResponse } from "./kernel.js";
import { projectKernelResult, projectScreenshotResult } from "./result.js";
import { OAUTH_PROFILE_TOOL_CEILINGS, OAUTH_SCOPE_TOOL_MATRIX, UNMAPPED_REMOTE_PROFILES, authorizeToolByScopes } from "./oauth_authorization.js";
import { allowedToolsFor, buildOrcelServer, localTransportContext, tunnelTransportContext, type TransportContext } from "./server.js";
import {
  BROWSER_FULL_CONTRACT,
  BROWSER_FULL_TOOLS,
  DESKTOP_STRUCTURED_TOOLS,
  LIVE_BROWSER_TOOLS,
  LOCAL_TOOL_SURFACE_PROFILES,
  REMOTE_BROWSER_FULL_TOOLS,
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
  "browser_screenshot",
  "browser_tabs",
  "browser_close",
  "browser_task_status",
  "browser_profiles",
  "browser_profile_create",
  "browser_profile_delete"
];
const PAGE = "pg-0123456789abcdef0123456789abcdef";

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
  const soft = ["browser_session_create", "browser_open", "browser_click", "browser_fill", "browser_select", "browser_tabs", "browser_profile_create", "browser_profile_delete"];
  for (const [name, entry] of Object.entries(BROWSER_FULL_CONTRACT)) {
    const a = entry.annotations;
    // SG-000135 OB-09: the persistent profile tools stay local-only; the
    // remote-safe tools read with orcel.read and act with orcel.execute.
    const remote = ["browser_profiles", "browser_profile_create", "browser_profile_delete"].includes(name)
      ? "local_only"
      : entry.effect === "read" && name !== "browser_close"
        ? ["orcel.read"]
        : ["orcel.execute"];
    assert.deepEqual(entry.remote, remote, name);
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

test("only local configuration selects the local browser_full profile; a remote path maps only its remote-safe tools", () => {
  assert.equal(localProfileFromConfig("browser_full"), "browser_full");
  assert.deepEqual([...LOCAL_TOOL_SURFACE_PROFILES], ["desktop_structured", "browser_structured", "browser_full"]);
  for (const value of ["Browser_Full", " browser_full", "browser-full", "browser_full "]) {
    assert.throws(() => localProfileFromConfig(value), /TOOL_SURFACE_DENIED/, value);
  }
  const local = localTransportContext({ [TOOL_SURFACE_PROFILE_ENV]: "browser_full" });
  assert.equal(local.toolSurfaceProfile, "browser_full");
  assert.equal(local.transportKind, "stdio");
  // SG-000135 OB-09: browser_full is mapped remotely, separately from core.
  assert.equal((UNMAPPED_REMOTE_PROFILES as readonly string[]).includes("browser_full"), false);
  assert.deepEqual(OAUTH_PROFILE_TOOL_CEILINGS.browser_full, [...REMOTE_BROWSER_FULL_TOOLS]);
  const all = ["orcel.read", "orcel.write", "orcel.execute"];
  for (const provider of Object.keys(REMOTE_PROVIDER_PROFILES)) {
    // Every provider's default stays core, unchanged.
    assert.equal(REMOTE_PROVIDER_PROFILES[provider], "core");
    assert.equal(tunnelTransportContext(provider).toolSurfaceProfile, "core");
    for (const transportKind of ["tunnel", "relay"] as const) {
      const context = { transportKind, providerKind: provider, toolSurfaceProfile: "browser_full" } as const;
      if (provider === "openai" || provider === "generic") {
        // A tunnel or relay route set up for browser_full: the remote-safe broker tools only.
        assert.deepEqual([...allowedToolsFor(context)].sort(), [...REMOTE_BROWSER_FULL_TOOLS].sort());
      } else {
        assert.throws(() => allowedToolsFor(context), /TOOL_SURFACE_DENIED/, provider);
      }
      const served = allowedToolsFor({ transportKind, providerKind: provider, toolSurfaceProfile: "core" });
      for (const tool of BROWSER_FULL_TOOLS) {
        // A core route never serves a broker tool (the shared names are the
        // local-only browser_structured forms, which core never lists).
        assert.equal(served.has(tool), false, `${tool} ${transportKind} ${provider}`);
      }
    }
  }
  for (const tool of BROWSER_FULL_TOOLS) {
    assert.equal(Object.hasOwn(OAUTH_SCOPE_TOOL_MATRIX, tool), false, tool);
    assert.equal(authorizeToolByScopes(tool, "core", all, all).ok, false, tool);
    assert.equal(authorizeToolByScopes(tool, "browser_full", all, all).ok, REMOTE_BROWSER_FULL_TOOLS.includes(tool), tool);
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
      // Only browser_tabs names a page: one of the session's own tabs.
      assert.equal(properties.includes("page_id"), tool.name === "browser_tabs", tool.name);
      const sessionless = ["browser_session_create", "browser_profiles", "browser_profile_create", "browser_profile_delete"];
      assert.equal(properties.includes("session_id"), !sessionless.includes(tool.name), tool.name);
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
    browser_session_create: { task: "fixture form", mode: "visible", profile: "work" },
    browser_open: { session_id: SESSION, url: "https://example.org/" },
    browser_snapshot: { session_id: SESSION },
    browser_click: { session_id: SESSION, node_id: "d1-e2", expected_generation: 1 },
    browser_fill: { session_id: SESSION, node_id: "d1-e2", value: "Ada", expected_generation: 1 },
    browser_select: { session_id: SESSION, node_id: "d1-e3", option: "Porto", expected_generation: 1 },
    browser_verify: { session_id: SESSION, checks: [{ kind: "url_is", url: "https://example.org/done" }], expected_generation: 1 },
    browser_extract: { session_id: SESSION, expected_generation: 1 },
    browser_screenshot: { session_id: SESSION, expected_generation: 1, full_page: true },
    browser_tabs: { session_id: SESSION, action: "switch", page_id: PAGE },
    browser_close: { session_id: SESSION },
    browser_task_status: { session_id: SESSION },
    browser_profiles: {},
    browser_profile_create: { name: "work" },
    browser_profile_delete: { name: "work" }
  };
  for (const tool of BROWSER_FULL_TOOLS) {
    sent.length = 0;
    const handler = handlers.get(tool);
    assert.ok(handler, tool);
    await handler({ workspace_id: "default", page_id: "pg-a1", profile: "Default", path: "C:\\x", selector: "#x", hwnd: 7, ...args[tool] });
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
    ["create visible", browserSessionCreateSchema("default"), { mode: "visible", profile: "work-2" }],
    ["profiles", browserProfilesSchema("default"), {}],
    ["profile name", browserProfileNameArgsSchema("default"), { name: "work" }],
    ["session", browserSessionSchema("default"), { session_id: SESSION }],
    ["open", browserOpenSchema("default"), { session_id: SESSION, url: "https://example.org/" }],
    ["click", browserSessionClickSchema("default"), { session_id: SESSION, node_id: "d1-e2", expected_generation: 0 }],
    ["fill", browserSessionFillSchema("default"), { session_id: SESSION, node_id: "d1-e2", value: "Ada", expected_generation: 0 }],
    ["select", browserSessionSelectSchema("default"), { session_id: SESSION, node_id: "d1-e2", option: "A", expected_generation: 0 }],
    ["verify", browserSessionVerifySchema("default"), { session_id: SESSION, checks: [{ kind: "element_visible", node_id: "d1" }], expected_generation: 0 }],
    ["extract", browserExtractSchema("default"), { session_id: SESSION, expected_generation: 0 }],
    ["screenshot", browserScreenshotSchema("default"), { session_id: SESSION, expected_generation: 0 }],
    ["screenshot full", browserScreenshotSchema("default"), { session_id: SESSION, expected_generation: 0, full_page: true }],
    ["tabs list", browserTabsSchema("default"), { session_id: SESSION, action: "list" }],
    ["tabs new", browserTabsSchema("default"), { session_id: SESSION, action: "new", url: "https://example.org/b" }]
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

test("OB-04: mode is shadow or visible and a profile is a checked name, never a path", () => {
  const create = browserSessionCreateSchema("default");
  for (const value of [{ mode: "headed" }, { mode: "Visible" }, { mode: true }, { profile: "Default" }, { profile: "C:\\Users\\me\\AppData\\Local\\Google\\Chrome\\User Data" }, { profile: "../work" }, { profile: "a/b" }, { profile: "" }, { profile: "-a" }, { profile: "a-" }, { profile: "a".repeat(33) }, { profile_dir: "C:\\x" }]) {
    assert.equal(create.safeParse(value).success, false, JSON.stringify(value));
  }
  const named = browserProfileNameArgsSchema("default");
  for (const value of [{}, { name: "Work" }, { name: "work", path: "C:\\x" }, { name: "a b" }]) {
    assert.equal(named.safeParse(value).success, false, JSON.stringify(value));
  }
  assert.equal(browserProfilesSchema("default").safeParse({ name: "work" }).success, false);
});

test("the contract document lists the browser_full profile and its broker tools", () => {
  const doc = readFileSync(join(repo, "docs", "p16", "TOOL_CONTRACT.md"), "utf8");
  const yes = (value: boolean): string => (value ? "yes" : "no");
  assert.ok(doc.includes("## browser_full (SG-000135; remote-safe tools also remote, OB-09)"));
  assert.ok(doc.includes(`Locally it holds ${String(profileTools("browser_full").size)} tools`));
  assert.ok(doc.includes(`serves only the`) && doc.includes(`${String(REMOTE_BROWSER_FULL_TOOLS.length)} broker tools with remote scopes`));
  for (const [name, e] of Object.entries(BROWSER_FULL_CONTRACT)) {
    const a = e.annotations;
    const remote = e.remote === "local_only" ? "local-only" : e.remote.join(" ");
    const row = `| \`${name}\` | \`${e.capability}/${e.operation}\` | ${e.effect} | ${e.approval} | ${remote} | ${yes(a.readOnlyHint)} | ${yes(a.destructiveHint)} | ${yes(a.idempotentHint)} | ${yes(a.openWorldHint)} | ${e.outputBound} |`;
    assert.ok(doc.includes(row), `${name} row is current`);
  }
});

test("OB-03: the screenshot and tabs schemas are strict and name nothing outside the session", () => {
  const shot = browserScreenshotSchema("default");
  for (const extra of [{ hwnd: 7 }, { window: "Edge" }, { page_id: PAGE }, { clip: { x: 0 } }, { mask: false }, { full_page: "yes" }]) {
    assert.equal(shot.safeParse({ session_id: SESSION, expected_generation: 0, ...extra }).success, false, JSON.stringify(extra));
  }
  const tabs = browserTabsSchema("default");
  for (const value of [
    { session_id: SESSION, action: "switch", page_id: PAGE },
    { session_id: SESSION, action: "close", page_id: PAGE },
    { session_id: SESSION, action: "new" }
  ]) {
    assert.equal(tabs.safeParse(value).success, true, JSON.stringify(value));
  }
  for (const value of [
    { session_id: SESSION, action: "group" },
    { session_id: SESSION, action: "switch" },
    { session_id: SESSION, action: "close", page_id: "pg-a1" },
    { session_id: SESSION, action: "list", page_id: PAGE },
    { session_id: SESSION, action: "switch", page_id: PAGE, url: "https://example.org/" },
    { session_id: SESSION, action: "new", url: "http://example.org/" },
    { session_id: SESSION, action: "new", page_id: PAGE },
    { session_id: SESSION, action: "list", target: "other-session" }
  ]) {
    assert.equal(tabs.safeParse(value).success, false, JSON.stringify(value));
  }
});

test("OB-07: a Needs-you refusal keeps its typed code, and the status lists the waiting page as orceld sent it", async () => {
  const refused = projectKernelResult({
    version: 1,
    request_id: "r",
    ok: false,
    error: { code: "HUMAN_VERIFICATION_REQUIRED", message: "needs_you: await_human_verification (pg-1): the page needs a person to complete a verification; nothing was done" }
  });
  assert.equal(refused.isError, true);
  const error = (JSON.parse(refused.content[0]?.text ?? "{}") as { error: { code: string } }).error;
  assert.equal(error.code, "HUMAN_VERIFICATION_REQUIRED");
  // browser_task_status forwards its shape and returns orceld's needs_you
  // list unchanged (the edge adds and drops nothing).
  const needsYou = [{ page_id: PAGE, kind: "captcha", signals: ["captcha_widget"], reason: "a CAPTCHA or bot check is on the page; Orcel never solves or skips one", clearing: false, handoff: "rerun_in_visible", guidance: "close this session" }];
  const handlers = new Map<string, (args: Record<string, unknown>) => Promise<unknown>>();
  const server = {
    registerTool(name: string, config: { description?: string }, handler: (args: Record<string, unknown>) => Promise<unknown>) {
      if (name === "browser_task_status") {
        assert.match(config.description ?? "", /needs_you/);
        assert.match(config.description ?? "", /HUMAN_VERIFICATION_REQUIRED/);
        assert.match(config.description ?? "", /HUMAN_TAKEOVER/);
      }
      handlers.set(name, handler);
    }
  } as unknown as McpServer;
  const kernel = {
    call: async (input: { capability: string; operation: string }) => {
      assert.equal(`${input.capability}/${input.operation}`, "browser.session/status");
      return { ok: true, result: { session_id: SESSION, page_state: "AWAIT_HUMAN_VERIFICATION", needs_you: needsYou } };
    }
  } as unknown as KernelClient;
  registerSessionBrokerTools(server, kernel, "default");
  const projected = (await handlers.get("browser_task_status")?.({ workspace_id: "default", session_id: SESSION })) as { content: Array<{ text: string }> };
  const body = JSON.parse(projected.content[0]?.text ?? "{}") as { result: { needs_you: unknown; page_state: string } };
  assert.deepEqual(body.result.needs_you, needsYou);
  assert.equal(body.result.page_state, "AWAIT_HUMAN_VERIFICATION");
  // No tool of the profile can clear, solve or take over a challenge.
  assert.ok(!BROWSER_FULL_TOOLS.some((tool) => /captcha|solve|challenge|verification|takeover/.test(tool)));
});

test("OB-03: a screenshot crosses as image content, and a malformed one never does", () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40, 1)]).toString("base64");
  const ok = (result: Record<string, unknown>): KernelResponse => ({ version: 1, request_id: "r", ok: true, result });
  const projected = projectScreenshotResult(ok({ page_id: PAGE, sha256: "ab", width: 1, height: 1, png_base64: png }));
  assert.equal("isError" in projected, false);
  assert.equal(projected.content.length, 2);
  const [text, image] = projected.content;
  assert.deepEqual(image, { type: "image", data: png, mimeType: "image/png" });
  assert.equal(text?.type, "text");
  const body = JSON.parse((text as { text: string }).text) as { result: Record<string, unknown> };
  assert.equal(body.result.png_base64, undefined, "the image is never inside the JSON");
  assert.equal(body.result.sha256, "ab");
  for (const data of [undefined, 7, "", "not base64!", Buffer.from("GIF89a-not-a-png").toString("base64"), "A".repeat(3 * 1024 * 1024)]) {
    const bad = projectScreenshotResult(ok({ png_base64: data }));
    assert.equal("isError" in bad && bad.isError, true, String(data).slice(0, 20));
    assert.equal(bad.content.length, 1);
  }
  const failed = projectScreenshotResult({ version: 1, request_id: "r", ok: false, error: { code: "TARGET_STALE", message: "busy" } });
  assert.equal("isError" in failed && failed.isError, true);
});
