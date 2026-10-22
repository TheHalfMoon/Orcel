import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { KernelClient } from "./kernel.js";
import { LOCAL_ONLY_TOOL_NAMES, OAUTH_PROFILE_TOOL_CEILINGS, OAUTH_SCOPE_TOOL_MATRIX, authorizeToolByScopes } from "./oauth_authorization.js";
import { CANONICAL_TOOL_NAMES, allowedToolsFor, buildOrcelServer, defaultTransportContext, type TransportContext } from "./server.js";
import {
  REMOTE_PROVIDER_PROFILES,
  REMOTE_TOOL_NAMES,
  SURFACE_PROFILES,
  TOOL_CONTRACT,
  profileTools,
  remoteProfileForProvider
} from "./tool_contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");

const CORE = [
  "fs_edit", "fs_find", "fs_list", "fs_mkdir", "fs_move", "fs_read", "fs_read_range", "fs_remove", "fs_search",
  "fs_stat", "fs_write", "fs_write_preview", "git_branch_create", "git_commit", "git_diff", "git_fetch",
  "git_fetch_preview", "git_log", "git_push", "git_push_preview", "git_stage", "git_status", "git_unstage",
  "process_spawn", "system_status", "workspace_get"
];
const LOCAL_ONLY = [
  "clipboard_read",
  "clipboard_write",
  "desktop_cursor_get",
  "desktop_element_invoke",
  "desktop_element_scroll",
  "desktop_element_select",
  "desktop_element_set_value",
  "desktop_element_toggle",
  "desktop_input_execute",
  "desktop_window_action",
  "desktop_window_capture",
  "desktop_window_list",
  "desktop_window_tree",
  "web_fetch",
  "web_search"
];
// SG-000108 slice 3c: the live browser tools, local-only and served only
// under browser_structured.
const LIVE = [
  "browser_click",
  "browser_download",
  "browser_download_preview",
  "browser_navigate",
  "browser_observe",
  "browser_page_open"
];

function fakeKernel(): KernelClient {
  return {
    sessionId: "contract-test",
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
}

async function listTools(context: TransportContext): Promise<ListedTool[]> {
  const server = buildOrcelServer(fakeKernel(), "default", context);
  const transport = new MemoryTransport();
  await server.connect(transport as never);
  await transport.request(1, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "contract-test", version: "1" }
  });
  transport.notify("notifications/initialized");
  const listed = await transport.request(2, "tools/list", {});
  await server.close();
  return (listed.result as { tools: ListedTool[] }).tools;
}

test("every canonical tool has exactly one contract entry", () => {
  assert.deepEqual(Object.keys(TOOL_CONTRACT).sort(), [...CANONICAL_TOOL_NAMES].sort());
  assert.deepEqual([...REMOTE_TOOL_NAMES].sort(), CORE);
  assert.deepEqual([...LOCAL_ONLY_TOOL_NAMES].sort(), [...LIVE, ...LOCAL_ONLY].sort());
  const titles = Object.values(TOOL_CONTRACT).map((entry) => entry.annotations.title);
  assert.equal(new Set(titles).size, titles.length, "titles are unique");
  for (const [name, entry] of Object.entries(TOOL_CONTRACT)) {
    assert.ok(entry.annotations.title.length > 0, name);
    assert.ok(entry.outputBound.length > 0, `${name} states an output bound`);
  }
});

test("the contract module is metadata only and can reach no kernel", () => {
  const source = readFileSync(join(here, "..", "src", "tool_contract.ts"), "utf8");
  assert.doesNotMatch(source, /kernel|KernelClient|\.call\(|registerTool|import \{/);
  assert.match(source, /^import type \{ OAuthScope \} from "\.\/oauth_authorization\.js";$/m);
});

test("each contract entry names the kernel shape its tool actually sends", () => {
  const inventory = JSON.parse(
    readFileSync(join(repo, "docs", "p16", "capability_parity_inventory.json"), "utf8")
  ) as { capabilities: Array<{ capability: string; operation: string; status: string; mcp_tool?: string }> };
  for (const [name, entry] of Object.entries(TOOL_CONTRACT)) {
    const recorded = inventory.capabilities.find((c) => c.mcp_tool === name);
    assert.ok(recorded, `${name} is in the parity inventory`);
    assert.equal(recorded.status, "implemented_exposed", name);
    assert.equal(`${recorded.capability}/${recorded.operation}`, `${entry.capability}/${entry.operation}`, name);
  }
});

test("annotations, effect classes, and approval classes are mutually consistent", () => {
  const strong: string[] = [];
  for (const [name, entry] of Object.entries(TOOL_CONTRACT)) {
    const a = entry.annotations;
    if (["read", "preview", "desktop_observe", "desktop_capture"].includes(entry.effect)) {
      assert.equal(a.readOnlyHint, true, `${name} observes only`);
    }
    if (["write", "destructive", "execute", "desktop_control"].includes(entry.effect)) {
      assert.equal(a.readOnlyHint, false, `${name} changes state`);
    }
    if (a.readOnlyHint) {
      assert.equal(a.destructiveHint, false, `${name} cannot be read-only and destructive`);
    }
    if (entry.effect === "destructive" || entry.effect === "execute" || entry.effect === "desktop_control") {
      assert.equal(a.destructiveHint, true, `${name} must declare destructive effects`);
    }
    if (entry.effect === "network" || entry.effect === "execute") {
      assert.equal(a.openWorldHint, true, `${name} reaches beyond the machine`);
    }
    if (!["network", "execute"].includes(entry.effect)) {
      assert.equal(a.openWorldHint, false, `${name} is closed-world`);
    }
    assert.equal(
      entry.approval === "none",
      ["read", "preview", "desktop_observe"].includes(entry.effect),
      `${name}: approval is required exactly for effects beyond observation`
    );
    if (entry.approval === "STRONG") {
      strong.push(name);
    }
  }
  assert.deepEqual(strong, ["fs_remove"]);
  // The orceld source requests STRONG presence for fs.remove.
  const fsMutation = readFileSync(join(repo, "crates", "orceld", "src", "fs_mutation.rs"), "utf8");
  assert.match(fsMutation, /new_strong/);
});

test("the contract's remote scopes equal the orceld remote-session scope table", () => {
  const rust = readFileSync(join(repo, "crates", "orcel-policy", "src", "remote_session.rs"), "utf8");
  const start = rust.indexOf("pub fn required_scopes");
  const body = rust.slice(start, rust.indexOf("_ => return None", start));
  const mapped = new Map<string, string>();
  let pending: string[] = [];
  for (const match of body.matchAll(/\("([a-z._]+)", "([a-z_]+)"\)|=> (READ|WRITE|EXECUTE)/g)) {
    if (match[3] !== undefined) {
      const scope = { READ: "orcel.read", WRITE: "orcel.write", EXECUTE: "orcel.execute" }[match[3]] ?? "";
      for (const shape of pending) {
        mapped.set(shape, scope);
      }
      pending = [];
    } else {
      pending.push(`${match[1] ?? ""}/${match[2] ?? ""}`);
    }
  }
  assert.equal(mapped.size, CORE.length);
  for (const [name, entry] of Object.entries(TOOL_CONTRACT)) {
    const shape = `${entry.capability}/${entry.operation}`;
    if (entry.remote === "local_only") {
      assert.equal(mapped.has(shape), false, `${name} must have no remote lease scope`);
    } else {
      assert.deepEqual([mapped.get(shape)], [...entry.remote], `${name} remote scope`);
      assert.deepEqual(OAUTH_SCOPE_TOOL_MATRIX[name], [...entry.remote], `${name} OAuth scope`);
    }
  }
  assert.deepEqual(Object.keys(OAUTH_SCOPE_TOOL_MATRIX).sort(), CORE);
  assert.deepEqual([...OAUTH_PROFILE_TOOL_CEILINGS.core ?? []].sort(), CORE);
});

test("profile membership is exact and unmapped profiles fail closed", () => {
  assert.deepEqual(Object.keys(SURFACE_PROFILES).sort(), ["browser_structured", "core", "desktop_structured"]);
  assert.deepEqual([...profileTools("core")].sort(), CORE);
  assert.deepEqual([...profileTools("desktop_structured")].sort(), [...CORE, ...LOCAL_ONLY].sort());
  // SG-000108: browser_structured adds exactly the live browser tools.
  assert.deepEqual([...profileTools("browser_structured")].sort(), [...CORE, ...LOCAL_ONLY, ...LIVE].sort());
  for (const profile of ["developer", "coordinate_fallback", "admin", "", "__proto__", "constructor"]) {
    assert.throws(() => profileTools(profile), /not mapped/, profile);
  }
  for (const tool of [...LOCAL_ONLY, ...LIVE]) {
    const all = ["orcel.read", "orcel.write", "orcel.execute"];
    assert.equal(authorizeToolByScopes(tool, "core", all, all).ok, false, tool);
  }
});

test("provider-specific mappings are explicit and unknown providers deny", () => {
  assert.deepEqual(REMOTE_PROVIDER_PROFILES, {
    generic: "core",
    openai: "core",
    anthropic: "core",
    mistral: "core",
    codex: "core"
  });
  for (const provider of ["unknown", "", "__proto__", "toString", "OpenAI"]) {
    assert.equal(remoteProfileForProvider(provider), null, provider);
    assert.throws(
      () => allowedToolsFor({ transportKind: "relay", providerKind: provider, toolSurfaceProfile: "core" }),
      /TOOL_SURFACE_DENIED/
    );
  }
  assert.throws(
    () => allowedToolsFor({ transportKind: "relay", providerKind: "generic", toolSurfaceProfile: "desktop_structured" }),
    /TOOL_SURFACE_DENIED/
  );
});

test("local discovery lists the full local profile with contract annotations", async () => {
  for (const transportKind of ["stdio", "loopback_http"] as const) {
    const tools = await listTools({ ...defaultTransportContext(), transportKind });
    assert.deepEqual(tools.map((t) => t.name).sort(), [...CORE, ...LOCAL_ONLY].sort(), transportKind);
    for (const tool of tools) {
      const entry = TOOL_CONTRACT[tool.name];
      assert.ok(entry, tool.name);
      assert.equal(tool.title, entry.annotations.title, tool.name);
      assert.deepEqual(tool.annotations, { ...entry.annotations }, tool.name);
    }
  }
});

test("remote discovery lists only the core profile for every known provider", async () => {
  for (const providerKind of Object.keys(REMOTE_PROVIDER_PROFILES)) {
    const tools = await listTools({ transportKind: "relay", providerKind, toolSurfaceProfile: "core" });
    assert.deepEqual(tools.map((t) => t.name).sort(), CORE, providerKind);
    for (const tool of tools) {
      assert.equal(LOCAL_ONLY.includes(tool.name), false, `${tool.name} must not be advertised remotely`);
    }
  }
});

test("the contract document is generated from the same contract", () => {
  const doc = readFileSync(join(repo, "docs", "p16", "TOOL_CONTRACT.md"), "utf8");
  const yes = (value: boolean): string => (value ? "yes" : "no");
  for (const [name, e] of Object.entries(TOOL_CONTRACT)) {
    const a = e.annotations;
    const remote = e.remote === "local_only" ? "local-only" : e.remote.join(" ");
    const row = `| \`${name}\` | \`${e.capability}/${e.operation}\` | ${e.effect} | ${e.approval} | ${remote} | ${yes(a.readOnlyHint)} | ${yes(a.destructiveHint)} | ${yes(a.idempotentHint)} | ${yes(a.openWorldHint)} | ${e.outputBound} |`;
    assert.ok(doc.includes(row), `${name} row is current`);
  }
  assert.ok(doc.includes(`| \`core\` | relay (remote) | ${SURFACE_PROFILES.core.length} |`));
  assert.ok(doc.includes(`| \`desktop_structured\` | stdio and loopback HTTP (local) | ${SURFACE_PROFILES.desktop_structured.length} |`));
});

test("SG-000071: approvals, scopes, and tool sets are identical for every provider", () => {
  const sets = Object.keys(REMOTE_PROVIDER_PROFILES).map((providerKind) =>
    [...allowedToolsFor({ transportKind: "relay", providerKind, toolSurfaceProfile: "core" })].sort()
  );
  for (const set of sets) {
    assert.deepEqual(set, sets[0]);
  }
  for (const entry of Object.values(TOOL_CONTRACT)) {
    assert.deepEqual(Object.keys(entry).sort(), ["annotations", "approval", "capability", "effect", "operation", "outputBound", "remote"]);
  }
  const rust = readFileSync(join(repo, "crates", "orcel-policy", "src", "sg000019.rs"), "utf8");
  assert.match(rust, /pub fn approval_class_for\(capability: &str, operation: &str\) -> ApprovalClass/);
});
