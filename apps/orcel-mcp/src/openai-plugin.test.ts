import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { discoverTools } from "./discovery.js";
import { buildAuthorizationServerMetadata } from "./oauth_authorization.js";
import {
  buildOpenAIPluginPackage,
  findSecrets,
  isMcpEndpointUrl,
  validateConfig,
  validateOpenAIPluginPackage,
  type OpenAIPluginConfig,
  type PackageFiles
} from "./openai_plugin.js";
import { LOCAL_ONLY_TOOL_NAMES, REMOTE_TOOL_NAMES, securitySchemesFor } from "./tool_contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");
const source = join(repo, "distribution", "openai");
const config = JSON.parse(readFileSync(join(source, "plugin.config.json"), "utf8")) as OpenAIPluginConfig;
const logoSvg = readFileSync(join(source, "assets", "logo.svg"), "utf8");
const reviewFiles = Object.fromEntries(
  readdirSync(join(source, "review")).map((name) => [name, readFileSync(join(source, "review", name), "utf8")])
);
const MCP_URL = "https://relay.orcel.test/mcp";
const pkgVersion = (JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8")) as { version: string }).version;

async function buildPackage(): Promise<PackageFiles> {
  const tools = await discoverTools({ transportKind: "relay", providerKind: "openai", toolSurfaceProfile: "core" });
  return buildOpenAIPluginPackage({ config, version: pkgVersion, mcpUrl: MCP_URL, logoSvg, tools, reviewFiles });
}

function mutate(files: PackageFiles, path: string, change: (value: Record<string, unknown>) => void): PackageFiles {
  const parsed = JSON.parse(files[path] ?? "{}") as Record<string, unknown>;
  change(parsed);
  return { ...files, [path]: JSON.stringify(parsed) };
}

test("the Orcel package builds reproducibly from clean source and validates", async () => {
  const first = await buildPackage();
  const second = await buildPackage();
  assert.deepEqual(first, second, "the package is deterministic");
  assert.deepEqual(validateOpenAIPluginPackage(first), []);
  assert.deepEqual(Object.keys(first).sort(), [
    "SHA256SUMS.txt",
    "assets/logo.svg",
    "mcp.json",
    "plugin.json",
    "review/DEMO_RECORDING.md",
    "review/RELEASE_NOTES.md",
    "review/distribution-state.json",
    "review/test-cases.json",
    "review/tool-scan.json"
  ]);
  const mcp = JSON.parse(first["mcp.json"] ?? "") as { mcpServers: Record<string, unknown> };
  assert.deepEqual(mcp.mcpServers, { orcel: { type: "streamable-http", url: MCP_URL } });
  const plugin = JSON.parse(first["plugin.json"] ?? "") as Record<string, unknown>;
  assert.equal(plugin.name, "orcel");
  assert.equal(plugin.license, "Apache-2.0");
  assert.deepEqual(Object.keys(plugin.extensions as object), ["com.openai"]);
});

test("OpenAI-visible tools are exactly the core profile with contract annotations and schemes", async () => {
  const files = await buildPackage();
  const scan = JSON.parse(files["review/tool-scan.json"] ?? "") as { tools: Array<Record<string, unknown>> };
  assert.deepEqual(scan.tools.map((tool) => tool.name).sort(), [...REMOTE_TOOL_NAMES].sort());
  for (const tool of scan.tools) {
    assert.equal(LOCAL_ONLY_TOOL_NAMES.includes(String(tool.name)), false);
    assert.deepEqual(tool.securitySchemes, securitySchemesFor(String(tool.name)));
    assert.equal((tool.securitySchemes as unknown as Array<{ type: string }>).some((scheme) => scheme.type === "noauth"), false);
  }
  for (const local of LOCAL_ONLY_TOOL_NAMES) {
    assert.equal(securitySchemesFor(local), null, `${local} has no remote scheme`);
  }
});

test("tampered packages fail validation", async () => {
  const files = await buildPackage();
  const cases: Array<[string, PackageFiles]> = [
    ["local-only tool", mutate(files, "review/tool-scan.json", (scan) => {
      (scan.tools as unknown[]).push({ name: "clipboard_read", description: "x", annotations: {}, securitySchemes: null });
    })],
    ["missing tool", mutate(files, "review/tool-scan.json", (scan) => {
      (scan.tools as unknown[]).pop();
    })],
    ["weakened annotation", mutate(files, "review/tool-scan.json", (scan) => {
      const tool = (scan.tools as Array<Record<string, unknown>>).find((t) => t.name === "fs_remove");
      (tool!.annotations as Record<string, unknown>).destructiveHint = false;
    })],
    ["anonymous scheme", mutate(files, "review/tool-scan.json", (scan) => {
      const tool = (scan.tools as Array<Record<string, unknown>>)[0];
      tool!.securitySchemes = [{ type: "noauth" }];
    })],
    ["second server", mutate(files, "mcp.json", (mcp) => {
      (mcp.mcpServers as Record<string, unknown>).other = { type: "streamable-http", url: "https://other.test/mcp" };
    })],
    ["http endpoint", mutate(files, "mcp.json", (mcp) => {
      (mcp.mcpServers as Record<string, Record<string, unknown>>).orcel!.url = "http://relay.orcel.test/mcp";
    })],
    ["server headers", mutate(files, "mcp.json", (mcp) => {
      (mcp.mcpServers as Record<string, Record<string, unknown>>).orcel!.headers = { Authorization: "Bearer x" };
    })],
    ["foreign extension", mutate(files, "plugin.json", (plugin) => {
      (plugin.extensions as Record<string, unknown>)["com.example"] = {};
    })],
    ["unexpected top-level field", mutate(files, "plugin.json", (plugin) => {
      plugin.hooks = "./hooks.json";
    })],
    ["escaping asset", mutate(files, "plugin.json", (plugin) => {
      ((plugin.extensions as Record<string, Record<string, Record<string, unknown>>>)["com.openai"]!.interface!).logo = "../logo.svg";
    })],
    ["secret in review", { ...files, "review/RELEASE_NOTES.md": "client_secret=abc" }],
    ["private key", { ...files, "assets/logo.svg": "-----BEGIN PRIVATE KEY-----" }]
  ];
  for (const [label, tampered] of cases) {
    assert.ok(validateOpenAIPluginPackage(tampered).length > 0, label);
  }
});

test("configuration and endpoint validation fail closed", () => {
  assert.deepEqual(validateConfig(config), []);
  for (const url of ["http://relay.test/mcp", "https://relay.test/", "https://user:pw@relay.test/mcp", "https://relay.test/mcp?x=1", "https://localhost/mcp", "https://127.0.0.1/mcp", "", 42]) {
    assert.equal(isMcpEndpointUrl(url), false, String(url));
  }
  assert.equal(isMcpEndpointUrl(MCP_URL), true);
  assert.ok(validateConfig({ ...config, privacyPolicyURL: "http://example.com/privacy" }).length > 0);
  assert.ok(validateConfig({ ...config, supportURL: `https://example.com/${"a".repeat(1100)}` }).length > 0);
  assert.throws(() => buildOpenAIPluginPackage({ config, version: "0.2.0", mcpUrl: "https://relay.test/", logoSvg, tools: [] }));
});

test("listing URLs point at real repository documents and no paid service is required", () => {
  for (const [field, path] of [
    ["privacyPolicyURL", "docs/legal/PRIVACY.md"],
    ["termsOfServiceURL", "docs/legal/TERMS.md"],
    ["securityURL", "SECURITY.md"]
  ] as const) {
    assert.ok(config[field].endsWith(`/blob/main/${path}`), field);
    assert.ok(existsSync(join(repo, path)), path);
  }
  for (const value of Object.values(config).flat()) {
    if (typeof value === "string" && value.startsWith("https://")) {
      assert.equal(new URL(value).hostname, "github.com", `${value} must not require a paid host`);
    }
  }
  const committed = readdirSync(source, { recursive: true }).map(String);
  assert.equal(committed.some((name) => name.endsWith("mcp.json") || name.endsWith("plugin.json")), false, "no endpoint is committed");
});

test("the review bundle has exactly five positive and three negative cases over core tools", () => {
  const cases = JSON.parse(reviewFiles["test-cases.json"] ?? "") as {
    positive: Array<{ id: string; prompt: string; tools: string[]; expected: string }>;
    negative: Array<{ id: string; prompt: string; tools: string[]; expected: string; reason: string }>;
  };
  assert.equal(cases.positive.length, 5);
  assert.equal(cases.negative.length, 3);
  for (const entry of cases.positive) {
    assert.ok(entry.tools.length > 0 && entry.prompt.length > 0 && entry.expected.length > 0, entry.id);
    for (const tool of entry.tools) {
      assert.ok(REMOTE_TOOL_NAMES.includes(tool), `${entry.id} uses ${tool}`);
    }
  }
  for (const entry of cases.negative) {
    assert.deepEqual(entry.tools, [], `${entry.id} must use no tool`);
    assert.ok(entry.reason.length > 20, entry.id);
  }
  for (const [name, text] of Object.entries(reviewFiles)) {
    assert.deepEqual(findSecrets(text), [], name);
  }
});

test("provider-controlled distribution states are never promoted by software", () => {
  const state = JSON.parse(reviewFiles["distribution-state.json"] ?? "") as {
    states: string[];
    provider_controlled: string[];
    status: Record<string, { state: string; evidence?: unknown; blockers?: string[] }>;
  };
  assert.deepEqual(state.states, ["SOFTWARE_READY", "SUBMISSION_READY", "SUBMITTED", "APPROVED", "PUBLISHED", "ACCOUNT_VERIFIED"]);
  assert.deepEqual(state.provider_controlled, ["SUBMITTED", "APPROVED", "PUBLISHED", "ACCOUNT_VERIFIED"]);
  for (const name of state.provider_controlled) {
    const entry = state.status[name];
    assert.ok(entry !== undefined, name);
    if (entry.state !== "NOT_OBSERVED") {
      assert.ok(entry.evidence !== null && typeof entry.evidence === "object", `${name} needs observed provider evidence`);
    }
  }
  const submission = state.status.SUBMISSION_READY;
  if (submission?.state !== "READY") {
    assert.ok((submission?.blockers ?? []).length > 0, "an unready submission names its blockers");
  }
});

test("authorization metadata advertises only what the relay implements", () => {
  const metadata = buildAuthorizationServerMetadata("https://relay.orcel.test");
  assert.equal(metadata.client_id_metadata_document_supported, false);
  assert.equal(metadata.registration_endpoint, "https://relay.orcel.test/oauth/register");
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
});

test("at most one grain is active (or the founder-approved SG-000096/SG-000108 pair) and no later grain is activated ahead of it", () => {
  const dir = join(repo, ".specgrain", "specs");
  const specs = readdirSync(dir).filter((name) => /^SG-\d{6}\.json$/.test(name)).sort();
  const active = specs.filter((name) => (JSON.parse(readFileSync(join(dir, name), "utf8")) as { state: string }).state !== "CLOSED");
  // The only lawful parallel pair is SG-000096 with SG-000108, by the founder
  // decision recorded canonically under issue #290. Remove this pin when
  // either grain closes.
  if (active.length === 2) {
    assert.deepEqual(active, ["SG-000096.json", "SG-000108.json"], `parallel active grains: ${active.join(", ")}`);
    const current = readFileSync(join(repo, "docs", "canonical", "CURRENT.md"), "utf8");
    assert.ok(current.includes("parallel active grain by founder decision of 2026-10-10 (issue #290)"), "the parallel pair requires the recorded founder decision");
    assert.equal(specs[specs.length - 1], "SG-000108.json", "no grain beyond the newest active grain exists");
    return;
  }
  assert.ok(active.length <= 1, `parallel active grains: ${active.join(", ")}`);
  if (active.length === 1) {
    assert.equal(specs[specs.length - 1], active[0], "no grain beyond the active grain exists");
    assert.ok((active[0] ?? "") >= "SG-000067.json", "SG-000067 or its lawful successor is active");
    return;
  }
  // Zero active grains is lawful only at a recorded program exit: the
  // canonical frontier must state the exit and name no active grain.
  const current = readFileSync(join(repo, "docs", "canonical", "CURRENT.md"), "utf8");
  assert.ok(current.includes("ORCEL-P18 is exited"), "zero active grains requires a recorded program exit");
  assert.ok(current.includes("No grain is active"), "zero active grains requires an explicit no-active-grain record");
});
