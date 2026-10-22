import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CANONICAL_TOOL_NAMES } from "./server.js";
import { profileTools } from "./tool_contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const examplesDir = join(here, "..", "..", "..", "examples", "mcp-clients");

function example(name: string): string {
  return readFileSync(join(examplesDir, name), "utf8");
}

function jsonExample(name: string): unknown {
  return JSON.parse(example(name)) as unknown;
}

test("client examples use only supported installed entrypoints", () => {
  const claude = jsonExample("claude-desktop.json") as {
    mcpServers: Record<string, { command: string; args: string[] }>;
  };
  assert.deepEqual(claude.mcpServers.orcel, { command: "orcel", args: ["mcp", "stdio"] });

  // SG-000068: Claude Code project configuration uses the same stdio entrypoint.
  const claudeCode = jsonExample("claude-code.mcp.json") as {
    mcpServers: Record<string, unknown>;
  };
  assert.deepEqual(claudeCode, { mcpServers: { orcel: { type: "stdio", command: "orcel", args: ["mcp", "stdio"] } } });

  const genericStdio = jsonExample("generic-stdio.json") as {
    command: string;
    args: string[];
  };
  assert.deepEqual(genericStdio, { command: "orcel", args: ["mcp", "stdio"] });

  for (const name of ["codex-config.toml", "vibe-code-config.toml"]) {
    const text = example(name);
    assert.ok(text.includes('"orcel"'), `${name} must reference the orcel command`);
    assert.ok(text.includes('"mcp"'), `${name} must use the mcp entrypoint`);
    assert.ok(!text.includes("tunnel_"), `${name} must not contain tunnel material`);
  }

  const manifest = jsonExample("claude-desktop-mcpb-manifest.json") as {
    server: { type: string; mcp_config: { command: string; args: string[] } };
  };
  assert.equal(manifest.server.type, "binary");
  assert.equal(manifest.server.mcp_config.command, "orcel");
  assert.deepEqual(manifest.server.mcp_config.args, ["mcp", "stdio"]);
});

test("client examples carry no secrets and no remote endpoints", () => {
  for (const name of readdirSync(examplesDir).sort()) {
    if (name === "README.md" || name === "inspector.sh") {
      continue;
    }
    const text = example(name);
    assert.ok(!text.includes("tunnel_"), `${name} must not contain tunnel material`);
    assert.ok(!text.includes("BEGIN PRIVATE"), `${name} must not contain key material`);
    assert.ok(!text.includes("0.0.0.0"), `${name} must not reference wildcard binds`);
    if (name !== "claude-desktop-mcpb-manifest.json") {
      assert.ok(!text.includes("https://"), `${name} must not point at remote endpoints`);
    }
  }
  const http = example("vibe-code-config.toml");
  assert.ok(http.includes("127.0.0.1"), "loopback examples must stay on loopback");
  assert.ok(http.includes("PORT"), "loopback examples must force an explicit port choice");
});

test("desktop extension manifest matches the canonical catalog", () => {
  const manifest = jsonExample("claude-desktop-mcpb-manifest.json") as {
    manifest_version: string;
    name: string;
    version: string;
    author: { name: string };
    server: { type: string; entry_point: string };
    tools: Array<{ name: string }>;
    compatibility: { platforms: string[] };
  };
  assert.equal(manifest.manifest_version, "0.3");
  assert.equal(manifest.name, "orcel");
  assert.equal(manifest.server.type, "binary");
  const pkg = JSON.parse(
    readFileSync(join(here, "..", "package.json"), "utf8")
  ) as { version: string };
  assert.equal(manifest.version, pkg.version);
  assert.ok(manifest.author.name.length > 0);
  assert.deepEqual(manifest.compatibility.platforms, ["win32"]);
  // The extension serves the default local profile, desktop_structured;
  // the live browser tools (browser_structured) are never advertised there.
  assert.deepEqual(
    manifest.tools.map((tool) => tool.name).sort(),
    [...profileTools("desktop_structured")].sort()
  );
  assert.ok(manifest.tools.every((tool) => CANONICAL_TOOL_NAMES.includes(tool.name)));
});

test("SG-000068: Claude directory and account states are never promoted by software", () => {
  const state = JSON.parse(
    readFileSync(join(here, "..", "..", "..", "distribution", "claude", "distribution-state.json"), "utf8")
  ) as { provider_controlled: string[]; status: Record<string, { state: string; evidence: unknown }> };
  assert.deepEqual(state.provider_controlled, ["DIRECTORY_SUBMITTED", "DIRECTORY_LISTED", "ACCOUNT_VERIFIED"]);
  for (const name of state.provider_controlled) {
    const entry = state.status[name];
    assert.ok(entry !== undefined, name);
    if (entry.state !== "NOT_OBSERVED") {
      assert.ok(entry.evidence !== null && typeof entry.evidence === "object", `${name} needs observed Anthropic evidence`);
    }
  }
});

test("SG-000069: Vibe Code examples use the canonical entrypoint and the loopback bearer contract", () => {
  const text = example("vibe-code-config.toml");
  const stdio = text.split("\n").filter((line) => !line.startsWith("#")).join("\n");
  for (const line of ['name = "orcel"', 'transport = "stdio"', 'command = "orcel"', 'args = ["mcp", "stdio"]']) {
    assert.ok(stdio.includes(line), line);
  }
  for (const line of [
    '# transport = "streamable-http"',
    '# url = "http://127.0.0.1:PORT/mcp"',
    '# api_key_env = "ORCEL_LOOPBACK_TOKEN"',
    '# api_key_header = "Authorization"',
    '# api_key_format = "Bearer {token}"'
  ]) {
    assert.ok(text.includes(line), line);
  }
  assert.doesNotMatch(text, /https:\/\//, "Vibe Code has no remote relay path");
  assert.doesNotMatch(text, /api_key\s*=|token\s*=\s*"[^{]/, "no literal credential");
});

test("SG-000069: Mistral directory and account states are never promoted by software", () => {
  const state = JSON.parse(
    readFileSync(join(here, "..", "..", "..", "distribution", "mistral", "distribution-state.json"), "utf8")
  ) as { provider_controlled: string[]; provider_limitations: string[]; status: Record<string, { state: string; evidence: unknown }> };
  assert.deepEqual(state.provider_controlled, ["DIRECTORY_SUBMITTED", "DIRECTORY_LISTED", "ACCOUNT_VERIFIED"]);
  assert.ok(state.provider_limitations.some((entry) => entry.includes("does not support MCP servers that require OAuth")));
  for (const name of state.provider_controlled) {
    const entry = state.status[name];
    assert.ok(entry !== undefined, name);
    if (entry.state !== "NOT_OBSERVED") {
      assert.ok(entry.evidence !== null && typeof entry.evidence === "object", `${name} needs observed Mistral evidence`);
    }
  }
});
