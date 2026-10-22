import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CANONICAL_TOOL_NAMES } from "./server.js";
import { LIVE_BROWSER_TOOLS, TOOL_CONTRACT } from "./tool_contract.js";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..", "..");

const BROWSER_SHAPES = [
  "browser.profile/status",
  "browser.destination/validate",
  "browser.page/open",
  "browser.navigation/preview",
  "browser.navigation/navigate",
  "browser.snapshot/observe",
  "browser.dom/click",
  "browser.dom/fill",
  "browser.download/preview",
  "browser.download/download",
  "browser.upload/preview",
  "browser.upload/submit"
];

function nonTestRust(dir: string): Array<[string, string]> {
  return readdirSync(dir)
    .filter((name) => name.endsWith(".rs") && !name.includes("test"))
    .map((name) => [name, readFileSync(join(dir, name), "utf8")] as [string, string]);
}

test("the only MCP tools that claim browser capability are the governed live tools", () => {
  // SG-000108 slice 3c: exactly the live browser tools, each local-only.
  for (const tool of CANONICAL_TOOL_NAMES) {
    const browser = tool.startsWith("browser") || (TOOL_CONTRACT[tool]?.capability ?? "").startsWith("browser.");
    assert.equal(browser, LIVE_BROWSER_TOOLS.includes(tool), tool);
  }
  for (const tool of LIVE_BROWSER_TOOLS) {
    assert.equal(TOOL_CONTRACT[tool]?.remote, "local_only", tool);
  }
});

test("the structured browser layer launches, attaches, and connects to nothing outside tests", () => {
  const sources = [
    ...nonTestRust(join(repo, "crates", "orcel-provider-browser", "src")),
    ["orceld/browser.rs", readFileSync(join(repo, "crates", "orceld", "src", "browser.rs"), "utf8")] as [string, string]
  ];
  for (const [name, text] of sources) {
    const production = text.split("#[cfg(test)]")[0] ?? text;
    for (const forbidden of ["Command::new", "CreateProcess", "WebSocket", "TcpStream", "remote-debugging", "msedge", "chrome.exe", "UdpSocket"]) {
      assert.ok(!production.includes(forbidden), `${name} must not reference ${forbidden}`);
    }
  }
});

test("every structured browser shape is recorded as live (SG-000108) or model-only and denied", () => {
  const doc = readFileSync(join(repo, "docs", "p16", "BROWSER_QUALIFICATION.md"), "utf8");
  const inventory = JSON.parse(readFileSync(join(repo, "docs", "p16", "capability_parity_inventory.json"), "utf8")) as {
    capabilities: Array<{ capability: string; operation: string; status: string; reason?: string }>;
    workflows: Array<{ id: string; status: string; owner_grain?: string }>;
  };
  const liveShapes = new Map(LIVE_BROWSER_TOOLS.map((tool) => [`${TOOL_CONTRACT[tool]?.capability}/${TOOL_CONTRACT[tool]?.operation}`, tool]));
  assert.equal(liveShapes.size, 6);
  for (const shape of BROWSER_SHAPES) {
    const [capability, operation] = shape.split("/");
    const entry = inventory.capabilities.find((c) => c.capability === capability && c.operation === operation) as
      | { status: string; reason?: string; mcp_tool?: string }
      | undefined;
    const tool = liveShapes.get(shape);
    if (tool !== undefined) {
      assert.ok(doc.includes(`| \`${shape}\` | live (SG-000108) | \`${tool}\``), shape);
      assert.equal(entry?.status, "implemented_exposed", shape);
      assert.equal(entry?.mcp_tool, tool, shape);
    } else {
      assert.ok(doc.includes(`| \`${shape}\` | model-only`), shape);
      assert.equal(entry?.status, "intentionally_denied", shape);
      assert.ok((entry?.reason ?? "").includes("model-only"), shape);
    }
  }
  for (const shape of liveShapes.keys()) {
    assert.ok(BROWSER_SHAPES.includes(shape), `${shape} is one of the twelve qualified shapes`);
  }
  const workflow = inventory.workflows.find((w) => w.id === "browser_structured");
  assert.equal(workflow?.status, "implemented_exposed");
  assert.equal(workflow?.owner_grain, "SG-000108");
});
