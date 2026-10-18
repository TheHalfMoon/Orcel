#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
const tracked = git("ls-files", "-z").split("\0").filter(Boolean);
const supersededUnqualified = /Quntal|QUNTAL|quntal/;

const historicalContentAllowed = (path) =>
  path === "docs/identity/QUNTAL_RENAME.md" ||
  path === "docs/identity/ORCEL_RENAME.md" ||
  path === "docs/identity/ORCEL_HISTORY_DESKAL.md" ||
  path === "docs/identity/ORCEL_HISTORY_QDRAL.md" ||
  path === "docs/canonical/CURRENT.md" ||
  path === "docs/p16/sg000066_exit_evidence.json" ||
  path === ".specgrain/canonical-evidence.json" ||
  path === ".specgrain/ledger.json" ||
  path === "scripts/check-current-identity.mjs" ||
  (path.startsWith(".specgrain/specs/") && path !== ".specgrain/specs/SG-000067.json");

const isBinary = (bytes) => bytes.subarray(0, Math.min(bytes.length, 8192)).includes(0);

const historicalTokensAllowed = new Map([
  [
    "apps/orcel-mcp/src/p16-exit.test.ts",
    [
      '"quntal-p16-exit-evidence/2"',
      "/^apps\\/quntal-mcp\\//",
      "/^crates\\/quntald\\//"
    ]
  ]
]);

const withoutAllowedTokens = (path, text) => {
  let remaining = text;
  for (const token of historicalTokensAllowed.get(path) ?? []) {
    remaining = remaining.split(token).join("");
  }
  return remaining;
};

const pathResidue = tracked.filter(
  (path) => path !== "docs/identity/QUNTAL_RENAME.md" && supersededUnqualified.test(path)
);
if (pathResidue.length) {
  throw new Error(`superseded identity remains in current paths:\n${pathResidue.join("\n")}`);
}

// Also reject every previous product name in active runtime paths and source.
// Dated donor/architecture assertions must continue to match the frozen evidence.
const oldProductName = /cotra|deskal|aladdin|qdral|quntal/i;
const historicalFilenameExceptions = new Set([
  "docs/identity/QUNTAL_RENAME.md",
  "docs/identity/ORCEL_HISTORY_DESKAL.md",
  "docs/identity/ORCEL_HISTORY_QDRAL.md"
]);
const staleActiveFilenames = tracked.filter(
  (path) => oldProductName.test(path) && !historicalFilenameExceptions.has(path)
);
if (staleActiveFilenames.length) {
  throw new Error(`former product name in maintained file paths:\n${staleActiveFilenames.join("\n")}`);
}
const historicalAssertions = new Set([
  "apps/orcel-mcp/src/p16-exit.test.ts",
  "apps/orcel-mcp/src/p20-architecture.test.ts",
  "apps/web/tests/p19-exit.test.mjs",
  "apps/web/tests/site.test.mjs"
]);
const runtimePaths = tracked.filter(
  (path) => /^(apps|crates|distribution|examples|\.github)\//.test(path) && !historicalAssertions.has(path)
);
for (const path of runtimePaths) {
  const bytes = readFileSync(path);
  if (!isBinary(bytes) && oldProductName.test(bytes.toString("utf8"))) {
    throw new Error(`former product name in current source: ${path}`);
  }
}

const contentResidue = [];
for (const path of tracked) {
  if (historicalContentAllowed(path)) continue;
  const bytes = readFileSync(path);
  if (isBinary(bytes)) continue;
  if (supersededUnqualified.test(withoutAllowedTokens(path, bytes.toString("utf8")))) {
    contentResidue.push(path);
  }
}
if (contentResidue.length) {
  throw new Error(`superseded identity remains outside the historical allowlist:\n${contentResidue.join("\n")}`);
}

for (const required of [
  "apps/orcel-mcp/package.json",
  "apps/orcel-relay/package.json",
  "crates/orceld/Cargo.toml",
  "crates/orcel-lifecycle/Cargo.toml",
  "docs/identity/ORCEL_RENAME.md",
  "docs/identity/ORCEL_HISTORY_DESKAL.md",
  "docs/identity/ORCEL_HISTORY_QDRAL.md",
  ".specgrain/specs/SG-000067.json"
]) {
  if (!existsSync(required)) throw new Error(`missing required Orcel or compatibility path: ${required}`);
}

for (const forbidden of [
  "apps/quntal-mcp",
  "apps/quntal-relay",
  "crates/quntald",
  "crates/quntal-lifecycle"
]) {
  if (existsSync(forbidden)) throw new Error(`superseded project-owned path still exists: ${forbidden}`);
}

const rootPackage = JSON.parse(readFileSync("package.json", "utf8"));
if (rootPackage.name !== "orcel") {
  throw new Error(`root npm package is ${rootPackage.name}, expected orcel`);
}

const workspaces = [...(rootPackage.workspaces ?? [])].sort();
const expectedWorkspaces = ["apps/orcel-mcp", "apps/orcel-relay"].sort();
if (JSON.stringify(workspaces) !== JSON.stringify(expectedWorkspaces)) {
  throw new Error(`unexpected compatibility npm workspaces: ${JSON.stringify(workspaces)}`);
}

for (const [path, expected] of [
  ["apps/orcel-mcp/package.json", "@orcel/mcp"],
  ["apps/orcel-relay/package.json", "@orcel/relay"]
]) {
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  if (manifest.name !== expected) {
    throw new Error(`${path} compatibility name is ${manifest.name}, expected ${expected}`);
  }
}

const cargoRoot = readFileSync("Cargo.toml", "utf8");
if (!cargoRoot.includes('repository = "https://github.com/TheHalfMoon/Orcel"')) {
  throw new Error("Cargo workspace repository is not TheHalfMoon/Orcel");
}

if (supersededUnqualified.test(readFileSync(".specgrain/specs/SG-000067.json", "utf8"))) {
  throw new Error("active SG-000067 still contains the superseded Quntal identity");
}

const identity = readFileSync("docs/identity/ORCEL_RENAME.md", "utf8");
for (const expected of [
  "Status: ACTIVE PRODUCT IDENTITY",
  "Product: `Orcel`",
  "Root package: `orcel`",
  "Public plugin name: `orcel`",
  "CLI command: `orcel`",
  "Local daemon: `orceld`",
  "MCP package: `@orcel/mcp`",
  "Relay package: `@orcel/relay`",
  "Environment-variable prefix: `ORCEL_`",
  "OAuth scope prefix: `orcel.`",
  "Repository identity: `TheHalfMoon/Orcel`"
]) {
  if (!identity.includes(expected)) throw new Error(`Orcel identity record is missing: ${expected}`);
}

// Active governance notices must never call Orcel a superseded identity.
// Historical ledgers below the CURRENT separator remain immutable evidence.
const activeFrontier = readFileSync("docs/canonical/CURRENT.md", "utf8").split("\n---\n")[0];
const planningIdentity = readFileSync("docs/canonical/PLANNING_INDEX.md", "utf8").split("## 2. Planning precedence")[0];
for (const [name, notice] of [["CURRENT", activeFrontier], ["PLANNING_INDEX", planningIdentity]]) {
  if (!notice.includes("Orcel is the sole current product and repository identity")) {
    throw new Error(`${name} must identify Orcel as the sole current product`);
  }
  if (/Orcel and Cotra are superseded|Orcel, .*?are superseded/i.test(notice)) {
    throw new Error(`${name} incorrectly lists Orcel as a superseded product`);
  }
}

const readme = readFileSync("README.md", "utf8");
if (!readme.startsWith("# Orcel\n")) {
  throw new Error("README does not present Orcel as the current product name");
}

const marketplace = JSON.parse(readFileSync(".agents/plugins/marketplace.json", "utf8"));
if (marketplace.name !== "orcel" || marketplace.interface?.displayName !== "Orcel") {
  throw new Error("plugin marketplace does not present Orcel as the current product identity");
}

const codexPlugin = JSON.parse(readFileSync("distribution/codex/orcel/plugin.json", "utf8"));
if (codexPlugin.name !== "orcel" || codexPlugin.extensions?.["com.openai"]?.interface?.displayName !== "Orcel") {
  throw new Error("Codex plugin does not present Orcel as the current product identity");
}

const openaiPlugin = JSON.parse(readFileSync("distribution/openai/plugin.config.json", "utf8"));
if (openaiPlugin.name !== "orcel" || openaiPlugin.displayName !== "Orcel") {
  throw new Error("OpenAI plugin does not present Orcel as the current product identity");
}

execFileSync(process.execPath, ["scripts/sync-brand.mjs", "--check"], { encoding: "utf8" });
console.log(`Orcel identity validated across ${tracked.length} tracked files with orcel compatibility identifiers preserved, including synchronized nested monogram assets.`);
