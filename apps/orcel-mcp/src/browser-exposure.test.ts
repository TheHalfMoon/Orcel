import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { attachProfile, buildRequest } from "./kernel.js";
import { UNMAPPED_REMOTE_PROFILES } from "./oauth_authorization.js";
import { localTransportContext } from "./server.js";
import {
  DESKTOP_STRUCTURED_TOOLS,
  LIVE_BROWSER_TOOLS,
  LOCAL_TOOL_SURFACE_PROFILES,
  REMOTE_PROVIDER_PROFILES,
  SURFACE_PROFILES,
  TOOL_CONTRACT,
  TOOL_SURFACE_PROFILE_ENV,
  localProfileFromConfig,
  profileTools
} from "./tool_contract.js";

// SG-000108 decision 6: the live browser exposure tables agree across the
// MCP contract, orceld's profile gate and the browser host's exposure list.

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/**
 * Read a Rust constant that must be written as a plain literal table: its
 * declared type is exactly `type`, it is defined exactly once, and its value
 * holds only string literals (or pairs of them). Anything else (named
 * constants, comments, cfg'd duplicates, another type) fails the test
 * instead of reading as an empty table.
 */
function rustStrings(path: string, constant: string, type: string): string[] {
  const text = readFileSync(join(repo, path), "utf8");
  const definitions = [...text.matchAll(new RegExp(`\\bconst ${constant}\\b`, "g"))];
  assert.equal(definitions.length, 1, `${constant} is defined exactly once in ${path}`);
  const escaped = type.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const declaration = new RegExp(`pub const ${constant}: ${escaped} = (&\\[[^\\]]*\\]);`);
  const match = declaration.exec(text);
  assert.ok(match !== null, `${constant} in ${path} is a literal table of type ${type}`);
  const body = match[1] ?? "";
  const item = String.raw`(?:"[^"\\]*"|\(\s*"[^"\\]*"\s*,\s*"[^"\\]*"\s*,?\s*\))`;
  const literal = new RegExp(String.raw`^&\[\s*(?:${item}\s*(?:,\s*${item}\s*)*,?\s*)?\]$`);
  assert.match(body, literal, `${constant} holds only string literals`);
  return [...body.matchAll(/"([^"]*)"/g)].map((found) => found[1] ?? "");
}

test("the live browser tools agree across the contract, orceld's gate and the host", () => {
  const host = rustStrings("crates/orcel-browser-host/src/exposure.rs", "LIVE_BROWSER_MCP_TOOLS", "&[&str]");
  assert.deepEqual([...host].sort(), [...LIVE_BROWSER_TOOLS].sort());
  // orceld lists shapes as (capability, operation) pairs.
  const flat = rustStrings("crates/orceld/src/profile_gate.rs", "LIVE_BROWSER_SHAPES", "&[(&str, &str)]");
  assert.equal(flat.length % 2, 0);
  const shapes: string[] = [];
  for (let index = 0; index < flat.length; index += 2) {
    shapes.push(`${flat[index]}/${flat[index + 1]}`);
  }
  const contractShapes = LIVE_BROWSER_TOOLS.map((tool) => {
    const entry = TOOL_CONTRACT[tool];
    assert.ok(entry !== undefined, `${tool} has a contract entry`);
    return `${entry.capability}/${entry.operation}`;
  });
  assert.deepEqual(shapes.sort(), contractShapes.sort());
  // Every live tool is local-only.
  for (const tool of LIVE_BROWSER_TOOLS) {
    assert.equal(TOOL_CONTRACT[tool]?.remote, "local_only", tool);
  }
  // Slice 3c: six of SG-000079's qualified shapes, never fill or uploads.
  assert.equal(LIVE_BROWSER_TOOLS.length, 6);
  for (const shape of contractShapes) {
    assert.ok(!["browser.dom/fill", "browser.upload/preview", "browser.upload/submit"].includes(shape), shape);
  }
});

test("desktop_structured is an explicit list that adding a contract tool cannot widen", () => {
  const desktop = new Set(DESKTOP_STRUCTURED_TOOLS);
  assert.equal(desktop.size, DESKTOP_STRUCTURED_TOOLS.length, "no duplicates");
  const nonLive = Object.keys(TOOL_CONTRACT).filter((tool) => !LIVE_BROWSER_TOOLS.includes(tool));
  // Every non-live contract tool is listed, explicitly, and nothing else.
  assert.deepEqual([...desktop].sort(), nonLive.sort());
  for (const tool of LIVE_BROWSER_TOOLS) {
    assert.ok(!desktop.has(tool), tool);
  }
  // A browser tool left out of LIVE_BROWSER_TOOLS must not land here instead.
  for (const tool of DESKTOP_STRUCTURED_TOOLS) {
    assert.ok(!(TOOL_CONTRACT[tool]?.capability ?? "").startsWith("browser."), tool);
  }
  for (const tool of SURFACE_PROFILES.core) {
    assert.ok(desktop.has(tool), `core ${tool} is in desktop_structured`);
  }
  assert.ok(Object.isFrozen(DESKTOP_STRUCTURED_TOOLS));
});

test("browser_structured is desktop_structured plus the live browser tools", () => {
  assert.deepEqual(
    [...profileTools("browser_structured")].sort(),
    [...DESKTOP_STRUCTURED_TOOLS, ...LIVE_BROWSER_TOOLS].sort()
  );
});

test("only local configuration selects the profile, and only a local one", () => {
  assert.equal(localProfileFromConfig(undefined), "desktop_structured");
  assert.equal(localProfileFromConfig(""), "desktop_structured");
  assert.equal(localProfileFromConfig("desktop_structured"), "desktop_structured");
  assert.equal(localProfileFromConfig("browser_structured"), "browser_structured");
  for (const value of ["core", "developer", "coordinate_fallback", "Browser_Structured", "__proto__", " browser_structured"]) {
    assert.throws(() => localProfileFromConfig(value), /TOOL_SURFACE_DENIED/, value);
  }
  assert.deepEqual([...LOCAL_TOOL_SURFACE_PROFILES], ["desktop_structured", "browser_structured"]);
  assert.equal(localTransportContext({}).toolSurfaceProfile, "desktop_structured");
  assert.equal(
    localTransportContext({ [TOOL_SURFACE_PROFILE_ENV]: "browser_structured" }).toolSurfaceProfile,
    "browser_structured"
  );
  assert.equal(localTransportContext({ [TOOL_SURFACE_PROFILE_ENV]: "browser_structured" }).transportKind, "stdio");
  assert.throws(() => localTransportContext({ [TOOL_SURFACE_PROFILE_ENV]: "core" }), /TOOL_SURFACE_DENIED/);
});

test("no remote path maps browser_structured", () => {
  assert.ok((UNMAPPED_REMOTE_PROFILES as readonly string[]).includes("browser_structured"));
  for (const profile of Object.values(REMOTE_PROVIDER_PROFILES)) {
    assert.equal(profile, "core");
  }
});

test("the kernel stamps the local profile on a request, and nothing when unset", () => {
  const base = () =>
    buildRequest({ sessionId: "s", workspaceId: "w", capability: "fs.read", operation: "read" });
  assert.equal("profile" in base(), false);
  assert.equal(attachProfile(base(), null).profile, undefined);
  assert.equal(attachProfile(base(), "browser_structured").profile, "browser_structured");
  const line = JSON.parse(JSON.stringify(attachProfile(base(), "desktop_structured"))) as Record<string, unknown>;
  assert.equal(line.profile, "desktop_structured");
});
