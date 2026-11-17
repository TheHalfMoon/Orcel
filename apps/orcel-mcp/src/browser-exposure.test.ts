import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { attachProfile, buildRequest } from "./kernel.js";
import {
  LOCAL_ONLY_TOOL_NAMES,
  OAUTH_PROFILE_TOOL_CEILINGS,
  OAUTH_SCOPE_TOOL_MATRIX,
  UNMAPPED_REMOTE_PROFILES,
  authorizeToolByScopes
} from "./oauth_authorization.js";
import { allowedToolsFor, localTransportContext, tunnelTransportContext } from "./server.js";
import {
  DESKTOP_STRUCTURED_TOOLS,
  LIVE_BROWSER_TOOLS,
  LOCAL_TOOL_SURFACE_PROFILES,
  REMOTE_PROVIDER_PROFILES,
  REMOTE_TOOL_NAMES,
  SURFACE_PROFILES,
  TOOL_CONTRACT,
  TOOL_SURFACE_PROFILE_ENV,
  localProfileFromConfig,
  profileTools,
  securitySchemesFor
} from "./tool_contract.js";

/** SG-000122 slice A3's tools and the shapes they forward. */
const SG122_A3 = {
  browser_fill: "browser.dom/fill",
  browser_wait_text: "browser.wait/text",
  browser_verify: "browser.verify/check"
} as const;

/** SG-000122 slice A4's tools and the shapes they forward. */
const SG122_A4 = {
  browser_select: "browser.form/select",
  browser_check: "browser.form/check",
  browser_enter: "browser.form/enter"
} as const;

/** Every SG-000122 tool: since slice A4, one for each of the grain's shapes. */
const SG122 = { ...SG122_A3, ...SG122_A4 } as const;

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
  // Slice 3c's six and SG-000122's six (slices A3 and A4); never the
  // uploads or the closed-grain press and select.
  assert.equal(LIVE_BROWSER_TOOLS.length, 12);
  for (const [tool, shape] of Object.entries(SG122)) {
    assert.ok(LIVE_BROWSER_TOOLS.includes(tool), tool);
    assert.ok(shapes.includes(shape), shape);
  }
  for (const shape of contractShapes) {
    assert.ok(
      !["browser.upload/preview", "browser.upload/submit", "browser.dom/press", "browser.dom/select"].includes(shape),
      shape
    );
  }
  // Every live form shape of orceld's policy has its MCP tool now, so no
  // live shape is reachable without one: orceld's gate keeps no second
  // table, and the policy's table is exactly the grain's six tools' shapes.
  const gate = readFileSync(join(repo, "crates/orceld/src/profile_gate.rs"), "utf8");
  assert.doesNotMatch(gate, /\bconst LIVE_FORM_SHAPES\b/);
  const forms = rustStrings("crates/orcel-policy/src/live_browser.rs", "LIVE_FORM_SHAPES", "&[(&str, &str)]");
  const formShapes: string[] = [];
  for (let index = 0; index < forms.length; index += 2) {
    formShapes.push(`${forms[index]}/${forms[index + 1]}`);
  }
  assert.deepEqual(formShapes.sort(), Object.values(SG122).sort());
  for (const shape of formShapes) {
    assert.ok(shapes.includes(shape), shape);
  }
});

test("SG-000122 slices A3 and A4: fill, the text wait, the verifier, select, check and Enter are local-only, browser_structured only", () => {
  const all = ["orcel.read", "orcel.write", "orcel.execute"];
  for (const [tool, shape] of Object.entries(SG122)) {
    const entry = TOOL_CONTRACT[tool];
    assert.equal(`${entry?.capability}/${entry?.operation}`, shape, tool);
    assert.equal(entry?.remote, "local_only", tool);
    // Only browser_structured lists it; core and desktop_structured never.
    assert.ok(profileTools("browser_structured").has(tool), tool);
    assert.equal(profileTools("core").has(tool), false, tool);
    assert.equal(profileTools("desktop_structured").has(tool), false, tool);
    assert.equal(localTransportContext({}).toolSurfaceProfile, "desktop_structured");
    assert.equal(allowedToolsFor(localTransportContext({})).has(tool), false, tool);
    // No remote path maps it: the tunnel and the relay for every provider,
    // the OAuth matrix and ceilings, and the remote tool list.
    for (const provider of Object.keys(REMOTE_PROVIDER_PROFILES)) {
      assert.equal(allowedToolsFor(tunnelTransportContext(provider)).has(tool), false, `${tool} tunnel ${provider}`);
      assert.equal(
        allowedToolsFor({ transportKind: "relay", providerKind: provider, toolSurfaceProfile: "core" }).has(tool),
        false,
        `${tool} relay ${provider}`
      );
    }
    assert.throws(() =>
      allowedToolsFor({ transportKind: "tunnel", providerKind: "openai", toolSurfaceProfile: "browser_structured" })
    );
    assert.ok(LOCAL_ONLY_TOOL_NAMES.includes(tool), tool);
    assert.equal(REMOTE_TOOL_NAMES.includes(tool), false, tool);
    assert.equal(Object.hasOwn(OAUTH_SCOPE_TOOL_MATRIX, tool), false, tool);
    for (const ceiling of Object.values(OAUTH_PROFILE_TOOL_CEILINGS)) {
      assert.equal(ceiling.includes(tool), false, tool);
    }
    assert.equal(securitySchemesFor(tool), null, tool);
    assert.equal(authorizeToolByScopes(tool, "core", all, all).ok, false, tool);
    assert.equal(authorizeToolByScopes(tool, "browser_structured", all, all).ok, false, tool);
  }
  // Fill, select, check and Enter are each SOFT-approved and reach the
  // network through the page (Enter may submit what the page holds); the
  // wait and the verifier are read-only and ask nothing.
  for (const tool of ["browser_fill", ...Object.keys(SG122_A4)]) {
    assert.equal(TOOL_CONTRACT[tool]?.approval, "SOFT", tool);
    assert.equal(TOOL_CONTRACT[tool]?.effect, "network", tool);
    assert.equal(TOOL_CONTRACT[tool]?.annotations.readOnlyHint, false, tool);
    assert.equal(TOOL_CONTRACT[tool]?.annotations.openWorldHint, true, tool);
    assert.equal(TOOL_CONTRACT[tool]?.annotations.idempotentHint, false, tool);
  }
  for (const tool of ["browser_wait_text", "browser_verify"]) {
    assert.equal(TOOL_CONTRACT[tool]?.approval, "none", tool);
    assert.equal(TOOL_CONTRACT[tool]?.effect, "read", tool);
    assert.equal(TOOL_CONTRACT[tool]?.annotations.readOnlyHint, true, tool);
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
  assert.deepEqual([...LOCAL_TOOL_SURFACE_PROFILES], ["desktop_structured", "browser_structured", "browser_full"]);
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
