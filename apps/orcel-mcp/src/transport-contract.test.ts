import assert from "node:assert/strict";
import test from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import {
  buildOrcelServer,
  CANONICAL_TOOL_NAMES,
  defaultTransportContext,
  registerOrcelTools
} from "./server.js";
import { projectKernelResult } from "./result.js";
import { LOOPBACK_TRANSPORT_RESERVED } from "./transports/loopback_http.js";
import { RELAY_TRANSPORT_RESERVED } from "./transports/relay_device.js";
import type { KernelClient } from "./kernel.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");

const EXPECTED_TOOLS = [
  "browser_click",
  "browser_download",
  "browser_download_preview",
  "browser_navigate",
  "browser_observe",
  "browser_page_open",
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
  "fs_edit",
  "fs_find",
  "fs_list",
  "fs_mkdir",
  "fs_move",
  "fs_read",
  "fs_read_range",
  "fs_remove",
  "fs_search",
  "fs_stat",
  "fs_write",
  "fs_write_preview",
  "git_branch_create",
  "git_commit",
  "git_diff",
  "git_fetch",
  "git_fetch_preview",
  "git_log",
  "git_push",
  "git_push_preview",
  "git_stage",
  "git_status",
  "git_unstage",
  "process_spawn",
  "system_status",
  "web_fetch",
  "web_search",
  "workspace_get"
];

function allSources(): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  const visit = (dir: string, prefix: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(path, rel);
      } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) {
        found.push([rel, readFileSync(path, "utf8")]);
      }
    }
  };
  visit(srcDir, "");
  return found.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

function fakeKernel(): KernelClient {
  return {
    sessionId: "test-session",
    call: async () => {
      throw new Error("fake kernel must not be called during registration");
    },
    close: () => {},
    pending: new Map(),
    child: {} as never
  } as unknown as KernelClient;
}

test("authoritative catalog matches the closed v0.1 tool set", () => {
  assert.deepEqual([...CANONICAL_TOOL_NAMES].sort(), [...EXPECTED_TOOLS].sort());
  assert.equal(new Set(CANONICAL_TOOL_NAMES).size, CANONICAL_TOOL_NAMES.length);
});

test("transport adapters register no tools independently", () => {
  const offenders: string[] = [];
  for (const [name, text] of allSources()) {
    if (!name.startsWith("transports/") && !name.startsWith("entrypoints/")) {
      continue;
    }
    for (const match of text.matchAll(/registerTool\s*\(/g)) {
      void match;
      offenders.push(name);
    }
  }
  assert.deepEqual(offenders, [], "transport/entrypoint must reuse registerOrcelTools");
});

test("stdio transport reuses the authoritative builder", () => {
  const entry = allSources().find(([name]) => name === "transports/stdio.ts");
  assert.ok(entry, "transports/stdio.ts exists");
  const [, text] = entry as [string, string];
  assert.ok(text.includes("buildOrcelServer"), "stdio must use buildOrcelServer");
  assert.ok(!text.includes("registerTool("), "stdio must not register tools directly");
});

test("installed stdio entrypoint reuses the stdio transport", () => {
  const entry = allSources().find(([name]) => name === "entrypoints/stdio.ts");
  assert.ok(entry, "entrypoints/stdio.ts exists");
  const [, text] = entry as [string, string];
  assert.ok(
    text.includes("../transports/stdio.js"),
    "the installed entrypoint must reuse the stdio transport"
  );
  assert.ok(!text.includes("registerTool("), "the entrypoint must not register tools directly");
  assert.ok(!text.includes("buildOrcelServer"), "the entrypoint must not bypass the transport");
});

test("loopback transport reuses the authoritative builder", () => {
  const entry = allSources().find(([name]) => name === "transports/loopback_http.ts");
  assert.ok(entry, "transports/loopback_http.ts exists");
  const [, text] = entry as [string, string];
  assert.ok(text.includes("buildOrcelServer"), "loopback must use buildOrcelServer");
  assert.ok(!text.includes("registerTool("), "loopback must not register tools directly");
});

test("result projection is the single authoritative source", () => {
  for (const name of ["git_fetch.ts", "git_mutation.ts", "git_push.ts", "server.ts"]) {
    const entry = allSources().find(([rel]) => rel === name);
    assert.ok(entry, `${name} exists`);
    const [, text] = entry as [string, string];
    assert.ok(
      text.includes('from "./result.js"'),
      `${name} must import the authoritative projection`
    );
    assert.ok(
      !text.includes("function asToolResult"),
      `${name} must not define an independent projection`
    );
  }
});

test("result projection preserves the v0.1 envelope without adding authority", () => {
  const failure = projectKernelResult({
    version: 1,
    request_id: "req-1",
    ok: false,
    error: { code: "WORKSPACE_DENIED", message: "denied" }
  });
  assert.equal(failure.isError, true);
  const failureText = (failure.content[0] as { text: string }).text;
  assert.ok(failureText.includes("WORKSPACE_DENIED"));
  assert.ok(!failureText.includes("transport"));
  assert.ok(!failureText.includes("device_id"));
  assert.ok(!failureText.includes("token"));

  const success = projectKernelResult({
    version: 1,
    request_id: "req-2",
    ok: true,
    result: { hello: "world" },
    evidence: { workspace_id: "default", policy_revision: "rev-1" }
  });
  assert.equal((success as { isError?: boolean }).isError, undefined);
  const successText = (success.content[0] as { text: string }).text;
  const parsed = JSON.parse(successText) as {
    result: unknown;
    evidence: unknown;
  };
  assert.deepEqual(parsed.result, { hello: "world" });
  assert.deepEqual(parsed.evidence, { workspace_id: "default", policy_revision: "rev-1" });
});

test("transport context is server-supplied metadata, never a tool field", () => {
  const context = defaultTransportContext();
  assert.equal(context.transportKind, "stdio");
  assert.equal(context.providerKind, "generic");
  assert.equal(context.toolSurfaceProfile, "desktop_structured");

  for (const [name, text] of allSources()) {
    if (name.endsWith(".test.ts")) {
      continue;
    }
    for (const line of text.split("\n")) {
      if (
        line.includes("transport_kind") ||
        line.includes("provider_kind") ||
        line.includes("remote_principal_id") ||
        line.includes("remote_connection_id") ||
        line.includes("tool_surface_profile")
      ) {
        assert.ok(
          name === "server.ts",
          `${name} must not carry transport identity as tool fields`
        );
      }
    }
  }
});

test("reserved transports fail closed without authority", () => {
  assert.equal(LOOPBACK_TRANSPORT_RESERVED, "SG-000050");
  assert.equal(RELAY_TRANSPORT_RESERVED, "ORCEL-P15");
});

test("authoritative builder registers without spawning orceld", () => {
  const kernel = fakeKernel();
  const server: McpServer = buildOrcelServer(kernel, "default");
  assert.ok(server);
  assert.equal(typeof registerOrcelTools, "function");
  try {
    kernel.close();
  } catch {
    // Fake close never throws.
  }
});
