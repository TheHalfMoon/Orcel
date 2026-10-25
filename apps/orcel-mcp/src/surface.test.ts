import assert from "node:assert/strict";
import test from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");

/** The closed MCP tool set. Adding a tool requires a governed grain. */
const CANONICAL_TOOLS = [
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
  "report_commit",
  "report_preview",
  "report_start",
  "system_status",
  "task_resume_summary",
  "web_fetch",
  "web_search",
  "workspace_get"
];

/** Every non-test TypeScript source under src, including subdirectories. */
function toolSources(): Array<[string, string]> {
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

test("the MCP surface registers exactly the canonical closed tool set", () => {
  const registered: string[] = [];
  for (const [, text] of toolSources()) {
    for (const match of text.matchAll(/registerTool\(\s*["']([^"']+)["']/g)) {
      registered.push(match[1] ?? "");
    }
  }
  assert.deepEqual([...registered].sort(), [...CANONICAL_TOOLS].sort());
  assert.equal(new Set(registered).size, registered.length, "duplicate tool registration");
});

test("no MCP tool source reaches lifecycle, installer, update, trust, or approval surfaces", () => {
  const offenders: string[] = [];
  const forbidden = [
    /orcel\.exe\b/i,
    /orcel-mcp-host/i,
    /\bsupervise\b/i,
    /self-check/i,
    /emergency[-_]revoke|revoke_emergency/i,
    /workspace\.trust\.|trust\.history|approval\.history/i,
    /tunnel-runtime-key|tunnel_runtime_key/i
  ];
  for (const [name, text] of toolSources()) {
    text.split("\n").forEach((line, index) => {
      if (forbidden.some((pattern) => pattern.test(line))) {
        offenders.push(`${name}:${String(index + 1)}:${line.trim()}`);
      }
    });
  }
  assert.deepEqual(offenders, []);
});
