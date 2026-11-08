import assert from "node:assert/strict";
import test from "node:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DESKTOP_KERNEL_SHAPES,
  desktopElementScrollSchema,
  desktopInputExecuteSchema,
  desktopWindowActionSchema,
  desktopWindowCaptureSchema,
  desktopWindowTreeSchema
} from "./desktop.js";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "src");
const repo = join(here, "..", "..", "..");

function toolSources(): string[] {
  return readdirSync(srcDir).filter(
    (name) => name.endsWith(".ts") && !name.endsWith(".test.ts") && name !== "tool_contract.ts"
  );
}

test("SG-000095 desktop projection is centralized, exact, and contains no authority-management path", () => {
  const forwarded: string[] = [];
  for (const name of toolSources()) {
    const text = readFileSync(join(srcDir, name), "utf8");
    for (const match of text.matchAll(/capability:\s*["']((?:uia|desktop)\.[a-z_.]+)["'],\s*operation:\s*["']([a-z_]+)["']/g)) {
      forwarded.push(`${name}:${match[1] ?? ""}/${match[2] ?? ""}`);
    }
    if (name !== "desktop.ts") {
      assert.doesNotMatch(text, /["']desktop\.(?:cursor|input|window)["']/, `${name} must not name SG-000095 desktop authority`);
    }
  }

  const expected = DESKTOP_KERNEL_SHAPES.map(
    ([capability, operation]) => `desktop.ts:${capability}/${operation}`
  ).sort();
  assert.deepEqual(forwarded.sort(), expected);

  const desktop = readFileSync(join(srcDir, "desktop.ts"), "utf8");
  for (const forbidden of [
    /full[_-]?control.*grant/i,
    /full[_-]?control.*renew/i,
    /full[_-]?control.*revoke/i,
    /AdminLease|PersistentAdmin|RemoteFullControl/,
    /SendInput|SetForegroundWindow|keybd_event|mouse_event/,
    /UAC|Windows Hello bypass|secure desktop bypass/i
  ]) {
    assert.doesNotMatch(desktop, forbidden);
  }
});

test("retained UIA exposure exactly matches the provider qualification table", () => {
  const lib = readFileSync(join(repo, "crates", "orcel-provider-uia", "src", "lib.rs"), "utf8");
  const live = [...lib.matchAll(/\(\s*"(uia\.[a-z_.]+)",\s*"([a-z_]+)",\s*DesktopShapeQualification::LiveExposed,?\s*\)/g)].map(
    (match) => `${match[1] ?? ""}/${match[2] ?? ""}`
  );
  assert.deepEqual(live.sort(), [
    "uia.element/invoke",
    "uia.element/scroll",
    "uia.element/select",
    "uia.element/set_value",
    "uia.element/toggle",
    "uia.screenshot/capture",
    "uia.tree/observe",
    "uia.window/list"
  ]);
});

test("typed desktop schemas fail closed on stale-looking ids and widened bounds", () => {
  const tree = desktopWindowTreeSchema("w");
  assert.equal(
    tree.safeParse({ window_id: "uia-win-0123456789abcdef", window_generation: 3 }).success,
    true
  );
  for (const bad of [
    { window_id: "uia-win-0123456789ABCDEF", window_generation: 3 },
    { window_id: "hwnd:1234", window_generation: 3 },
    { window_id: "uia-win-0123456789abcdef", window_generation: -1 },
    { window_id: "uia-win-0123456789abcdef", window_generation: 3, max_depth: 9 },
    { window_id: "uia-win-0123456789abcdef", window_generation: 3, max_nodes: 257 },
    // SG-000128: a subtree root is an issued element id with its tree
    // generation, both or neither; nothing else names a root.
    { window_id: "uia-win-0123456789abcdef", window_generation: 3, root_element_id: "uia-el-0123456789abcdef" },
    { window_id: "uia-win-0123456789abcdef", window_generation: 3, tree_generation: 4 },
    { window_id: "uia-win-0123456789abcdef", window_generation: 3, root_element_id: "hwnd:1234", tree_generation: 4 },
    { window_id: "uia-win-0123456789abcdef", window_generation: 3, root_element_id: "uia-el-0123456789abcdef", tree_generation: -1 }
  ]) {
    assert.equal(tree.safeParse(bad).success, false, JSON.stringify(bad));
  }
  const scoped = tree.safeParse({
    window_id: "uia-win-0123456789abcdef",
    window_generation: 3,
    root_element_id: "uia-el-0123456789abcdef",
    tree_generation: 4
  });
  assert.equal(scoped.success, true);
  assert.equal(scoped.data?.max_depth, 8);
  assert.equal(scoped.data?.max_nodes, 256);

  const capture = desktopWindowCaptureSchema("w");
  assert.equal(
    capture.safeParse({ window_id: "uia-win-0123456789abcdef", window_generation: 1 }).success,
    true
  );
  assert.equal(capture.safeParse({ window_id: "uia-win-bad", window_generation: 1 }).success, false);

  const scroll = desktopElementScrollSchema("w");
  const base = {
    element_id: "uia-el-0123456789abcdef",
    tree_generation: 1,
    control_type: "List"
  };
  assert.equal(
    scroll.safeParse({
      ...base,
      direction: "down",
      amount: 20,
      expected_horizontal_percent: 0,
      expected_vertical_percent: 0
    }).success,
    true
  );
  assert.equal(
    scroll.safeParse({
      ...base,
      direction: "down",
      amount: 21,
      expected_horizontal_percent: 0,
      expected_vertical_percent: 0
    }).success,
    false
  );
});

test("raw input and window-action schemas are bounded to the SG-000095 vocabulary", () => {
  const input = desktopInputExecuteSchema("w");
  const window = {
    window_id: "uia-win-0123456789abcdef",
    window_generation: 1
  };
  assert.equal(input.safeParse({ ...window, action: "click", x: 4, y: 5 }).success, true);
  assert.equal(
    input.safeParse({ ...window, action: "scroll", x: 4, y: 5, scroll_x: 0, scroll_y: 20 }).success,
    true
  );
  assert.equal(
    input.safeParse({ ...window, action: "scroll", x: 4, y: 5, scroll_x: 0, scroll_y: 21 }).success,
    false
  );
  assert.equal(input.safeParse({ ...window, action: "shell", text: "whoami" }).success, false);
  assert.equal(
    input.safeParse({ ...window, action: "hotkey", key: "ctrl+".concat("a".repeat(80)) }).success,
    false
  );

  const windowAction = desktopWindowActionSchema("w");
  for (const action of ["focus", "minimize", "maximize", "restore", "close"]) {
    assert.equal(windowAction.safeParse({ ...window, action }).success, true, action);
  }
  for (const action of ["launch", "elevate", "terminate_process", "secure_desktop"]) {
    assert.equal(windowAction.safeParse({ ...window, action }).success, false, action);
  }
});
