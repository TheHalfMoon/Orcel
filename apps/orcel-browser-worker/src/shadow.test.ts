// SG-000135 OB-04: the worker never reaches the person's desktop. Its page
// actions go to the engine over the debugging pipe (Playwright's CDP input,
// never OS input), so nothing in the worker may raise, activate or focus a
// window, touch the system clipboard, or synthesize OS input. This scans
// every non-test worker source for the calls that would.

import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");

/// Calls and flags that would touch the person's desktop.
const FORBIDDEN: readonly RegExp[] = [
  /bringToFront/,
  /navigator\.clipboard|clipboard\.(read|write)|readText|writeText/,
  // Permissions are only ever all refused: grantPermissions([]) only.
  /\.grantPermissions\((?!\[\]\))/,
  /SetForegroundWindow|AllowSetForegroundWindow|BringWindowToTop|SetActiveWindow|SwitchToThisWindow/,
  /SendInput|keybd_event|mouse_event|SetCursorPos|AttachThreadInput/,
  /OpenClipboard|SetClipboardData|EmptyClipboard/,
  /--start-maximized|--start-fullscreen|--kiosk|--app=/,
  /Browser\.setWindowBounds|Page\.bringToFront|Emulation\.setFocusEmulationEnabled/
];

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...sources(path));
    else if (name.endsWith(".ts") && !name.endsWith(".test.ts") && name !== "fixtures.ts") out.push(path);
  }
  return out;
}

test("SG-000135 OB-04: no worker source raises a window, uses the clipboard or synthesizes OS input", () => {
  const files = sources(src);
  assert.ok(files.length > 20, `the worker sources were found under ${src}`);
  const hits: string[] = [];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const pattern of FORBIDDEN) {
      if (pattern.test(text)) hits.push(`${file}: ${pattern}`);
    }
  }
  assert.deepEqual(hits, []);
});

test("SG-000135 OB-04: every launch denies all permissions and intercepts file choosers", () => {
  const entry = readFileSync(join(src, "entry.ts"), "utf8");
  assert.match(entry, /await denyDesktopPermissions\(context\);/);
  assert.match(entry, /context\.on\("page", interceptFileChoosers\);/);
  assert.match(entry, /for \(const existing of context\.pages\(\)\) interceptFileChoosers\(existing\);/);
  const guard = readFileSync(join(src, "desktop-guard.ts"), "utf8");
  assert.match(guard, /await context\.grantPermissions\(\[\]\);/);
});

test("SG-000135 OB-04: the engine runs headless unless the argv is the exact Visible form", () => {
  const entry = readFileSync(join(src, "entry.ts"), "utf8");
  assert.match(entry, /headless: !isVisibleArgv\(spec\.argv\)/);
  assert.equal((entry.match(/headless:/g) ?? []).length, 1, "one headless decision, from the argv");
});
