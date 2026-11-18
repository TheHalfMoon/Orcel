// SG-000135 OB-04: the desktop guard, checked on the installed Edge in the
// worker's own launch shape (a persistent context). The page is the test's
// own, fulfilled by a route (no network). The clipboard is never written or
// read here: the test asks the page for the permission state only.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { chromium } from "playwright-core";
import { denyDesktopPermissions, interceptFileChoosers } from "./desktop-guard.js";

const EDGE_CANDIDATES = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
];
const isWindows = process.platform === "win32";
const engine = EDGE_CANDIDATES.find((path) => existsSync(path));
const skip = isWindows ? false : "native probes are Windows-only evidence";

const PAGE = `<!doctype html><title>guard</title><label>File <input type="file" id="f"></label>`;

test("OB-04: pages are denied the clipboard, and file choosers never reach the desktop", { skip }, async () => {
  assert.ok(engine, "Edge is installed");
  const profile = mkdtempSync(join(tmpdir(), "orcel-ob04-guard-"));
  const context = await chromium.launchPersistentContext(profile, { executablePath: engine, headless: true });
  try {
    const page = context.pages()[0] ?? (await context.newPage());
    await page.route("https://guard.test/**", (route) => route.fulfill({ status: 200, contentType: "text/html", body: PAGE }));
    await page.goto("https://guard.test/");
    const state = (name: string) =>
      page.evaluate(async (permission) => (await navigator.permissions.query({ name: permission as PermissionName })).state, name);
    const before = await state("clipboard-write");
    assert.notEqual(before, "denied", "the control: not denied before the guard");
    await denyDesktopPermissions(context);
    assert.equal(await state("clipboard-write"), "denied");
    assert.equal(await state("clipboard-read"), "denied");
    // A new page of the same context is denied too.
    const second = await context.newPage();
    await second.route("https://guard.test/**", (route) => route.fulfill({ status: 200, contentType: "text/html", body: PAGE }));
    await second.goto("https://guard.test/");
    assert.equal(
      await second.evaluate(async () => (await navigator.permissions.query({ name: "clipboard-write" as PermissionName })).state),
      "denied"
    );
    // The chooser is intercepted: the event arrives instead of a dialog.
    interceptFileChoosers(page);
    const chooser = page.waitForEvent("filechooser", { timeout: 10_000 });
    await page.click("#f");
    const intercepted = await chooser;
    assert.equal(intercepted.isMultiple(), false);
  } finally {
    await context.close();
    rmSync(profile, { recursive: true, force: true });
  }
});
