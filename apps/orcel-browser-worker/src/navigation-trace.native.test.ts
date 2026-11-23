// #584: the probe after a stalled navigation, checked on the installed Edge in
// the worker's own shape: a persistent context, and a redirect guard on the
// page. A healthy engine with a navigation that stays pending (the server
// accepts and never answers), then one that is gone. On Windows a missing
// engine fails the suite; elsewhere it is skipped, as the others are.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { test } from "node:test";
import { chromium } from "playwright-core";
import { probeBrowser } from "./navigation-trace.js";
import { attachRedirectGuard } from "./redirect-guard.js";

const EDGE_CANDIDATES = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
];
const isWindows = process.platform === "win32";
const engine = EDGE_CANDIDATES.find((path) => existsSync(path));
const skip = isWindows ? false : "native probes are Windows-only evidence";

/// Wait (bounded) until no engine process uses `profile`, as native.test.ts
/// does: one still exiting holds files in it.
function engineExited(profile: string): void {
  execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `$ErrorActionPreference='Stop'; $q = { @(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like '*${basename(profile)}*' }) }; $deadline = (Get-Date).AddSeconds(60); $p = @(& $q); while ($p.Count -gt 0 -and (Get-Date) -lt $deadline) { $left = [Math]::Max(1, [int]($deadline - (Get-Date)).TotalSeconds); Wait-Process -Id $p.ProcessId -Timeout $left -ErrorAction SilentlyContinue; $p = @(& $q) }; $p.Count`
    ],
    { encoding: "utf8", timeout: 120_000 }
  );
}

test("#584: a healthy engine answers the probe while a navigation is pending, and a closed one does not", { skip, timeout: 300_000 }, async () => {
  assert.ok(engine, "Edge is installed");
  let requests = 0;
  const server = createServer(() => {
    requests += 1;
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  const profile = mkdtempSync(join(tmpdir(), "orcel-584-probe-"));
  const context = await chromium.launchPersistentContext(profile, { executablePath: engine, headless: true });
  try {
    const page = await context.newPage();
    await attachRedirectGuard(context, page, { decide: async () => true });
    assert.equal(await page.evaluate("1"), 1, "the control: the renderer answers before the navigation");
    // The timeout ends only the wait: the navigation itself goes on.
    await assert.rejects(page.goto(url, { timeout: 2_000 }), { name: "TimeoutError" });
    for (const until = Date.now() + 60_000; requests === 0 && Date.now() < until; ) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.ok(requests >= 1, "the control: the navigation reached the server and is pending");
    const answered = ["browser_attach_answered", "browser_history_answered", "browser_version_answered"];
    assert.deepEqual(await probeBrowser(() => context.newCDPSession(page), 10_000), answered);
    // A second probe of the same pending navigation is answered too.
    assert.deepEqual(await probeBrowser(() => context.newCDPSession(page), 10_000), answered);
    // Shown, not required: what the probe used to ask (#584). A later engine
    // may answer it, and that would be no fault of the worker's.
    const renderer = await Promise.race([
      page.evaluate("1").then(
        () => "answered",
        () => "error"
      ),
      new Promise<string>((resolve) => setTimeout(() => resolve("no answer"), 2_000))
    ]);
    process.stderr.write(`#584 the healthy renderer with a navigation pending: ${renderer}\n`);
    await context.close();
    const gone = await probeBrowser(() => context.newCDPSession(page), 2_000);
    assert.ok(gone.every((mark) => !mark.endsWith("_answered")), gone.join(" "));
  } finally {
    await context.close().catch(() => {});
    server.closeAllConnections();
    server.close();
    engineExited(profile);
    rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
  }
});
