// SG-000108 decision 7: the resolve guard refuses every module outside the
// pinned runtime, wherever Node would have found it.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { MODULE_REFUSED, moduleRefusal } from "./resolve-guard.js";

const here = dirname(fileURLToPath(import.meta.url));

test("only Node built-ins, dist/ and playwright-core resolve", () => {
  const root = join(tmpdir(), "app");
  const dist = join(root, "dist");
  const url = (...parts: string[]) => pathToFileURL(join(root, ...parts)).href;
  assert.equal(moduleRefusal("node:fs", dist), null);
  assert.equal(moduleRefusal(url("dist", "worker.js"), dist), null);
  assert.equal(moduleRefusal(url("dist", "extract", "clean.js"), dist), null);
  assert.equal(moduleRefusal(url("node_modules", "playwright-core", "lib", "server.js"), dist), null);
  // Case differs on Windows paths only in spelling.
  assert.equal(moduleRefusal(url("DIST", "worker.js"), dist), null);
  for (const refused of [
    url("node_modules", "bufferutil", "index.js"),
    url("node_modules", "typescript", "lib", "typescript.js"),
    url("dist", "node_modules", "playwright-core", "index.js"),
    url("node_modules", "playwright-core", "node_modules", "bufferutil", "index.js"),
    url("package.json"),
    pathToFileURL(join(tmpdir(), "node_modules", "bufferutil", "index.js")).href,
    pathToFileURL(join(root + "-other", "dist", "x.js")).href,
    "data:text/javascript,export default 1",
    "https://example.test/x.js"
  ]) {
    assert.notEqual(moduleRefusal(refused, dist), null, refused);
  }
});

test("a planted module is refused wherever Node finds it, and built-ins still load", () => {
  // outer/node_modules is a parent directory of the app: Node's lookup
  // walks up to it (as it would to C:\\node_modules).
  const outer = mkdtempSync(join(tmpdir(), "orcel-guard-"));
  try {
    const root = join(outer, "app");
    const dist = join(root, "dist");
    mkdirSync(dist, { recursive: true });
    copyFileSync(join(here, "resolve-guard.js"), join(dist, "resolve-guard.js"));
    const plant = (dir: string, name: string) => {
      mkdirSync(join(dir, name), { recursive: true });
      writeFileSync(join(dir, name, "package.json"), JSON.stringify({ name, main: "index.js" }));
      writeFileSync(join(dir, name, "index.js"), `process.stdout.write("PLANTED ${name}\\n");`);
    };
    plant(join(outer, "node_modules"), "bufferutil");
    plant(join(root, "node_modules"), "utf-8-validate");
    plant(join(root, "node_modules"), "playwright-core");
    plant(join(dist, "node_modules"), "shadowed");
    writeFileSync(
      join(dist, "probe.js"),
      [
        'import { createRequire } from "node:module";',
        'import { installResolveGuard } from "./resolve-guard.js";',
        "installResolveGuard();",
        "const require = createRequire(import.meta.url);",
        "const outcome = (name) => { try { require(name); return 'loaded'; } catch (error) { return error.code; } };",
        'const results = { fs: outcome("node:fs"), path: outcome("path"), pw: outcome("playwright-core"),',
        '  parent: outcome("bufferutil"), sibling: outcome("utf-8-validate"), shadow: outcome("shadowed") };',
        "let dynamic = 'loaded';",
        'try { await import("bufferutil"); } catch (error) { dynamic = error.code; }',
        "process.stdout.write(JSON.stringify({ ...results, dynamic }) + '\\n');"
      ].join("\n")
    );
    writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
    const run = spawnSync(process.execPath, [join(dist, "probe.js")], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.doesNotMatch(run.stdout, /PLANTED (bufferutil|utf-8-validate|shadowed)/);
    const last = run.stdout.trim().split("\n").at(-1) ?? "{}";
    assert.deepEqual(JSON.parse(last), {
      fs: "loaded",
      path: "loaded",
      pw: "loaded",
      parent: MODULE_REFUSED,
      sibling: MODULE_REFUSED,
      shadow: MODULE_REFUSED,
      dynamic: MODULE_REFUSED
    });
  } finally {
    rmSync(outer, { recursive: true, force: true });
  }
});
