// SG-000108 decision 7: the resolve guard loads Node built-ins and exactly
// the files the runtime manifest names, wherever Node would have found
// anything else.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadAllowlist, MANIFEST_NAME, MANIFEST_SCHEMA, MODULE_REFUSED, moduleRefusal } from "./resolve-guard.js";

const here = dirname(fileURLToPath(import.meta.url));

function manifest(dist: string, files: unknown, schema: unknown = MANIFEST_SCHEMA): void {
  writeFileSync(join(dist, MANIFEST_NAME), JSON.stringify({ schema, files }));
}

test("only Node built-ins and the manifest's files resolve", () => {
  const root = mkdtempSync(join(tmpdir(), "orcel-guard-list-"));
  try {
    const dist = join(root, "dist");
    mkdirSync(dist);
    manifest(dist, ["dist/worker.js", "dist/extract/clean.js", "node_modules/playwright-core/lib/coreBundle.js", "package.json"]);
    const allowed = loadAllowlist(dist);
    const url = (...parts: string[]) => pathToFileURL(join(root, ...parts)).href;
    assert.equal(moduleRefusal("node:fs", allowed), null);
    assert.equal(moduleRefusal(url("dist", "worker.js"), allowed), null);
    assert.equal(moduleRefusal(url("dist", "extract", "clean.js"), allowed), null);
    assert.equal(moduleRefusal(url("node_modules", "playwright-core", "lib", "coreBundle.js"), allowed), null);
    // Windows paths compare case-insensitively.
    assert.equal(moduleRefusal(url("DIST", "Worker.js"), allowed), null);
    for (const refused of [
      // A file planted beside a pinned one: CommonJS tries it first.
      url("node_modules", "playwright-core", "lib", "coreBundle"),
      url("node_modules", "playwright-core", "lib", "other.js"),
      // Excluded from the pin, so never loadable.
      url("dist", "worker.test.js"),
      url("node_modules", "bufferutil", "index.js"),
      url("dist", "node_modules", "playwright-core", "index.js"),
      url("node_modules", "playwright-core", "node_modules", "bufferutil", "index.js"),
      pathToFileURL(join(tmpdir(), "node_modules", "bufferutil", "index.js")).href,
      pathToFileURL(join(root + "-other", "dist", "worker.js")).href,
      "data:text/javascript,export default 1",
      "https://example.test/x.js"
    ]) {
      assert.notEqual(moduleRefusal(refused, allowed), null, refused);
    }
    // A missing or malformed manifest installs no guard: the worker never starts.
    for (const [files, schema] of [
      [["../outside.js"], MANIFEST_SCHEMA],
      [["dist//x.js"], MANIFEST_SCHEMA],
      [["C:/x.js"], MANIFEST_SCHEMA],
      [["dist\\x.js"], MANIFEST_SCHEMA],
      [["dist/./x.js"], MANIFEST_SCHEMA],
      [[""], MANIFEST_SCHEMA],
      [[1], MANIFEST_SCHEMA],
      ["dist/x.js", MANIFEST_SCHEMA],
      [["dist/x.js"], "orcel-worker-runtime-manifest/0"]
    ] as const) {
      manifest(dist, files, schema);
      assert.throws(() => loadAllowlist(dist), new RegExp(MODULE_REFUSED), JSON.stringify(files));
    }
    rmSync(join(dist, MANIFEST_NAME));
    assert.throws(() => loadAllowlist(dist));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a planted module is refused wherever Node finds it, and built-ins and listed files still load", () => {
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
    plant(join(dist, "node_modules"), "shadowed");
    // A stand-in playwright-core whose entry requires `./lib/core` without
    // an extension, as playwright-core's CommonJS code does.
    const pw = join(root, "node_modules", "playwright-core");
    mkdirSync(join(pw, "lib"), { recursive: true });
    writeFileSync(join(pw, "package.json"), JSON.stringify({ name: "playwright-core", main: "index.js" }));
    writeFileSync(join(pw, "index.js"), 'module.exports = require("./lib/core");');
    writeFileSync(join(pw, "lib", "core.js"), 'module.exports = "pinned core";');
    writeFileSync(join(pw, "lib", "lazy.js"), 'module.exports = "pinned core";');
    writeFileSync(join(dist, "helper.test.js"), 'process.stdout.write("PLANTED test file\\n");');
    writeFileSync(
      join(dist, "probe.js"),
      [
        'import { createRequire } from "node:module";',
        'import { writeFileSync } from "node:fs";',
        'import { installResolveGuard } from "./resolve-guard.js";',
        "installResolveGuard();",
        "const require = createRequire(import.meta.url);",
        "const outcome = (name) => { try { const value = require(name); return value === 'pinned core' ? 'pinned' : 'loaded'; } catch (error) { return error.code; } };",
        'const results = { fs: outcome("node:fs"), path: outcome("path"), pw: outcome("playwright-core"),',
        '  parent: outcome("bufferutil"), sibling: outcome("utf-8-validate"), shadow: outcome("shadowed"), test: outcome("./helper.test.js") };',
        "let dynamic = 'loaded';",
        'try { await import("bufferutil"); } catch (error) { dynamic = error.code; }',
        // After the guard is installed, a file appears beside a pinned one
        // that loads lazily, under the extensionless name CommonJS tries
        // first; its first require must not load it.
        `writeFileSync(${JSON.stringify(join(pw, "lib", "lazy"))}, 'process.stdout.write("PLANTED extensionless\\\\n"); module.exports = "planted";');`,
        'const planted = outcome("playwright-core/lib/lazy");',
        "process.stdout.write(JSON.stringify({ ...results, dynamic, planted }) + '\\n');"
      ].join("\n")
    );
    writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
    manifest(dist, [
      "dist/probe.js",
      "dist/resolve-guard.js",
      "node_modules/playwright-core/index.js",
      "node_modules/playwright-core/lib/core.js",
      "node_modules/playwright-core/lib/lazy.js",
      "node_modules/playwright-core/package.json",
      "package.json"
    ]);
    const run = spawnSync(process.execPath, [join(dist, "probe.js")], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.doesNotMatch(run.stdout, /PLANTED/);
    const last = run.stdout.trim().split("\n").at(-1) ?? "{}";
    assert.deepEqual(JSON.parse(last), {
      fs: "loaded",
      path: "loaded",
      pw: "pinned",
      parent: MODULE_REFUSED,
      sibling: MODULE_REFUSED,
      shadow: MODULE_REFUSED,
      test: MODULE_REFUSED,
      dynamic: MODULE_REFUSED,
      planted: MODULE_REFUSED
    });
  } finally {
    rmSync(outer, { recursive: true, force: true });
  }
});

test("the built worker's manifest names exactly its runtime", async () => {
  const { runtimeFiles, MANIFEST } = (await import(pathToFileURL(join(here, "..", "scripts", "runtime-manifest.mjs")).href)) as {
    runtimeFiles: (root: string) => string[];
    MANIFEST: string;
  };
  const root = join(here, "..");
  const listed = [...loadAllowlist(here)].sort();
  const expected = runtimeFiles(root)
    .filter((relative) => relative !== MANIFEST)
    .map((relative) => join(root, ...relative.split("/")).toLowerCase())
    .sort();
  assert.deepEqual(listed, expected);
  assert.ok(listed.some((path) => path.endsWith(join("dist", "entry.js"))));
  assert.ok(!listed.some((path) => path.endsWith(".test.js")));
});
