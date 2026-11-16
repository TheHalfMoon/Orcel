import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkNpmLicences } from "./check-npm-licenses.mjs";
import { basePolicy, makeTree, removeTree } from "./licence-gate-fixture.mjs";
import { spdxAllowed } from "./licence-gate-lib.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWED = new Set(basePolicy().allowed_licences);

function lock(packages) {
  return { name: "fixture", lockfileVersion: 3, packages: { "": { name: "fixture" }, ...packages } };
}

function run(files, policy = {}) {
  const root = makeTree({ "docs/orcel/notices/licence-policy.json": basePolicy(policy), ...files });
  try {
    return checkNpmLicences(root).errors;
  } finally {
    removeTree(root);
  }
}

test("today's lockfiles pass, the root workspace lockfile included", () => {
  const { errors, lockfiles, checked } = checkNpmLicences(REPO);
  assert.deepEqual(errors, []);
  assert.ok(lockfiles.includes("package-lock.json"));
  assert.ok(lockfiles.includes("apps/web/package-lock.json"));
  assert.ok(checked > 100);
});

test("SPDX expressions: OR needs one allowed branch, AND needs all, WITH needs the exact pair", () => {
  assert.equal(spdxAllowed("MIT", ALLOWED), true);
  assert.equal(spdxAllowed("(MIT OR GPL-3.0-only)", ALLOWED), true);
  assert.equal(spdxAllowed("MIT/Apache-2.0", ALLOWED), true);
  assert.equal(spdxAllowed("MIT AND GPL-3.0-only", ALLOWED), false);
  assert.equal(spdxAllowed("(AFL-2.1 OR BSD-3-Clause)", ALLOWED), true);
  assert.equal(spdxAllowed("Apache-2.0 WITH LLVM-exception", ALLOWED), false);
  assert.equal(spdxAllowed("Apache-2.0 WITH LLVM-exception OR MIT", ALLOWED), true);
  assert.equal(spdxAllowed("MIT OR", ALLOWED), false);
  assert.equal(spdxAllowed("(MIT", ALLOWED), false);
});

test("an AGPL package fails", () => {
  const errors = run({ "apps/a/package-lock.json": lock({ "node_modules/agpl-thing": { version: "1.0.0", license: "AGPL-3.0-only" } }) });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /apps\/a\/package-lock\.json: agpl-thing@1\.0\.0: licence "AGPL-3\.0-only" \(AGPL\)/);
});

test("GPL, LGPL, MPL, SSPL, BUSL, commercial and unknown licences fail; a missing licence fails", () => {
  const packages = {
    "node_modules/g": { license: "GPL-2.0-or-later" },
    "node_modules/l": { license: "LGPL-3.0-or-later", optional: true },
    "node_modules/m": { license: "MPL-2.0" },
    "node_modules/s": { license: "SSPL-1.0" },
    "node_modules/b": { license: "BUSL-1.1" },
    "node_modules/c": { license: "SEE LICENSE IN LICENSE.md" },
    "node_modules/u": { license: "UNLICENSED" },
    "node_modules/n": { version: "1.0.0" },
    "node_modules/ok": { license: "MIT" },
  };
  const errors = run({ "packages/sdk/package-lock.json": lock(packages) });
  assert.equal(errors.length, 8, errors.join("\n"));
  assert.ok(errors.some((e) => e.includes("n@1.0.0: no licence declared")));
  assert.ok(errors.some((e) => e.includes('"MPL-2.0" (MPL)')));
});

test("PSF-2.0 is allowed only in test-only lockfiles", () => {
  const packages = { "node_modules/py-port": { license: "PSF-2.0" } };
  assert.deepEqual(run({ "tests/fixture/package-lock.json": lock(packages) }), []);
  assert.equal(run({ "apps/a/package-lock.json": lock(packages) }).length, 1);
});

test("a named exception admits exactly its lockfile, licence and packages", () => {
  const exception = { lockfile: "apps/web/package-lock.json", licence: "LGPL-3.0-or-later", packages: ["libvips"], reason: "fixture" };
  const ok = { "apps/web/package-lock.json": lock({ "node_modules/libvips": { license: "LGPL-3.0-or-later" } }) };
  assert.deepEqual(run(ok, { npm_exceptions: [exception] }), []);
  const otherLock = { ...ok, "apps/b/package-lock.json": lock({ "node_modules/libvips": { license: "LGPL-3.0-or-later" } }) };
  assert.equal(run(otherLock, { npm_exceptions: [exception] }).length, 1);
  const otherLicence = { "apps/web/package-lock.json": lock({ "node_modules/libvips": { license: "GPL-3.0-only" } }) };
  const errors = run(otherLicence, { npm_exceptions: [exception] });
  assert.ok(errors.some((e) => e.includes('"GPL-3.0-only"')));
  assert.ok(errors.some((e) => e.includes("no longer appears")), "the unused exception is reported");
});

test("workspace packages take their licence from package.json", () => {
  const files = {
    "package-lock.json": lock({ "apps/mcp": { name: "@x/mcp" }, "node_modules/@x/mcp": { link: true, resolved: "apps/mcp" } }),
    "apps/mcp/package.json": { name: "@x/mcp", license: "Apache-2.0" },
  };
  assert.deepEqual(run(files), []);
  const missing = { ...files, "apps/mcp/package.json": { name: "@x/mcp" } };
  const errors = run(missing);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /package-lock\.json: apps\/mcp: no licence declared/);
});

test("a lockfile anywhere in the repository is read", () => {
  const errors = run({ "docs/example/package-lock.json": lock({ "node_modules/g": { license: "GPL-3.0-only" } }) });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /docs\/example\/package-lock\.json: g: licence "GPL-3\.0-only"/);
});

test("other lockfile kinds fail: the gate reads only package-lock.json", () => {
  for (const name of ["npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]) {
    const errors = run({ [`apps/a/${name}`]: "{}\n" });
    assert.equal(errors.length, 1, `${name}: ${errors.join("; ")}`);
    assert.match(errors[0], /only package-lock\.json is read/);
  }
});

test("a package.json with dependencies but no package-lock.json fails; workspace members use the root lock", () => {
  const unlocked = { "packages/sdk/package.json": { name: "sdk", license: "MIT", dependencies: { left: "1.0.0" } } };
  const errors = run(unlocked);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /packages\/sdk\/package\.json: declares dependencies but has no package-lock\.json/);
  assert.deepEqual(run({ "packages/sdk/package.json": { name: "sdk", scripts: { build: "tsc" } } }), []);
  const member = {
    ...unlocked,
    "package.json": { name: "root", private: true, workspaces: ["packages/sdk"] },
    "package-lock.json": lock({ "packages/sdk": { name: "sdk", license: "MIT" } }),
  };
  assert.deepEqual(run(member), []);
});
