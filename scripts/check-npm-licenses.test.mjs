import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkNpmLockfiles } from "./check-npm-licenses.mjs";
import { makeTree, removeTree } from "./licence-gate-fixture.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function pinned(name, license) {
  const entry = {
    version: "1.0.0",
    resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
    integrity: "sha512-AAAA",
  };
  if (license !== undefined) entry.license = license;
  return entry;
}

function lock(packages) {
  return { name: "fixture", lockfileVersion: 3, packages: { "": { name: "fixture" }, ...packages } };
}

function run(files) {
  const root = makeTree(files);
  try {
    return checkNpmLockfiles(root);
  } finally {
    removeTree(root);
  }
}

test("today's lockfiles pass: every package pinned, licences reported", () => {
  const { errors, lockfiles, report } = checkNpmLockfiles(REPO);
  assert.deepEqual(errors, []);
  assert.ok(lockfiles.includes("package-lock.json"));
  assert.ok(lockfiles.includes("apps/web/package-lock.json"));
  assert.ok(report.some((row) => row.licence === "LGPL-3.0-or-later"), "licences are reported, not refused");
});

test("no licence blocks: AGPL, GPL, commercial and undeclared licences all pass when pinned", () => {
  const packages = {
    "node_modules/a": pinned("a", "AGPL-3.0-only"),
    "node_modules/g": pinned("g", "GPL-2.0-or-later"),
    "node_modules/c": pinned("c", "SEE LICENSE IN LICENSE.md"),
    "node_modules/n": pinned("n"),
  };
  const { errors, report } = run({ "apps/a/package-lock.json": lock(packages) });
  assert.deepEqual(errors, []);
  assert.deepEqual(
    report.map((row) => row.licence),
    ["AGPL-3.0-only", "GPL-2.0-or-later", "SEE LICENSE IN LICENSE.md", null],
  );
});

test("an unpinned package fails: version, resolved URL and integrity are required", () => {
  const packages = {
    "node_modules/no-integrity": { version: "1.0.0", resolved: "https://registry.npmjs.org/x.tgz", license: "MIT" },
    "node_modules/no-anything": { license: "MIT" },
  };
  const { errors } = run({ "packages/sdk/package-lock.json": lock(packages) });
  assert.deepEqual(errors.sort(), [
    "packages/sdk/package-lock.json: no-anything is not pinned (missing version, resolved, integrity)",
    "packages/sdk/package-lock.json: no-integrity is not pinned (missing integrity)",
  ]);
});

test("a lockfile anywhere in the repository is read", () => {
  const { errors } = run({ "docs/example/package-lock.json": lock({ "node_modules/g": { license: "MIT" } }) });
  assert.equal(errors.length, 1);
  assert.match(errors[0], /docs\/example\/package-lock\.json: g is not pinned/);
});

test("other lockfile kinds fail: the gate reads only package-lock.json", () => {
  for (const name of ["npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]) {
    const { errors } = run({ [`apps/a/${name}`]: "{}\n" });
    assert.equal(errors.length, 1, `${name}: ${errors.join("; ")}`);
    assert.match(errors[0], /only package-lock\.json is read/);
  }
});

test("a package.json with dependencies but no package-lock.json fails; workspace members use the root lock", () => {
  const unlocked = { "packages/sdk/package.json": { name: "sdk", dependencies: { left: "1.0.0" } } };
  const { errors } = run(unlocked);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /packages\/sdk\/package\.json: declares dependencies but has no package-lock\.json/);
  assert.deepEqual(run({ "packages/sdk/package.json": { name: "sdk", scripts: { build: "tsc" } } }).errors, []);
  const member = {
    ...unlocked,
    "package.json": { name: "root", private: true, workspaces: ["packages/sdk"] },
    "package-lock.json": lock({ "packages/sdk": { name: "sdk" } }),
  };
  assert.deepEqual(run(member).errors, []);
});
