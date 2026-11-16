// WP1-01 definition of done: "a fixture crate with an AGPL dependency ...
// fails". Runs cargo-deny 0.20.2 with the root deny.toml against throwaway
// workspaces whose only dependency is a local path crate, so nothing is
// downloaded. Without cargo-deny the tests skip, unless
// ORCEL_REQUIRE_CARGO_DENY=1 (CI), which turns a missing tool into a failure.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { makeTree, removeTree } from "./licence-gate-fixture.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DENY = join(REPO, "deny.toml");

const probe = spawnSync("cargo", ["deny", "--version"], { encoding: "utf8" });
const available = probe.status === 0;
const required = process.env.ORCEL_REQUIRE_CARGO_DENY === "1";
const skip = !available && !required ? "cargo-deny is not installed" : false;

function manifest(name, license, dependency) {
  const lines = [
    "[package]",
    `name = "${name}"`,
    'version = "0.1.0"',
    'edition = "2021"',
    `license = "${license}"`,
    "publish = false",
    "",
  ];
  if (dependency) lines.push("[dependencies]", `${dependency} = { path = "../${dependency}" }`, "");
  return lines.join("\n");
}

// A two-crate workspace: `core` (Apache-2.0, like every crates/* unit)
// depending on `dep` under the given licence.
function deny(depLicense) {
  const root = makeTree({
    "Cargo.toml": '[workspace]\nresolver = "2"\nmembers = ["core", "dep"]\n',
    "core/Cargo.toml": manifest("fixture-core", "Apache-2.0", "dep"),
    "core/src/lib.rs": "pub use dep::f;\n",
    "dep/Cargo.toml": manifest("dep", depLicense),
    "dep/src/lib.rs": "pub fn f() {}\n",
  });
  try {
    const result = spawnSync(
      "cargo",
      ["deny", "--manifest-path", join(root, "Cargo.toml"), "--config", DENY, "--workspace", "check", "licenses"],
      { encoding: "utf8", env: { ...process.env, CARGO_TARGET_DIR: join(root, "target") } },
    );
    return { status: result.status, output: `${result.stdout}\n${result.stderr}` };
  } finally {
    removeTree(root);
  }
}

test("cargo-deny is available where the gate requires it", { skip: required ? false : "not required here" }, () => {
  assert.equal(available, true, `cargo deny --version failed: ${probe.stderr ?? probe.error}`);
});

test("the root deny.toml admits a permissive path dependency", { skip }, () => {
  const { status, output } = deny("MIT");
  assert.equal(status, 0, output);
});

test("the root deny.toml refuses a fixture crate with an AGPL dependency", { skip }, () => {
  const { status, output } = deny("AGPL-3.0-only");
  assert.notEqual(status, 0, output);
  assert.match(output, /AGPL-3\.0-only/);
  assert.match(output, /licenses FAILED/);
});

test("GPL, LGPL, SSPL, BUSL, FSL and MPL dependencies are refused too", { skip }, () => {
  for (const license of ["GPL-3.0-only", "LGPL-2.1-or-later", "SSPL-1.0", "BUSL-1.1", "FSL-1.1-MIT", "MPL-2.0"]) {
    const { status, output } = deny(license);
    assert.notEqual(status, 0, `${license} passed:\n${output}`);
  }
});
