// Runs cargo-deny 0.20.2 with the root deny.toml against throwaway
// workspaces whose only dependency is a local path crate, so nothing is
// downloaded. Founder decision of 2026-11-17: a licence type blocks nothing,
// so CI checks bans and sources only; these tests prove an AGPL-licensed or
// unlicensed dependency passes and the AD-16 bans still refuse. Without
// cargo-deny the tests skip, unless ORCEL_REQUIRE_CARGO_DENY=1 (CI), which
// turns a missing tool into a failure.

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
  const lines = ["[package]", `name = "${name}"`, 'version = "0.1.0"', 'edition = "2021"'];
  if (license) lines.push(`license = "${license}"`);
  lines.push("publish = false", "");
  if (dependency) lines.push("[dependencies]", `${dependency} = { path = "../${dependency}" }`, "");
  return lines.join("\n");
}

// A two-crate workspace: `core` (Apache-2.0) depending on `dep`.
function deny(depName, depLicense) {
  const root = makeTree({
    "Cargo.toml": `[workspace]\nresolver = "2"\nmembers = ["core", "${depName}"]\n`,
    "core/Cargo.toml": manifest("fixture-core", "Apache-2.0", depName),
    "core/src/lib.rs": `pub use ${depName.replace(/-/g, "_")}::f;\n`,
    [`${depName}/Cargo.toml`]: manifest(depName, depLicense),
    [`${depName}/src/lib.rs`]: "pub fn f() {}\n",
  });
  try {
    const result = spawnSync(
      "cargo",
      ["deny", "--manifest-path", join(root, "Cargo.toml"), "--config", DENY, "--workspace", "check", "bans", "sources"],
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

test("the root deny.toml no longer judges licences: AGPL, commercial and unlicensed dependencies pass", { skip }, () => {
  for (const license of ["MIT", "AGPL-3.0-only", "LicenseRef-Commercial", null]) {
    const { status, output } = deny("dep", license);
    assert.equal(status, 0, `${license}:\n${output}`);
  }
});

test("the root deny.toml still bans tokio in the main graph (AD-16)", { skip }, () => {
  const { status, output } = deny("tokio", "MIT");
  assert.notEqual(status, 0, output);
  assert.match(output, /bans FAILED/);
});
