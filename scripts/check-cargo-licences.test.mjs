import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { fixtureLicenceErrors, uncoveredManifests } from "./check-cargo-licences.mjs";
import { basePolicy } from "./licence-gate-fixture.mjs";
import { readPolicy } from "./licence-gate-lib.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = "tests/fx/src-tauri/Cargo.toml";

test("today: every Cargo project is under a licence gate", () => {
  assert.deepEqual(uncoveredManifests(REPO, readPolicy(REPO)), []);
});

test("a Cargo project with no deny.toml above it and no fixture entry fails", () => {
  const files = ["Cargo.toml", "crates/a/Cargo.toml", "apps/x/Cargo.toml", "apps/x/deny.toml", "apps/x/vendored/y/Cargo.toml", "tests/other/Cargo.toml"];
  const errors = uncoveredManifests(REPO, basePolicy(), files);
  assert.deepEqual(errors, ["tests/other/Cargo.toml: no licence gate covers this Cargo project (no deny.toml above it, not in cargo_fixtures)"]);
  const listed = basePolicy({ cargo_fixtures: [{ manifest: "tests/other/Cargo.toml", exceptions: [] }] });
  assert.deepEqual(uncoveredManifests(REPO, listed, files), []);
  const gone = basePolicy({ cargo_fixtures: [{ manifest: "tests/gone/Cargo.toml", exceptions: [] }] });
  assert.ok(uncoveredManifests(REPO, gone, files).some((e) => e.includes("cargo fixture tests/gone/Cargo.toml does not exist")));
});

function meta(packages) {
  return { packages: packages.map(([name, license]) => ({ name, version: "1.0.0", license })) };
}

test("fixture graphs: MPL, AGPL and unlicensed crates fail without a named exception", () => {
  const fixture = { manifest: FIXTURE, exceptions: [] };
  const errors = fixtureLicenceErrors(meta([["ok", "MIT OR Apache-2.0"], ["css", "MPL-2.0"], ["x", "AGPL-3.0-only"], ["root", null]]), basePolicy(), fixture);
  assert.equal(errors.length, 3, errors.join("\n"));
  assert.ok(errors.some((e) => e.includes('css 1.0.0 has licence "MPL-2.0"')));
  assert.ok(errors.some((e) => e.includes("root 1.0.0 has no declared licence")));
});

test("fixture exceptions admit exactly their crate and licence, and must stay in use", () => {
  const fixture = {
    manifest: FIXTURE,
    exceptions: [
      { crate: "css", licence: "MPL-2.0", reason: "r" },
      { crate: "root", licence: null, reason: "r" },
      { crate: "gone", licence: "MPL-2.0", reason: "r" },
    ],
  };
  const errors = fixtureLicenceErrors(meta([["css", "MPL-2.0"], ["root", null], ["other", "MPL-2.0"]]), basePolicy(), fixture);
  assert.deepEqual(errors.sort(), [
    `${FIXTURE}: exception gone (MPL-2.0) matches nothing; remove it`,
    `${FIXTURE}: other 1.0.0 has licence "MPL-2.0", not on the allowlist and with no named exception`,
  ]);
});
