#!/usr/bin/env node
// WP1-01 licence coverage for every Cargo project in the repository.
//
// Coverage (always): every Cargo.toml must be under a licence gate: a member
// of the main workspace (root deny.toml and crates/orceld/tests/
// dependency_direction.rs), inside a separate workspace with its own
// deny.toml (apps/*/deny.toml, run by its CI job), or listed in
// licence-policy.json cargo_fixtures.
//
// Fixtures (--fixtures): each cargo_fixtures entry is a Cargo project that
// cannot carry its own deny.toml (tests/native-fixtures holds upstream Cua
// bytes only, proven by scripts/check-vendored-cua.mjs) and has no lockfile.
// The project is copied to a temporary directory (so it resolves outside the
// main workspace and writes nothing into the checkout), `cargo metadata`
// resolves it (default features: the fixture's only feature selects a Tauri
// build mode), and every package's licence must pass the
// WP1-01 allowlist or a named exception of that fixture (crate, licence,
// reason). Exceptions that match nothing fail. The fixture has no lockfile
// of its own; "lock_from" names a reviewed lockfile copied in first, so the
// shared graph resolves to its versions and only the remainder floats.
// Resolution needs the crates.io index and crate downloads, so CI runs it.
//
// Usage: node scripts/check-cargo-licences.mjs [--root <repository>] [--fixtures]

import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listFiles, readPolicy, spdxAllowed } from "./licence-gate-lib.mjs";

/** Cargo.toml files no licence gate covers. */
export function uncoveredManifests(root, policy, files = listFiles(root)) {
  const manifests = files.filter((p) => p === "Cargo.toml" || p.endsWith("/Cargo.toml"));
  const denyDirs = files
    .filter((p) => p.endsWith("/deny.toml"))
    .map((p) => `${posix.dirname(p)}/`);
  const fixtures = (policy.cargo_fixtures ?? []).map((f) => f.manifest);
  const errors = [];
  for (const fixture of fixtures) {
    if (!manifests.includes(fixture)) errors.push(`cargo fixture ${fixture} does not exist`);
  }
  for (const manifest of manifests) {
    if (manifest === "Cargo.toml" || manifest.startsWith("crates/")) continue;
    if (denyDirs.some((dir) => manifest.startsWith(dir))) continue;
    if (fixtures.includes(manifest)) continue;
    errors.push(`${manifest}: no licence gate covers this Cargo project (no deny.toml above it, not in cargo_fixtures)`);
  }
  return errors;
}

/** Licence findings for one fixture's `cargo metadata`. */
export function fixtureLicenceErrors(meta, policy, fixture) {
  const allowed = new Set(policy.allowed_licences);
  const exceptions = (fixture.exceptions ?? []).map((e) => ({ ...e, used: false }));
  const errors = [];
  for (const exception of exceptions) {
    if (!exception.crate || !exception.reason || !("licence" in exception)) {
      errors.push(`${fixture.manifest}: exception ${exception.crate} needs crate, licence (null for none) and reason`);
    }
  }
  for (const pkg of meta.packages ?? []) {
    const licence = pkg.license ?? null;
    if (licence !== null && spdxAllowed(licence, allowed)) continue;
    const exception = exceptions.find((e) => e.crate === pkg.name && e.licence === licence);
    if (exception) {
      exception.used = true;
      continue;
    }
    const what = licence === null ? "no declared licence" : `licence "${licence}"`;
    errors.push(`${fixture.manifest}: ${pkg.name} ${pkg.version} has ${what}, not on the allowlist and with no named exception`);
  }
  for (const exception of exceptions) {
    if (!exception.used) errors.push(`${fixture.manifest}: exception ${exception.crate} (${exception.licence}) matches nothing; remove it`);
  }
  return errors;
}

function fixtureMetadata(root, fixture) {
  const scratch = mkdtempSync(join(tmpdir(), "orcel-cargo-fixture-"));
  try {
    cpSync(join(root, dirname(fixture.manifest)), scratch, { recursive: true });
    // A reviewed lockfile of a sibling project with the same framework pins
    // the shared part of the graph; cargo adds only what it lacks.
    if (fixture.lock_from) cpSync(join(root, fixture.lock_from), join(scratch, "Cargo.lock"));
    const out = execFileSync(
      "cargo",
      ["metadata", "--format-version", "1", "--manifest-path", join(scratch, "Cargo.toml")],
      { maxBuffer: 512 * 1024 * 1024, env: { ...process.env, CARGO_TARGET_DIR: join(scratch, "target") } },
    );
    return JSON.parse(out.toString());
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--root");
  const root = flag > 0 ? resolve(process.argv[flag + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const policy = readPolicy(root);
  const errors = uncoveredManifests(root, policy);
  let checked = 0;
  if (process.argv.includes("--fixtures")) {
    for (const fixture of policy.cargo_fixtures ?? []) {
      if (!existsSync(join(root, fixture.manifest))) continue;
      const meta = fixtureMetadata(root, fixture);
      checked += meta.packages.length;
      errors.push(...fixtureLicenceErrors(meta, policy, fixture));
    }
  }
  if (errors.length) {
    for (const error of errors) console.error(`check-cargo-licences: ${error}`);
    process.exit(1);
  }
  console.log(
    `check-cargo-licences: every Cargo project is under a licence gate${checked ? `; ${checked} fixture packages pass` : ""}`,
  );
}
