#!/usr/bin/env node
// WP1-01 npm licence check (UNIFIED_INTEGRATION_SPEC.md WP1-01, C-20).
//
// Reads every package-lock.json under apps/, packages/ and tests/, plus the
// root package-lock.json (the lockfile of the root npm workspaces, which
// live under apps/), and requires every locked package to declare a licence
// expression satisfiable from the WP1-01 allowlist in
// docs/orcel/notices/licence-policy.json (an OR expression passes when one
// branch is allowed). Lockfiles under tests/ may also use PSF-2.0. A package
// without a licence, with an unknown licence, or with an AGPL, GPL, LGPL,
// MPL, SSPL, BUSL, FSL or commercial licence fails unless a named exception
// in licence-policy.json lists that lockfile, that licence and that package
// with a reason. Exceptions that match nothing fail too.
//
// Usage: node scripts/check-npm-licenses.mjs [--root <repository>]

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { familiesOfExpression, listFiles, readPolicy, spdxAllowed, underAny } from "./licence-gate-lib.mjs";

const LOCK_ROOTS = ["apps/", "packages/", "tests/"];

function packageName(key) {
  const marker = "node_modules/";
  const at = key.lastIndexOf(marker);
  return at < 0 ? key : key.slice(at + marker.length);
}

export function lockfiles(root) {
  return listFiles(root).filter(
    (path) => path === "package-lock.json" || (underAny(path, LOCK_ROOTS) && path.endsWith("/package-lock.json")),
  );
}

export function checkNpmLicences(root) {
  const policy = readPolicy(root);
  const errors = [];
  const exceptions = (policy.npm_exceptions ?? []).map((entry) => ({ ...entry, used: new Set() }));
  for (const entry of exceptions) {
    if (!entry.reason || !entry.licence || !Array.isArray(entry.packages) || !entry.packages.length) {
      errors.push(`npm exception for ${entry.lockfile}: needs licence, packages and a reason`);
    }
  }
  const locks = lockfiles(root);
  let checked = 0;
  for (const lockfile of locks) {
    const testOnly = underAny(lockfile, policy.test_only_roots ?? []);
    const allowed = new Set([...policy.allowed_licences, ...(testOnly ? policy.test_only_extra_licences ?? [] : [])]);
    const lock = JSON.parse(readFileSync(join(root, lockfile), "utf8"));
    if (!lock.packages || typeof lock.packages !== "object") {
      errors.push(`${lockfile}: no "packages" map (lockfileVersion 2 or 3 is required)`);
      continue;
    }
    const lockDir = posix.dirname(lockfile);
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (key === "" || entry.link) continue;
      let licence = entry.license;
      const workspace = !key.includes("node_modules/");
      if (workspace && licence === undefined) {
        const manifest = join(root, lockDir === "." ? key : `${lockDir}/${key}`, "package.json");
        if (existsSync(manifest)) licence = JSON.parse(readFileSync(manifest, "utf8")).license;
      }
      checked += 1;
      const name = workspace ? key : packageName(key);
      const label = `${lockfile}: ${name}${entry.version ? `@${entry.version}` : ""}`;
      if (typeof licence !== "string" || !licence.trim()) {
        errors.push(`${label}: no licence declared`);
        continue;
      }
      if (spdxAllowed(licence, allowed)) continue;
      const exception = exceptions.find(
        (e) => e.lockfile === lockfile && e.licence === licence && e.packages?.includes(name),
      );
      if (exception) {
        exception.used.add(name);
        continue;
      }
      const families = familiesOfExpression(licence, allowed).join(", ");
      errors.push(`${label}: licence "${licence}" (${families}) is not on the allowlist and has no named exception`);
    }
  }
  for (const entry of exceptions) {
    if (!locks.includes(entry.lockfile)) {
      errors.push(`npm exception: lockfile ${entry.lockfile} does not exist`);
      continue;
    }
    for (const name of entry.packages ?? []) {
      if (!entry.used.has(name)) {
        errors.push(`npm exception: ${name} (${entry.licence}) no longer appears in ${entry.lockfile}; remove it`);
      }
    }
  }
  return { errors, lockfiles: locks, checked };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--root");
  const root = flag > 0 ? resolve(process.argv[flag + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const { errors, lockfiles: locks, checked } = checkNpmLicences(root);
  if (errors.length) {
    for (const error of errors) console.error(`check-npm-licenses: ${error}`);
    process.exit(1);
  }
  console.log(`check-npm-licenses: ${checked} locked packages in ${locks.length} lockfiles pass the WP1-01 allowlist`);
}
