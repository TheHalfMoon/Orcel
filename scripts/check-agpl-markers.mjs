#!/usr/bin/env node
// WP1-01 licence marker scan (UNIFIED_INTEGRATION_SPEC.md C-15, C-16).
//
// Scans every file under crates/, apps/, packages/ and tests/ for markers of
// restricted licences: AGPL ("GNU AFFERO", "AGPL", an SPDX AGPL identifier),
// GPL, LGPL, MPL, SSPL, BUSL, FSL, and any SPDX-License-Identifier whose
// expression is not satisfiable from the WP1-01 allowlist (commercial,
// LicenseRef or unknown). A marker is accepted only:
// - in a file on the founder-decision allowlist for its family
//   (docs/orcel/notices/fd06-files.txt for AGPL, fd04-files.txt for FSL);
// - inside an isolated component that admits the family
//   (licence-policy.json isolated_components);
// - in a file named by a marker exception that lists the family and a reason.
// Lockfiles are left to the dependency checks (root deny.toml,
// check-npm-licenses.mjs). Allowlist entries and exceptions that no longer
// match are errors too, so the lists cannot go stale.
//
// Usage: node scripts/check-agpl-markers.mjs [--root <repository>]

import { existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listFiles, markerFamilies, readList, readPolicy, readText, underAny } from "./licence-gate-lib.mjs";

const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|[^/]*\.lock)$/;

export function checkMarkers(root) {
  const policy = readPolicy(root);
  const allowed = new Set(policy.allowed_licences);
  const errors = [];
  const allowlists = new Map();
  for (const [decision, entry] of Object.entries(policy.restricted_allowlists ?? {})) {
    if (!existsSync(join(root, entry.list))) {
      errors.push(`${decision}: allowlist ${entry.list} is missing`);
      continue;
    }
    const paths = readList(root, entry.list);
    for (const path of paths) {
      if (!existsSync(join(root, path)) || !statSync(join(root, path)).isFile()) {
        errors.push(`${entry.list}: ${path} does not exist`);
      }
      if (!underAny(path, policy.scan_roots)) errors.push(`${entry.list}: ${path} is outside the scanned trees`);
    }
    allowlists.set(decision, { families: entry.families, paths: new Set(paths) });
  }
  const isolated = policy.isolated_components ?? [];
  for (const component of isolated) {
    if (!component.path?.endsWith("/") || !existsSync(join(root, component.path))) {
      errors.push(`isolated component ${component.path}: must be an existing directory ending in '/'`);
    }
    if (component.path?.startsWith("crates/")) {
      errors.push(`isolated component ${component.path}: a core crate cannot be an isolated component`);
    }
    if (!component.reason || !component.attestation || !Array.isArray(component.families)) {
      errors.push(`isolated component ${component.path}: needs families, attestation and reason`);
    }
  }
  const exceptions = new Map();
  for (const exception of policy.marker_exceptions ?? []) {
    if (!exception.reason || !Array.isArray(exception.families) || !exception.families.length) {
      errors.push(`marker exception ${exception.path}: needs families and a reason`);
    }
    if (exceptions.has(exception.path)) errors.push(`marker exception ${exception.path}: listed twice`);
    exceptions.set(exception.path, { families: new Set(exception.families), used: new Set() });
  }

  const files = listFiles(root).filter((path) => underAny(path, policy.scan_roots) && !LOCKFILE.test(path));
  const fileSet = new Set(files);
  let scanned = 0;
  let accepted = 0;
  for (const path of files) {
    const text = readText(root, path);
    if (text === null) continue;
    scanned += 1;
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      for (const family of markerFamilies(lines[index], allowed)) {
        const byDecision = [...allowlists.values()].some((list) => list.families.includes(family) && list.paths.has(path));
        const byComponent = isolated.some((c) => c.path && path.startsWith(c.path) && c.families?.includes(family));
        const exception = exceptions.get(path);
        const byException = exception?.families.has(family);
        if (byException) exception.used.add(family);
        if (byDecision || byComponent || byException) {
          accepted += 1;
          continue;
        }
        const where = `${path}:${index + 1}`;
        errors.push(`${where}: ${family} licence marker outside the allowlists: ${lines[index].trim().slice(0, 160)}`);
      }
    }
  }
  for (const [path, exception] of exceptions) {
    if (!fileSet.has(path)) {
      errors.push(`marker exception ${path}: no such file in the scanned trees`);
      continue;
    }
    for (const family of exception.families) {
      if (!exception.used.has(family)) errors.push(`marker exception ${path}: no ${family} marker left; remove it`);
    }
  }
  return { errors, scanned, accepted };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--root");
  const root = flag > 0 ? resolve(process.argv[flag + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const { errors, scanned, accepted } = checkMarkers(root);
  if (errors.length) {
    for (const error of errors) console.error(`check-agpl-markers: ${error}`);
    process.exit(1);
  }
  console.log(`check-agpl-markers: ${scanned} files scanned; ${accepted} restricted-licence markers, all on a reviewed allowlist`);
}
