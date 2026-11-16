#!/usr/bin/env node
// WP1-01 licence marker scan (UNIFIED_INTEGRATION_SPEC.md C-15, C-16).
//
// Scans every file under the policy's scan_roots (crates/, apps/, packages/,
// tests/, distribution/, examples/, scripts/, third_party/) for markers of
// restricted licences: AGPL ("GNU AFFERO", "AGPL", an SPDX AGPL identifier),
// GPL, LGPL, MPL, SSPL, BUSL, FSL, and any SPDX-License-Identifier whose
// expression is not satisfiable from the WP1-01 allowlist (commercial,
// LicenseRef or unknown). A marker is accepted only:
// - in a file on the founder-decision allowlist for its family
//   (docs/orcel/notices/fd06-files.txt for AGPL, fd04-files.txt for FSL),
//   each entry pinned by the SHA-256 of its content, so any change to an
//   allowlisted file (new AGPL code included, C-15) fails until reviewed;
// - inside an isolated component that admits the family;
// - in a file named by a marker exception that pins the exact number of
//   markers per family, with a reason.
// A file the scan cannot read (binary, archive, larger than 4 MiB) fails
// unless donor-provenance.json covers it or licence-policy.json lists it in
// unreadable_exceptions. UTF-16 with a byte-order mark is read. Lockfiles are
// left to the dependency checks. Entries that no longer match fail too.
//
// Usage: node scripts/check-agpl-markers.mjs [--root <repository>] [--pins]
//   --pins prints the current pins (allowlist hashes, exception counts) for
//   a reviewed update instead of checking.

import { existsSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  contentSha256,
  listFiles,
  markerFamilies,
  PROVENANCE_PATH,
  readJson,
  readPinnedList,
  readPolicy,
  readScan,
  underAny,
} from "./licence-gate-lib.mjs";

const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|[^/]*\.lock|pnpm-lock\.yaml|bun\.lockb)$/;

function coveredBy(entries, path) {
  return entries.some((e) => (e.path.endsWith("/") ? path.startsWith(e.path) : e.path === path));
}

export function checkMarkers(root) {
  const policy = readPolicy(root);
  const allowed = new Set(policy.allowed_licences);
  const errors = [];
  const pins = { lists: {}, exceptions: {} };
  const allowlists = new Map();
  for (const [decision, entry] of Object.entries(policy.restricted_allowlists ?? {})) {
    if (!existsSync(join(root, entry.list))) {
      errors.push(`${decision}: allowlist ${entry.list} is missing`);
      continue;
    }
    const paths = new Set();
    pins.lists[entry.list] = [];
    for (const { sha256, path } of readPinnedList(root, entry.list)) {
      paths.add(path);
      if (!existsSync(join(root, path)) || !statSync(join(root, path)).isFile()) {
        errors.push(`${entry.list}: ${path} does not exist`);
        continue;
      }
      const actual = contentSha256(root, path);
      pins.lists[entry.list].push(`${actual}  ${path}`);
      if (!underAny(path, policy.scan_roots)) errors.push(`${entry.list}: ${path} is outside the scanned trees`);
      if (sha256 === null) {
        errors.push(`${entry.list}: ${path} is not pinned ("<sha256>  <path>")`);
      } else if (sha256 !== actual) {
        errors.push(`${entry.list}: ${path} changed (pinned ${sha256}, now ${actual}); review it under ${decision} and re-pin`);
      }
    }
    allowlists.set(decision, { families: entry.families, paths });
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
    const counts = exception.markers ?? {};
    if (!exception.reason || !Object.keys(counts).length || !Object.values(counts).every((n) => Number.isInteger(n) && n > 0)) {
      errors.push(`marker exception ${exception.path}: needs a reason and a positive marker count per family`);
    }
    if (exceptions.has(exception.path)) errors.push(`marker exception ${exception.path}: listed twice`);
    exceptions.set(exception.path, { counts, seen: {} });
  }
  let provenanceEntries = [];
  if (existsSync(join(root, PROVENANCE_PATH))) {
    const manifest = readJson(root, PROVENANCE_PATH);
    provenanceEntries = [...(manifest.files ?? []), ...(manifest.references ?? [])].filter((e) => typeof e.path === "string");
  }
  const unreadableExceptions = policy.unreadable_exceptions ?? [];
  for (const exception of unreadableExceptions) {
    if (!exception.reason || !exception.path) errors.push(`unreadable exception ${exception.path}: needs a path and a reason`);
  }

  const files = listFiles(root).filter((path) => underAny(path, policy.scan_roots) && !LOCKFILE.test(path));
  const fileSet = new Set(files);
  let scanned = 0;
  let accepted = 0;
  for (const path of files) {
    const read = readScan(root, path);
    if (read.unreadable) {
      if (!coveredBy(provenanceEntries, path) && !coveredBy(unreadableExceptions, path)) {
        errors.push(`${path}: ${read.unreadable} file the marker scan cannot read, with no provenance entry or unreadable exception`);
      }
      continue;
    }
    scanned += 1;
    const lines = read.text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      for (const family of markerFamilies(lines[index], allowed)) {
        const byDecision = [...allowlists.values()].some((list) => list.families.includes(family) && list.paths.has(path));
        const byComponent = isolated.some((c) => c.path && path.startsWith(c.path) && c.families?.includes(family));
        const exception = exceptions.get(path);
        if (exception) exception.seen[family] = (exception.seen[family] ?? 0) + 1;
        if (byDecision || byComponent || exception?.counts[family]) {
          accepted += 1;
          continue;
        }
        const where = `${path}:${index + 1}`;
        errors.push(`${where}: ${family} licence marker outside the allowlists: ${lines[index].trim().slice(0, 160)}`);
      }
    }
  }
  for (const [path, exception] of exceptions) {
    pins.exceptions[path] = exception.seen;
    if (!fileSet.has(path)) {
      errors.push(`marker exception ${path}: no such file in the scanned trees`);
      continue;
    }
    for (const [family, count] of Object.entries(exception.counts)) {
      const seen = exception.seen[family] ?? 0;
      if (seen !== count) {
        errors.push(`marker exception ${path}: ${family} marker count is ${seen}, pinned ${count}; review the change and re-pin`);
      }
    }
  }
  return { errors, scanned, accepted, pins };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--root");
  const root = flag > 0 ? resolve(process.argv[flag + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const { errors, scanned, accepted, pins } = checkMarkers(root);
  if (process.argv.includes("--pins")) {
    console.log(JSON.stringify(pins, null, 2));
    process.exit(0);
  }
  if (errors.length) {
    for (const error of errors) console.error(`check-agpl-markers: ${error}`);
    process.exit(1);
  }
  console.log(`check-agpl-markers: ${scanned} files scanned; ${accepted} restricted-licence markers, all on a pinned allowlist`);
}
