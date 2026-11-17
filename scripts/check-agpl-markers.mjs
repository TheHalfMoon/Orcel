#!/usr/bin/env node
// WP1-01 licence-marker scan, reworked for the founder decision of
// 2026-11-17 (docs/orcel/grants/2026-11-17-founder-attestation.md):
// "all sources i have sent to you and all sources in the repo are legally
// and i have permission to copy all of them and re name them to orcel. so
// not worry about the licness anymore".
//
// A licence type no longer blocks anything. A licence marker is evidence of
// copied code, so it now requires provenance instead: every file under the
// policy's scan_roots that carries a third-party licence marker must be
// covered by an entry in
// docs/orcel/notices/donor-provenance.json: a donor file entry (pinned
// source, original licence and notice, owner-asserted authorization), or a
// reviewed "references" entry for files that only quote a licence.
// A marker is an SPDX-License-Identifier other than Orcel's own licence, or
// a phrase from a licence text or header (the GNU AGPL, GPL or LGPL title,
// "This program is free software", the Mozilla, Server Side, Business Source
// or Functional Source licence titles, the MIT grant, the BSD redistribution
// clause). A bare licence name in Orcel's own prose ("unlike GPLv3 tools")
// is not a marker.
// A file the scan cannot read (binary, archive, larger than 4 MiB) needs a
// provenance entry or an unreadable_exceptions entry in licence-policy.json.
// UTF-16 with a byte-order mark is read. Lockfiles are left to the
// dependency checks.
//
// Usage: node scripts/check-agpl-markers.mjs [--root <repository>]

import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listFiles, markerFamilies, PROVENANCE_PATH, readJson, readPolicy, readScan, rootFromArgs, underAny } from "./licence-gate-lib.mjs";

const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|[^/]*\.lock|pnpm-lock\.yaml|bun\.lockb)$/;

function coveredBy(entries, path) {
  return entries.some((e) => (e.path.endsWith("/") ? path.startsWith(e.path) : e.path === path));
}

export function checkMarkers(root) {
  const policy = readPolicy(root);
  const own = new Set([policy.orcel_licence]);
  const errors = [];
  let entries = [];
  if (existsSync(join(root, PROVENANCE_PATH))) {
    const manifest = readJson(root, PROVENANCE_PATH);
    entries = [...(manifest.files ?? []), ...(manifest.references ?? [])].filter((e) => typeof e.path === "string");
  } else {
    errors.push(`${PROVENANCE_PATH} is missing`);
  }
  const unreadableExceptions = policy.unreadable_exceptions ?? [];
  for (const exception of unreadableExceptions) {
    if (!exception.reason || !exception.path) errors.push(`unreadable exception ${exception.path}: needs a path and a reason`);
  }

  const files = listFiles(root).filter((path) => underAny(path, policy.scan_roots) && !LOCKFILE.test(path));
  let scanned = 0;
  let marked = 0;
  for (const path of files) {
    const read = readScan(root, path);
    if (read.unreadable) {
      if (!coveredBy(entries, path) && !coveredBy(unreadableExceptions, path)) {
        errors.push(`${path}: ${read.unreadable} file the marker scan cannot read, with no provenance entry or unreadable exception`);
      }
      continue;
    }
    scanned += 1;
    const lines = read.text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const families = markerFamilies(lines[index], own);
      if (!families.length) continue;
      marked += 1;
      if (!coveredBy(entries, path)) {
        errors.push(
          `${path}:${index + 1}: ${families.join(", ")} licence marker in a file with no provenance entry: ${lines[index].trim().slice(0, 160)}`,
        );
        break;
      }
    }
  }
  return { errors, scanned, marked };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = rootFromArgs(process.argv, resolve(dirname(fileURLToPath(import.meta.url)), ".."), "check-agpl-markers");
  const { errors, scanned, marked } = checkMarkers(root);
  if (errors.length) {
    for (const error of errors) console.error(`check-agpl-markers: ${error}`);
    process.exit(1);
  }
  console.log(`check-agpl-markers: ${scanned} files scanned; ${marked} licence-marker lines, all in files with provenance`);
}
