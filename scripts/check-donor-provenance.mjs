#!/usr/bin/env node
// WP1-01 donor provenance gate (founder decision 2026-11-17).
//
// Every vendored, copied or adapted donor file needs an entry in the
// machine-readable manifest docs/orcel/notices/donor-provenance.json whose
// donor records the source repository, the pin (40-hex commit, or a registry
// release with its SHA-256), the upstream licence, the notice, and the
// founder attestation that records permission separately from the licence.
//
// A file under crates/, apps/, packages/ or tests/ is a donor file when
// - it lies under a third_party/ directory, or
// - it names a donor notice (docs/orcel/notices/<file>), or
// - an "orcel-adapted-source-provenance/1" record lists it,
// and each one must be covered by a manifest file entry (an exact path, or a
// directory entry ending in '/') or by a reviewed "references" entry. Every
// per-task provenance record (docs/orcel/*_provenance.json,
// */third_party/PROVENANCE.json) must be consolidated by a donor.
//
// Restricted-licence donors (AGPL, GPL, LGPL, MPL, SSPL, BUSL, FSL, commercial)
// must cite an attestation for their family, and each of their files in the
// scanned trees must be on that decision's allowlist (fd06-files.txt,
// fd04-files.txt) or inside an isolated component; every allowlisted path in
// turn needs such a donor entry.
//
// Usage: node scripts/check-donor-provenance.mjs [--root <repository>]

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  familiesOfExpression,
  listFiles,
  PROVENANCE_PATH,
  readJson,
  readList,
  readPolicy,
  readText,
  underAny,
} from "./licence-gate-lib.mjs";

const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const NOTICE_REF = /docs\/orcel\/notices\/[A-Za-z0-9._-]*[A-Za-z0-9_-]/g;
// The gates' own policy files live beside the notices but are not notices.
const GATE_FILE = /\/(licence-policy\.json|donor-provenance\.json|fd\d+-files\.txt)$/;
const RECORD =/^(docs\/orcel\/[^/]+_provenance\.json|.+\/third_party\/PROVENANCE\.json)$/;

function exists(root, path) {
  return typeof path === "string" && path.length > 0 && existsSync(join(root, path));
}

function covers(entryPath, path) {
  return entryPath.endsWith("/") ? path.startsWith(entryPath) : entryPath === path;
}

function checkDonor(root, id, donor, attestations, errors) {
  const where = `donor ${id}`;
  if (!REPO.test(donor.repo ?? "")) errors.push(`${where}: repo must be "owner/name"`);
  if (donor.commit !== undefined) {
    if (!SHA1.test(donor.commit)) errors.push(`${where}: commit must be a 40-hex SHA`);
  } else if (donor.release) {
    const r = donor.release;
    const hashes = Array.isArray(r.sha256) ? r.sha256 : [r.sha256];
    if (!r.registry || !r.name || !r.version) errors.push(`${where}: release needs registry, name and version`);
    if (!hashes.length || !hashes.every((h) => SHA256.test(h ?? ""))) {
      errors.push(`${where}: release needs its SHA-256 pin(s)`);
    }
  } else {
    errors.push(`${where}: needs a pinned commit or release`);
  }
  if (typeof donor.licence !== "string" || !donor.licence.trim()) errors.push(`${where}: licence is required`);
  if (!exists(root, donor.notice)) errors.push(`${where}: notice ${donor.notice} does not exist`);
  const attestation = attestations[donor.attestation];
  if (!attestation) errors.push(`${where}: attestation ${donor.attestation} is not defined`);
  for (const record of donor.records ?? []) {
    if (!exists(root, record)) errors.push(`${where}: record ${record} does not exist`);
  }
  return attestation;
}

export function checkProvenance(root) {
  const policy = readPolicy(root);
  const manifest = readJson(root, PROVENANCE_PATH);
  const allowed = new Set(policy.allowed_licences);
  const errors = [];
  const attestations = manifest.attestations ?? {};
  for (const [id, attestation] of Object.entries(attestations)) {
    if (!Array.isArray(attestation.records) || !attestation.records.length) {
      errors.push(`attestation ${id}: needs at least one record`);
    }
    for (const record of attestation.records ?? []) {
      if (!exists(root, record)) errors.push(`attestation ${id}: record ${record} does not exist`);
    }
  }

  const donors = manifest.donors ?? {};
  const restricted = new Map();
  for (const [id, donor] of Object.entries(donors)) {
    const attestation = checkDonor(root, id, donor, attestations, errors);
    const families = typeof donor.licence === "string" ? familiesOfExpression(donor.licence, allowed) : [];
    if (!families.length) continue;
    restricted.set(id, { families, decision: donor.attestation });
    for (const family of families) {
      if (!attestation?.families?.includes(family)) {
        errors.push(`donor ${id}: ${family} licence needs an attestation that covers ${family}, not ${donor.attestation}`);
      }
    }
  }

  const entries = manifest.files ?? [];
  const references = manifest.references ?? [];
  for (const entry of entries) {
    if (!donors[entry.donor]) errors.push(`file ${entry.path}: unknown donor ${entry.donor}`);
    if (!exists(root, entry.path)) {
      errors.push(`file ${entry.path}: does not exist`);
    } else if (entry.path.endsWith("/") !== statSync(join(root, entry.path)).isDirectory()) {
      errors.push(`file ${entry.path}: a directory entry must end in '/', a file entry must not`);
    }
  }
  for (const reference of references) {
    if (!exists(root, reference.path)) errors.push(`reference ${reference.path}: does not exist`);
    if (!reference.reason) errors.push(`reference ${reference.path}: needs a reason`);
  }
  const covered = (path) => entries.some((e) => covers(e.path, path)) || references.some((r) => covers(r.path, path));

  // Records: every per-task record is consolidated, and adapted-source
  // records' files are covered.
  const files = listFiles(root);
  const consolidated = new Set([
    ...Object.values(donors).flatMap((d) => d.records ?? []),
    ...references.map((r) => r.path),
  ]);
  const required = new Map();
  const need = (path, why) => {
    if (!required.has(path)) required.set(path, why);
  };
  for (const record of files.filter((path) => RECORD.test(path))) {
    if (!consolidated.has(record)) errors.push(`${record}: provenance record not consolidated by any donor in ${PROVENANCE_PATH}`);
    let data;
    try {
      data = JSON.parse(readFileSync(join(root, record), "utf8"));
    } catch (error) {
      errors.push(`${record}: not valid JSON (${error.message})`);
      continue;
    }
    if (data.schema === "orcel-adapted-source-provenance/1") {
      for (const file of data.files ?? []) {
        if (typeof file.path === "string") need(file.path, `listed in ${record}`);
      }
    }
  }

  // Donor files found in the scanned trees.
  for (const path of files) {
    if (!underAny(path, policy.scan_roots) || path === PROVENANCE_PATH) continue;
    if (path.includes("/third_party/")) {
      need(path, "under a third_party/ directory");
      continue;
    }
    const text = readText(root, path);
    if (text === null) continue;
    const notices = [...new Set(text.match(NOTICE_REF) ?? [])].filter((ref) => !GATE_FILE.test(ref));
    if (notices.length) need(path, `names ${notices.join(", ")}`);
  }
  for (const [path, why] of required) {
    if (!covered(path)) errors.push(`${path}: donor file (${why}) has no entry in ${PROVENANCE_PATH}`);
  }

  // Restricted donors against the founder-decision allowlists.
  const isolated = policy.isolated_components ?? [];
  const lists = new Map();
  for (const [decision, entry] of Object.entries(policy.restricted_allowlists ?? {})) {
    lists.set(decision, exists(root, entry.list) ? new Set(readList(root, entry.list)) : new Set());
  }
  for (const entry of entries) {
    const info = restricted.get(entry.donor);
    if (!info || !underAny(entry.path, policy.scan_roots)) continue;
    if (isolated.some((c) => c.path && entry.path.startsWith(c.path))) continue;
    if (entry.path.endsWith("/")) {
      errors.push(`file ${entry.path}: a restricted-licence donor (${info.families.join(", ")}) must list files, not a directory, outside an isolated component`);
      continue;
    }
    if (!lists.get(info.decision)?.has(entry.path)) {
      errors.push(`file ${entry.path}: ${info.families.join(", ")} donor ${entry.donor} but not on the ${info.decision} allowlist`);
    }
  }
  for (const [decision, paths] of lists) {
    for (const path of paths) {
      const ok = entries.some((e) => e.path === path && restricted.get(e.donor)?.decision === decision);
      if (!ok) errors.push(`${decision} allowlist: ${path} has no ${decision} donor entry in ${PROVENANCE_PATH}`);
    }
  }
  return { errors, donors: Object.keys(donors).length, entries: entries.length, required: required.size };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--root");
  const root = flag > 0 ? resolve(process.argv[flag + 1]) : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const { errors, donors, entries, required } = checkProvenance(root);
  if (errors.length) {
    for (const error of errors) console.error(`check-donor-provenance: ${error}`);
    process.exit(1);
  }
  console.log(`check-donor-provenance: ${required} donor files covered by ${entries} entries of ${donors} pinned donors`);
}
