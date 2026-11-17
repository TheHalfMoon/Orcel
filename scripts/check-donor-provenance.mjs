#!/usr/bin/env node
// WP1-01 donor provenance gate.
//
// Founder decision of 2026-11-17 (docs/orcel/grants/2026-11-17-founder-
// attestation.md, owner-asserted): every source may be copied and renamed to
// Orcel, and a licence type blocks nothing. What this gate requires instead
// is provenance for every copied donor file, in the machine-readable
// manifest docs/orcel/notices/donor-provenance.json:
// - per donor: source repository, pin (a 40-hex commit, or a registry
//   release with its SHA-256), the original licence as recorded upstream
//   (recorded, not judged), the original copyright or attribution notice
//   preserved in the repository (its licence file or notice must exist, be
//   non-empty and, for a licence whose text the gate knows, carry that
//   text), and the authorization reference "OWNER-ASSERTED AUTHORIZATION,
//   founder 2026-11-17" defined in the manifest with its grant record;
// - per file entry: its donor and its source path(s) at that pin; a
//   directory entry (ending in '/') also names its patch queue ("patches":
//   a file, or "none").
//
// A file in the scanned trees is a donor file when a path segment marks it
// as vendored (upstream/, vendor/, vendored/, third_party/ anywhere), when it
// names a donor notice (docs/orcel/notices/<file>), or when an
// "orcel-adapted-source-provenance/1" record lists it with a donor path.
// Each must be covered by a file entry or a reviewed "references" entry, and
// every per-task provenance record (docs/orcel/*_provenance.json,
// */third_party/PROVENANCE.json) must be consolidated by a donor.
//
// The manifest is central rather than one PROVENANCE.json per vendored
// directory: one entry per directory or file carries the same fields
// ({repo, sha, paths, licence, attestation_ref, patches}), and one file lets
// the gate check every record and authorization in one place.
//
// Usage: node scripts/check-donor-provenance.mjs [--root <repository>]

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DONOR_SEGMENT,
  licenceTextProblem,
  listFiles,
  PROVENANCE_PATH,
  readJson,
  readPolicy,
  readText,
  underAny,
  rootFromArgs,
} from "./licence-gate-lib.mjs";

const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const NOTICE_REF = /docs\/orcel\/notices\/[A-Za-z0-9._-]*[A-Za-z0-9_-]/g;
// The gates' own policy files live beside the notices but are not notices.
const GATE_FILE = /\/(licence-policy\.json|donor-provenance\.json)$/;
const RECORD = /^(docs\/orcel\/[^/]+_provenance\.json|.+\/third_party\/PROVENANCE\.json)$/;

function exists(root, path) {
  return typeof path === "string" && path.length > 0 && existsSync(join(root, path));
}

function covers(entryPath, path) {
  return entryPath.endsWith("/") ? path.startsWith(entryPath) : entryPath === path;
}

function checkDonor(root, id, donor, authorizations, required, errors) {
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
  if (typeof donor.licence !== "string" || !donor.licence.trim()) {
    errors.push(`${where}: the original licence must be recorded`);
  }
  if (!exists(root, donor.notice)) errors.push(`${where}: preserved notice ${donor.notice} does not exist`);
  const licenceText = donor.licence_text ?? donor.notice;
  if (donor.licence_text !== undefined && !exists(root, donor.licence_text)) {
    errors.push(`${where}: licence_text ${donor.licence_text} does not exist`);
  } else if (exists(root, licenceText) && typeof donor.licence === "string") {
    const problem = licenceTextProblem(donor.licence, readFileSync(join(root, licenceText), "utf8"));
    if (problem) errors.push(`${where}: preserved notice ${licenceText} ${problem}`);
  }
  if (donor.authorization !== required) {
    errors.push(`${where}: authorization must be "${required}"`);
  } else if (!authorizations[donor.authorization]) {
    errors.push(`${where}: authorization "${donor.authorization}" is not defined in the manifest`);
  }
  for (const record of [...(donor.records ?? []), ...(donor.earlier_records ?? [])]) {
    if (!exists(root, record)) errors.push(`${where}: record ${record} does not exist`);
  }
}

export function checkProvenance(root) {
  const policy = readPolicy(root);
  const manifest = readJson(root, PROVENANCE_PATH);
  const errors = [];
  const required = policy.founder_decision?.authorization;
  if (!required) errors.push("licence-policy.json: founder_decision.authorization is missing");
  const authorizations = manifest.authorizations ?? {};
  for (const [id, authorization] of Object.entries(authorizations)) {
    if (!Array.isArray(authorization.records) || !authorization.records.length) {
      errors.push(`authorization ${id}: needs at least one record`);
    }
    for (const record of authorization.records ?? []) {
      if (!exists(root, record)) errors.push(`authorization ${id}: record ${record} does not exist`);
    }
  }

  const donors = manifest.donors ?? {};
  for (const [id, donor] of Object.entries(donors)) checkDonor(root, id, donor, authorizations, required, errors);

  const entries = [];
  const references = [];
  for (const [list, out, kind] of [[manifest.files ?? [], entries, "file"], [manifest.references ?? [], references, "reference"]]) {
    for (const [index, entry] of list.entries()) {
      if (typeof entry?.path !== "string" || !entry.path) {
        errors.push(`${kind} entry ${index + 1} of ${PROVENANCE_PATH} has no "path"`);
      } else {
        out.push(entry);
      }
    }
  }
  for (const entry of entries) {
    if (!donors[entry.donor]) errors.push(`file ${entry.path}: unknown donor ${entry.donor}`);
    const sources = Array.isArray(entry.source) ? entry.source : [];
    if (!sources.length || !sources.every((s) => typeof s === "string" && s.trim())) {
      errors.push(`file ${entry.path}: needs its source path(s) at the donor's pin ("source": [...])`);
    }
    if (!exists(root, entry.path)) {
      errors.push(`file ${entry.path}: does not exist`);
    } else if (entry.path.endsWith("/") !== statSync(join(root, entry.path)).isDirectory()) {
      errors.push(`file ${entry.path}: a directory entry must end in '/', a file entry must not`);
    } else if (entry.path.endsWith("/") && entry.patches !== "none" && !exists(root, entry.patches)) {
      errors.push(`file ${entry.path}: a directory entry needs "patches": an existing patch queue file, or "none"`);
    }
  }
  for (const reference of references) {
    if (!exists(root, reference.path)) errors.push(`reference ${reference.path}: does not exist`);
    if (!reference.reason) errors.push(`reference ${reference.path}: needs a reason`);
  }
  const covered = (path) => entries.some((e) => covers(e.path, path)) || references.some((r) => covers(r.path, path));

  // Records: every per-task record is consolidated, and the files that
  // adapted-source records copy from a donor path are covered.
  const files = listFiles(root);
  const consolidated = new Set([
    ...Object.values(donors).flatMap((d) => d.records ?? []),
    ...references.map((r) => r.path),
  ]);
  const needed = new Map();
  const need = (path, why) => {
    if (!needed.has(path)) needed.set(path, why);
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
        if (typeof file.path === "string" && file.donor_path !== null) need(file.path, `copied per ${record}`);
      }
    }
  }

  // Donor files found in the scanned trees.
  for (const path of files) {
    if (!underAny(path, policy.scan_roots)) continue;
    const segment = DONOR_SEGMENT.exec(path);
    if (segment) {
      need(path, `under a ${segment[2]}/ directory`);
      continue;
    }
    const text = readText(root, path);
    if (text === null) continue;
    const notices = [...new Set(text.match(NOTICE_REF) ?? [])].filter((ref) => !GATE_FILE.test(ref));
    if (notices.length) need(path, `names ${notices.join(", ")}`);
  }
  for (const [path, why] of needed) {
    if (!covered(path)) errors.push(`${path}: donor file (${why}) has no entry in ${PROVENANCE_PATH}`);
  }
  return { errors, donors: Object.keys(donors).length, entries: entries.length, required: needed.size };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = rootFromArgs(process.argv, resolve(dirname(fileURLToPath(import.meta.url)), ".."), "check-donor-provenance");
  const { errors, donors, entries, required } = checkProvenance(root);
  if (errors.length) {
    for (const error of errors) console.error(`check-donor-provenance: ${error}`);
    process.exit(1);
  }
  console.log(`check-donor-provenance: ${required} donor files covered by ${entries} entries of ${donors} pinned, attributed donors`);
}
