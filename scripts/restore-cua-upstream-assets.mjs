#!/usr/bin/env node
// #355: puts the six upstream files P-05 does not vendor back into the
// working tree, so CI can run the parity tests behind the `upstream-assets`
// features (cua-cursor-motion golden and motion_parity, cursor-overlay
// motion_equivalence, session badge and theme artifact).
//
// Each file is fetched from trycua/cua by the blob id the provenance file
// records for it (`removed_files[].upstream_blob_sha`), and its bytes must
// hash to that id before they are written. A blob id names exact bytes, and
// `check-vendored-cua.mjs --upstream` proves those ids are the ones in the
// pinned upstream trees, so the restored files are upstream's at the pin.
// Nothing is committed: the files exist only in the CI checkout, and the
// exact-diff review never sees them.
//
// #423: every network read is bounded (FETCH_TIMEOUT_MS per attempt,
// FETCH_ATTEMPTS attempts) and the blob id is computed in this process, with
// no git child, so the step fails fast with a message instead of hanging the
// job until it is cancelled.
//
// Usage: node scripts/restore-cua-upstream-assets.mjs
// Dependency-free. A token in GH_TOKEN or GITHUB_TOKEN raises the GitHub API
// rate limit. Exits 1 on any mismatch or timeout.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const provenancePath = join(repoRoot, "docs/orcel/cua_driver_provenance.json");
const SHA = /^[0-9a-f]{40}$/;
const FETCH_TIMEOUT_MS = 60_000;
const FETCH_ATTEMPTS = 3;

/** The git blob id of `bytes`: SHA-1 over `blob <size>` and a NUL, then the bytes. */
export function blobId(bytes) {
  return createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

async function fetchBlob(sha) {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  let last;
  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch(`https://api.github.com/repos/trycua/cua/git/blobs/${sha}`, {
        headers: {
          accept: "application/vnd.github.raw+json",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        // Bounds the whole exchange, body included.
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return Buffer.from(await response.arrayBuffer());
    } catch (error) {
      last = error;
      process.stderr.write(`blob ${sha}: attempt ${attempt} of ${FETCH_ATTEMPTS} failed: ${error.message}\n`);
    }
  }
  throw new Error(`GitHub API blob ${sha} could not be read in ${FETCH_ATTEMPTS} attempts of ${FETCH_TIMEOUT_MS / 1000}s: ${last?.message}`);
}

const provenance = JSON.parse(readFileSync(provenancePath, "utf8"));
const errors = [];
let restored = 0;
for (const crate of provenance.crates ?? []) {
  for (const file of crate.removed_files ?? []) {
    const destination = join(repoRoot, crate.destination, file.path);
    const label = `${crate.name}/${file.path}`;
    if (!SHA.test(file.upstream_blob_sha ?? "")) {
      errors.push(`${label}: no upstream blob id recorded`);
      continue;
    }
    process.stdout.write(`fetching ${label} (blob ${file.upstream_blob_sha})\n`);
    let bytes;
    try {
      bytes = await fetchBlob(file.upstream_blob_sha);
    } catch (error) {
      errors.push(`${label}: ${error.message}`);
      continue;
    }
    const id = blobId(bytes);
    if (id !== file.upstream_blob_sha) {
      errors.push(`${label}: fetched bytes hash to ${id}, not ${file.upstream_blob_sha}`);
      continue;
    }
    if (existsSync(destination) && blobId(readFileSync(destination)) !== id) {
      errors.push(`${label}: a different file is already at ${destination}`);
      continue;
    }
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, bytes);
    process.stdout.write(`restored ${label} (${bytes.length} bytes, blob ${id})\n`);
    restored += 1;
  }
}
if (restored === 0 && errors.length === 0) errors.push("the provenance records no removed upstream files");
if (errors.length) {
  for (const error of errors) process.stderr.write(`error: ${error}\n`);
  process.exit(1);
}
process.stdout.write(`${restored} upstream files restored from trycua/cua by blob id\n`);
