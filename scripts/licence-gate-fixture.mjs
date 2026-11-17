// Test helper for the WP1-01 provenance gate tests: builds a throwaway
// repository tree (not a git checkout, so the gates walk it) from a map of
// repository-relative paths to contents. Strings and Buffers are written
// as they are; other values as JSON.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

export const AUTHORIZATION = "OWNER-ASSERTED AUTHORIZATION, founder 2026-11-17";

export function makeTree(files) {
  const root = mkdtempSync(join(tmpdir(), "orcel-licence-gate-"));
  writeTree(root, files);
  return root;
}

export function writeTree(root, files) {
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    const raw = typeof content === "string" || Buffer.isBuffer(content);
    writeFileSync(full, raw ? content : `${JSON.stringify(content, null, 2)}\n`);
  }
}

export function removeTree(root) {
  rmSync(root, { recursive: true, force: true });
}

export function basePolicy(overrides = {}) {
  return {
    schema: "orcel-licence-policy/2",
    founder_decision: { date: "2026-11-17", authorization: AUTHORIZATION, record: "docs/orcel/grants/attestation.md" },
    orcel_licence: "Apache-2.0",
    scan_roots: ["crates/", "apps/", "packages/", "tests/", "distribution/", "examples/", "scripts/", "third_party/"],
    unreadable_exceptions: [],
    ...overrides,
  };
}
