// Test helper for the WP1-01 licence gate tests: builds a throwaway
// repository tree (not a git checkout, so the gates walk it) from a map of
// repository-relative paths to contents. Objects are written as JSON.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

export function makeTree(files) {
  const root = mkdtempSync(join(tmpdir(), "orcel-licence-gate-"));
  writeTree(root, files);
  return root;
}

export function writeTree(root, files) {
  for (const [path, content] of Object.entries(files)) {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, typeof content === "string" ? content : `${JSON.stringify(content, null, 2)}\n`);
  }
}

export function removeTree(root) {
  rmSync(root, { recursive: true, force: true });
}

export function basePolicy(overrides = {}) {
  return {
    schema: "orcel-licence-policy/1",
    allowed_licences: ["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib", "0BSD"],
    test_only_extra_licences: ["PSF-2.0"],
    test_only_roots: ["tests/"],
    scan_roots: ["crates/", "apps/", "packages/", "tests/"],
    restricted_allowlists: {
      "FD-06": { families: ["AGPL"], list: "docs/orcel/notices/fd06-files.txt" },
      "FD-04": { families: ["FSL"], list: "docs/orcel/notices/fd04-files.txt" },
    },
    isolated_components: [],
    marker_exceptions: [],
    npm_exceptions: [],
    ...overrides,
  };
}
