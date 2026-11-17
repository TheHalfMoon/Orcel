import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkProvenance } from "./check-donor-provenance.mjs";
import { AUTHORIZATION, basePolicy, makeTree, removeTree } from "./licence-gate-fixture.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "0123456789abcdef0123456789abcdef01234567";
const MANIFEST = "docs/orcel/notices/donor-provenance.json";

function manifest(overrides = {}) {
  return {
    schema: "orcel-donor-provenance/1",
    authorizations: { [AUTHORIZATION]: { records: ["docs/orcel/grants/attestation.md"] } },
    donors: {
      upstream: {
        repo: "owner/upstream",
        commit: SHA,
        licence: "MIT",
        notice: "docs/orcel/notices/upstream-MIT.txt",
        authorization: AUTHORIZATION,
        records: ["docs/orcel/upstream_provenance.json"],
      },
      agpl: {
        repo: "owner/agpl",
        commit: SHA,
        licence: "AGPL-3.0",
        notice: "docs/orcel/notices/agpl-AGPL-3.0.txt",
        authorization: AUTHORIZATION,
        records: [],
      },
    },
    files: [
      { path: "apps/tool/src/copied.ts", donor: "upstream", source: ["src/copied.ts"] },
      { path: "apps/tool/third_party/lib/", donor: "upstream", source: ["lib/"], patches: "none" },
      { path: "crates/core/src/port.rs", donor: "agpl", source: ["src/port.rs"] },
    ],
    references: [{ path: "apps/tool/README.md", reason: "documents the copy" }],
    ...overrides,
  };
}

function base(extra = {}, overrides = {}) {
  return {
    "docs/orcel/notices/licence-policy.json": basePolicy(),
    "docs/orcel/notices/upstream-MIT.txt": "MIT License\n\nCopyright (c) Upstream\n\nPermission is hereby granted, free of charge, to any person\n",
    "docs/orcel/notices/agpl-AGPL-3.0.txt": "Upstream licence: GNU Affero General Public License v3.0\n",
    "docs/orcel/grants/attestation.md": "Owner-asserted authorization\n",
    "docs/orcel/upstream_provenance.json": {
      schema: "orcel-adapted-source-provenance/1",
      files: [{ path: "apps/tool/src/copied.ts", donor_path: "src/copied.ts" }],
    },
    [MANIFEST]: manifest(overrides),
    "apps/tool/src/copied.ts": "// Adapted from owner/upstream; notice in docs/orcel/notices/upstream-MIT.txt.\n",
    "apps/tool/src/own.ts": "export const own = 1;\n",
    "apps/tool/README.md": "See docs/orcel/notices/upstream-MIT.txt.\n",
    "apps/tool/third_party/lib/index.js": "module.exports = 1;\n",
    "apps/tool/third_party/lib/LICENSE": "MIT License\n",
    "crates/core/src/port.rs": "//! Ported; notice in docs/orcel/notices/agpl-AGPL-3.0.txt.\n",
    ...extra,
  };
}

function run(files) {
  const root = makeTree(files);
  try {
    return checkProvenance(root).errors;
  } finally {
    removeTree(root);
  }
}

function expectOne(errors, needle) {
  assert.ok(errors.some((e) => e.includes(needle)), `expected an error containing "${needle}", got:\n${errors.join("\n")}`);
}

test("today's repository: every donor file has pinned, attributed provenance", () => {
  const { errors, required, donors } = checkProvenance(REPO);
  assert.deepEqual(errors, []);
  assert.ok(required > 50 && donors >= 10);
});

test("the fixture tree passes, AGPL donor in a core crate included (licence recorded, not judged)", () => {
  assert.deepEqual(run(base()), []);
});

test("a copied AGPL file with no provenance entry fails", () => {
  const errors = run(base({ "crates/core/src/new_port.rs": "// notice in docs/orcel/notices/agpl-AGPL-3.0.txt\n" }));
  assert.equal(errors.length, 1, errors.join("\n"));
  expectOne(errors, "crates/core/src/new_port.rs: donor file (names docs/orcel/notices/agpl-AGPL-3.0.txt) has no entry");
});

test("an unpinned upstream/ directory fails, wherever the segment appears", () => {
  for (const path of ["apps/tool/upstream/parser.c", "crates/core/src/vendor/lib.rs", "packages/sdk/vendored/x.js", "third_party/obscura/src/main.rs", "scripts/upstream/helper.py", "apps/other/third_party/v/lib.rs"]) {
    const errors = run(base({ [path]: "int main(void) { return 0; }\n" }));
    assert.equal(errors.length, 1, `${path}: ${errors.join("; ")}`);
    expectOne(errors, `${path}: donor file (under a`);
  }
});

test("a pinned upstream/ directory entry with its source and patch queue passes", () => {
  const files = [...manifest().files, { path: "apps/tool/upstream/", donor: "upstream", source: ["parser/"], patches: "apps/tool/upstream/PATCHES.md" }];
  const tree = base({ "apps/tool/upstream/parser.c": "int x;\n", "apps/tool/upstream/PATCHES.md": "No patches.\n" }, { files });
  assert.deepEqual(run(tree), []);
});

test("a file an adapted-source record copies must be in the manifest; new code it lists need not be", () => {
  const record = {
    schema: "orcel-adapted-source-provenance/1",
    files: [
      { path: "apps/tool/src/copied.ts", donor_path: "src/copied.ts" },
      { path: "apps/tool/src/own.ts", donor_path: "src/own.ts" },
    ],
  };
  expectOne(run(base({ "docs/orcel/upstream_provenance.json": record })), "apps/tool/src/own.ts: donor file (copied per docs/orcel/upstream_provenance.json) has no entry");
  record.files[1].donor_path = null;
  assert.deepEqual(run(base({ "docs/orcel/upstream_provenance.json": record })), []);
});

test("a provenance record no donor consolidates fails", () => {
  expectOne(run(base({ "docs/orcel/stray_provenance.json": { schema: "x/1" } })), "docs/orcel/stray_provenance.json: provenance record not consolidated");
});

test("a donor needs a repo, a pinned SHA, a recorded licence, a preserved notice and the owner-asserted authorization", () => {
  const donor = manifest().donors.upstream;
  const broken = {
    "no commit": [{ ...donor, commit: undefined }, "needs a pinned commit or release"],
    "short sha": [{ ...donor, commit: "abc123" }, "commit must be a 40-hex SHA"],
    "bad repo": [{ ...donor, repo: "upstream" }, 'repo must be "owner/name"'],
    "no licence": [{ ...donor, licence: "" }, "the original licence must be recorded"],
    "no notice": [{ ...donor, notice: "docs/orcel/notices/missing.txt" }, "preserved notice docs/orcel/notices/missing.txt does not exist"],
    "other authorization": [{ ...donor, authorization: "FD-99" }, `authorization must be "${AUTHORIZATION}"`],
    "release without hash": [{ ...donor, commit: undefined, release: { registry: "crates.io", name: "x", version: "1.0.0" } }, "release needs its SHA-256 pin(s)"],
  };
  for (const [label, [value, needle]] of Object.entries(broken)) {
    const errors = run(base({}, { donors: { ...manifest().donors, upstream: value } }));
    assert.ok(errors.some((e) => e.includes(needle)), `${label}: ${errors.join("; ")}`);
  }
  const release = { ...donor, commit: undefined, release: { registry: "crates.io", name: "x", version: "1.0.0", sha256: ["a".repeat(64)] } };
  assert.deepEqual(run(base({}, { donors: { ...manifest().donors, upstream: release } })), []);
  const undefinedAuth = run(base({}, { authorizations: {} }));
  expectOne(undefinedAuth, `authorization "${AUTHORIZATION}" is not defined in the manifest`);
});

test("the preserved notice must carry the recorded licence text; any licence may be recorded", () => {
  expectOne(
    run(base({ "docs/orcel/notices/upstream-MIT.txt": "Licensed under the Apache License, Version 2.0\n" })),
    "preserved notice docs/orcel/notices/upstream-MIT.txt does not contain the MIT licence text",
  );
  expectOne(run(base({ "docs/orcel/notices/upstream-MIT.txt": "  \n" })), "upstream-MIT.txt is empty");
  const donors = { ...manifest().donors, upstream: { ...manifest().donors.upstream, licence: "LicenseRef-Proprietary" } };
  assert.deepEqual(run(base({}, { donors })), []);
});

test("every file entry names its source path(s) and an existing path with the right shape", () => {
  const files = [
    { path: "apps/tool/src/copied.ts", donor: "upstream" },
    { path: "apps/tool/third_party/lib/", donor: "upstream", source: ["lib/"], patches: "none" },
    { path: "crates/core/src/port.rs", donor: "agpl", source: ["src/port.rs"] },
    { path: "apps/tool/src/gone.ts", donor: "upstream", source: ["x"] },
    { path: "apps/tool/src", donor: "upstream", source: ["x"] },
    { path: "apps/tool/third_party/", donor: "upstream", source: ["x"] },
  ];
  const errors = run(base({}, { files }));
  expectOne(errors, 'file apps/tool/src/copied.ts: needs its source path(s)');
  expectOne(errors, "file apps/tool/src/gone.ts: does not exist");
  expectOne(errors, "file apps/tool/src: a directory entry must end in '/'");
  expectOne(errors, 'file apps/tool/third_party/: a directory entry needs "patches"');
});
