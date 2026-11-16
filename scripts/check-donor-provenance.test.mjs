import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkProvenance } from "./check-donor-provenance.mjs";
import { basePolicy, makeTree, removeTree } from "./licence-gate-fixture.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "0123456789abcdef0123456789abcdef01234567";
const MANIFEST = "docs/orcel/notices/donor-provenance.json";

function manifest(overrides = {}) {
  return {
    schema: "orcel-donor-provenance/1",
    attestations: {
      "FA-1": { records: ["docs/orcel/grants/attestation.md"] },
      "FD-06": { records: ["docs/orcel/grants/attestation.md"], families: ["AGPL"] },
    },
    donors: {
      upstream: {
        repo: "owner/upstream",
        commit: SHA,
        licence: "MIT",
        notice: "docs/orcel/notices/upstream-MIT.txt",
        attestation: "FA-1",
        records: ["docs/orcel/upstream_provenance.json"],
      },
      agpl: {
        repo: "owner/agpl",
        commit: SHA,
        licence: "AGPL-3.0",
        notice: "docs/orcel/notices/agpl-AGPL-3.0.txt",
        attestation: "FD-06",
        records: [],
      },
    },
    files: [
      { path: "apps/tool/src/copied.ts", donor: "upstream" },
      { path: "apps/tool/third_party/lib/", donor: "upstream", patches: "none" },
      { path: "crates/core/src/port.rs", donor: "agpl" },
    ],
    references: [{ path: "apps/tool/README.md", reason: "documents the copy" }],
    ...overrides,
  };
}

function base(extra = {}, overrides = {}) {
  return {
    "docs/orcel/notices/licence-policy.json": basePolicy(),
    "docs/orcel/notices/fd06-files.txt": "crates/core/src/port.rs\n",
    "docs/orcel/notices/fd04-files.txt": "",
    "docs/orcel/notices/upstream-MIT.txt": "MIT License\n\nPermission is hereby granted, free of charge, to any person\n",
    "docs/orcel/notices/agpl-AGPL-3.0.txt": "Upstream licence: GNU Affero General Public License v3.0\n",
    "docs/orcel/grants/attestation.md": "Founder attestation\n",
    "docs/orcel/upstream_provenance.json": {
      schema: "orcel-adapted-source-provenance/1",
      files: [{ path: "apps/tool/src/copied.ts" }],
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

test("today's repository: every donor file has a pinned, attested provenance entry", () => {
  const { errors, required, donors } = checkProvenance(REPO);
  assert.deepEqual(errors, []);
  assert.ok(required > 50 && donors >= 10);
});

test("the fixture tree passes", () => {
  assert.deepEqual(run(base()), []);
});

test("a copied file that names a donor notice but has no provenance entry fails", () => {
  const errors = run(base({ "crates/core/src/new_port.rs": "// notice in docs/orcel/notices/upstream-MIT.txt\n" }));
  assert.equal(errors.length, 1, errors.join("\n"));
  expectOne(errors, "crates/core/src/new_port.rs: donor file (names docs/orcel/notices/upstream-MIT.txt) has no entry");
});

test("a vendored file under a third_party/ directory without provenance fails", () => {
  const errors = run(base({ "apps/other/third_party/vendored/lib.rs": "pub fn f() {}\n" }));
  assert.equal(errors.length, 1, errors.join("\n"));
  expectOne(errors, "apps/other/third_party/vendored/lib.rs: donor file (under a third_party/ directory) has no entry");
});

test("a file an adapted-source record lists must be in the manifest", () => {
  const record = {
    schema: "orcel-adapted-source-provenance/1",
    files: [{ path: "apps/tool/src/copied.ts" }, { path: "apps/tool/src/own.ts" }],
  };
  const errors = run(base({ "docs/orcel/upstream_provenance.json": record }));
  expectOne(errors, "apps/tool/src/own.ts: donor file (listed in docs/orcel/upstream_provenance.json) has no entry");
});

test("a provenance record no donor consolidates fails", () => {
  const errors = run(base({ "docs/orcel/stray_provenance.json": { schema: "x/1" } }));
  expectOne(errors, "docs/orcel/stray_provenance.json: provenance record not consolidated");
});

test("a donor needs a repo, a pinned SHA, a licence, a notice and a defined attestation", () => {
  const donor = manifest().donors.upstream;
  const broken = {
    "no commit": [{ ...donor, commit: undefined }, "needs a pinned commit or release"],
    "short sha": [{ ...donor, commit: "abc123" }, "commit must be a 40-hex SHA"],
    "bad repo": [{ ...donor, repo: "upstream" }, 'repo must be "owner/name"'],
    "no licence": [{ ...donor, licence: "" }, "licence is required"],
    "no notice": [{ ...donor, notice: "docs/orcel/notices/missing.txt" }, "notice docs/orcel/notices/missing.txt does not exist"],
    "no attestation": [{ ...donor, attestation: "FD-99" }, "attestation FD-99 is not defined"],
    "release without hash": [{ ...donor, commit: undefined, release: { registry: "crates.io", name: "x", version: "1.0.0" } }, "release needs its SHA-256 pin(s)"],
  };
  for (const [label, [value, needle]] of Object.entries(broken)) {
    const donors = { ...manifest().donors, upstream: value };
    const errors = run(base({}, { donors }));
    assert.ok(errors.some((e) => e.includes(needle)), `${label}: ${errors.join("; ")}`);
  }
  const release = { ...donor, commit: undefined, release: { registry: "crates.io", name: "x", version: "1.0.0", sha256: ["a".repeat(64)] } };
  assert.deepEqual(run(base({}, { donors: { ...manifest().donors, upstream: release } })), []);
});

test("an AGPL donor file outside the FD-06 allowlist fails", () => {
  const files = [...manifest().files, { path: "crates/core/src/new_port.rs", donor: "agpl" }];
  const errors = run(base({ "crates/core/src/new_port.rs": "pub fn g() {}\n" }, { files }));
  assert.equal(errors.length, 1, errors.join("\n"));
  expectOne(errors, "file crates/core/src/new_port.rs: AGPL donor agpl but not on the FD-06 allowlist");
});

test("an FD-06 allowlist path without an AGPL donor entry fails", () => {
  const errors = run(base({ "docs/orcel/notices/fd06-files.txt": "crates/core/src/port.rs\napps/tool/src/own.ts\n" }));
  expectOne(errors, "FD-06 allowlist: apps/tool/src/own.ts has no FD-06 donor entry");
});

test("a restricted donor must cite an attestation for its family and list files, not directories", () => {
  const donors = { ...manifest().donors, agpl: { ...manifest().donors.agpl, attestation: "FA-1" } };
  expectOne(run(base({}, { donors })), "donor agpl: AGPL licence needs an attestation that covers AGPL");
  const files = [...manifest().files, { path: "crates/core/", donor: "agpl", patches: "none" }];
  expectOne(run(base({}, { files })), "must list files, not a directory");
});

test("an isolated component may hold restricted donor code as a directory entry", () => {
  const component = { path: "apps/sidecar/", families: ["AGPL"], attestation: "FD-06", reason: "fixture" };
  const files = [...manifest().files, { path: "apps/sidecar/", donor: "agpl", patches: "none" }];
  const tree = base({ "apps/sidecar/src/server.ts": "// notice in docs/orcel/notices/agpl-AGPL-3.0.txt\n" }, { files });
  tree["docs/orcel/notices/licence-policy.json"] = basePolicy({ isolated_components: [component] });
  assert.deepEqual(run(tree), []);
});

test("entries must point at existing paths with the right shape", () => {
  const files = [
    ...manifest().files,
    { path: "apps/tool/src/gone.ts", donor: "upstream" },
    { path: "apps/tool/src", donor: "upstream" },
    { path: "apps/tool/third_party/", donor: "upstream" },
  ];
  const errors = run(base({}, { files }));
  expectOne(errors, "file apps/tool/src/gone.ts: does not exist");
  expectOne(errors, "file apps/tool/src: a directory entry must end in '/'");
  expectOne(errors, 'file apps/tool/third_party/: a directory entry needs "patches"');
});

test("an unpinned upstream/ directory fails, wherever the segment appears", () => {
  for (const path of ["apps/tool/upstream/parser.c", "crates/core/src/vendor/lib.rs", "packages/sdk/vendored/x.js", "third_party/obscura/src/main.rs", "scripts/upstream/helper.py"]) {
    const errors = run(base({ [path]: "int main(void) { return 0; }\n" }));
    assert.equal(errors.length, 1, `${path}: ${errors.join("; ")}`);
    expectOne(errors, `${path}: donor file (under a`);
  }
});

test("a pinned upstream/ directory entry with its patch queue passes", () => {
  const files = [...manifest().files, { path: "apps/tool/upstream/", donor: "upstream", patches: "apps/tool/upstream/PATCHES.md" }];
  const tree = base({ "apps/tool/upstream/parser.c": "int x;\n", "apps/tool/upstream/PATCHES.md": "No patches.\n" }, { files });
  assert.deepEqual(run(tree), []);
});

test("a donor whose notice does not carry its declared licence text fails", () => {
  const errors = run(base({ "docs/orcel/notices/upstream-MIT.txt": "Licensed under the Apache License, Version 2.0\n" }));
  expectOne(errors, "donor upstream: licence text docs/orcel/notices/upstream-MIT.txt does not contain the MIT licence text");
  const donors = { ...manifest().donors, upstream: { ...manifest().donors.upstream, licence: "WTFPL" } };
  expectOne(run(base({}, { donors })), "no licence-text check is defined for WTFPL");
});
