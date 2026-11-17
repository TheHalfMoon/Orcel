import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkMarkers } from "./check-agpl-markers.mjs";
import { basePolicy, makeTree, removeTree, writeTree } from "./licence-gate-fixture.mjs";
import { markerFamilies } from "./licence-gate-lib.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OWN = new Set(["Apache-2.0"]);
const MANIFEST = "docs/orcel/notices/donor-provenance.json";

// The port carries an AGPL marker and has a provenance entry.
function base(extra = {}, policy = {}, files = [{ path: "crates/core/src/port.rs", donor: "x" }], references = []) {
  return {
    "docs/orcel/notices/licence-policy.json": basePolicy(policy),
    [MANIFEST]: { files, references },
    "crates/core/src/port.rs": "//! Ported from an AGPL-3.0 upstream.\npub fn f() {}\n",
    "crates/core/src/lib.rs": "// SPDX-License-Identifier: Apache-2.0\npub mod port;\n",
    "docs/LICENSES.md": "GNU AFFERO GENERAL PUBLIC LICENSE text outside the scanned trees\n",
    ...extra,
  };
}

function run(files) {
  const root = makeTree(files);
  try {
    return checkMarkers(root).errors;
  } finally {
    removeTree(root);
  }
}

test("today's repository: every file with a licence marker has provenance", () => {
  const { errors, marked } = checkMarkers(REPO);
  assert.deepEqual(errors, []);
  assert.ok(marked > 0, "the copied donor files carry markers the scan must see");
});

test("a licence marker in a file with a provenance entry passes; docs/ is not scanned", () => {
  assert.deepEqual(run(base()), []);
});

test("a planted AGPL file WITH a provenance entry passes: the licence type blocks nothing", () => {
  const files = [
    { path: "crates/core/src/port.rs", donor: "x" },
    { path: "crates/core/src/agpl.rs", donor: "x" },
  ];
  const planted = { "crates/core/src/agpl.rs": "// SPDX-License-Identifier: AGPL-3.0-only\n// GNU AFFERO GENERAL PUBLIC LICENSE\n" };
  assert.deepEqual(run(base(planted, {}, files)), []);
});

test("a planted AGPL file WITHOUT provenance fails, in every scanned tree", () => {
  const roots = ["crates/core/src", "apps/tool/src", "packages/sdk", "tests/fixture", "distribution/linux", "examples/x", "scripts/x", "third_party/x"];
  for (const dir of roots) {
    const path = `${dir}/new.rs`;
    const errors = run(base({ [path]: "// SPDX-License-Identifier: AGPL-3.0-only\n" }));
    assert.equal(errors.length, 1, `${path}: ${errors.join("; ")}`);
    assert.ok(errors[0].startsWith(`${path}:1: AGPL licence marker in a file with no provenance entry`), errors[0]);
  }
});

test("every licence family, and any non-Orcel SPDX identifier, requires provenance", () => {
  const cases = {
    GPL: "Licensed under the GNU General Public License v3",
    LGPL: "// SPDX-License-Identifier: LGPL-2.1-or-later",
    MPL: "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.",
    SSPL: "Server Side Public License, v 1",
    BUSL: "Business Source License 1.1",
    FSL: "// SPDX-License-Identifier: FSL-1.1-MIT",
    COMMERCIAL: "// SPDX-License-Identifier: LicenseRef-Commercial",
    OTHER: "// SPDX-License-Identifier: MIT",
  };
  for (const [family, line] of Object.entries(cases)) {
    const errors = run(base({ "crates/core/src/planted.rs": `${line}\n` }));
    assert.equal(errors.length, 1, `${family}: ${errors}`);
    assert.ok(errors[0].includes(`${family} licence marker`), `${family}: ${errors[0]}`);
  }
});

test("a reviewed reference entry covers a file that only mentions a licence", () => {
  const notes = { "apps/tool/NOTICES.md": "| cssparser | MPL-2.0 |\n" };
  assert.equal(run(base(notes)).length, 1);
  const references = [{ path: "apps/tool/NOTICES.md", reason: "dependency inventory" }];
  assert.deepEqual(run(base(notes, {}, undefined, references)), []);
});

test("Orcel's own SPDX identifier and ordinary words are not markers", () => {
  assert.deepEqual(markerFamilies("// SPDX-License-Identifier: Apache-2.0", OWN), []);
  assert.deepEqual(markerFamilies('"// SPDX-License-Identifier: Apache-2.0\\npub mod x;",', OWN), []);
  assert.deepEqual(markerFamilies("let gplot = sample_1 + simple_2; // the GPU", OWN), []);
  assert.deepEqual(markerFamilies("an AGPL-3.0 port", OWN), ["AGPL"]);
  assert.deepEqual(markerFamilies("LGPL-2.1+", OWN), ["LGPL"]);
  assert.deepEqual(markerFamilies("// SPDX-License-Identifier: MIT", OWN), ["OTHER"]);
});

test("binary, archive and oversized files fail unless provenance or an exception covers them", () => {
  const binary = { "apps/tool/blob.bin": "\u0000\u0001AGPL hidden\u0000" };
  const errors = run(base(binary));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /apps\/tool\/blob\.bin: binary file the marker scan cannot read/);
  assert.match(run(base({ "tests/fixture/lib.whl": "PK not really a zip" })).join("; "), /tests\/fixture\/lib\.whl: archive file/);
  assert.match(run(base({ "apps/tool/big.txt": "a".repeat(4 * 1024 * 1024 + 1) })).join("; "), /apps\/tool\/big\.txt: larger than 4 MiB file/);
  assert.deepEqual(run(base(binary, { unreadable_exceptions: [{ path: "apps/tool/blob.bin", reason: "fixture image" }] })), []);
  const covered = [
    { path: "crates/core/src/port.rs", donor: "x" },
    { path: "apps/tool/blob.bin", donor: "x" },
  ];
  assert.deepEqual(run(base(binary, {}, covered)), []);
});

test("UTF-16 text with a byte-order mark is read, not skipped", () => {
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("// SPDX-License-Identifier: AGPL-3.0-only\n", "utf16le")]);
  const root = makeTree(base());
  try {
    writeTree(root, { "apps/tool/src/wide.ts": le });
    const { errors } = checkMarkers(root);
    assert.equal(errors.length, 1, errors.join("; "));
    assert.match(errors[0], /apps\/tool\/src\/wide\.ts:1: AGPL licence marker/);
  } finally {
    removeTree(root);
  }
});

test("lockfiles are left to the dependency checks", () => {
  const lock = { "apps/web/package-lock.json": '{"packages":{"node_modules/x":{"license":"LGPL-3.0-or-later"}}}\n' };
  assert.deepEqual(run(base(lock)), []);
});
