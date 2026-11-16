import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkMarkers } from "./check-agpl-markers.mjs";
import { basePolicy, makeTree, pin, removeTree, writeTree } from "./licence-gate-fixture.mjs";
import { markerFamilies } from "./licence-gate-lib.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWED = new Set(basePolicy().allowed_licences);
const PORT = "crates/core/src/port.rs";
const FD06 = "docs/orcel/notices/fd06-files.txt";

// The FD-06 list pins the port's final content unless a test sets the list.
function base(extra = {}, policy = {}) {
  const files = {
    "docs/orcel/notices/licence-policy.json": basePolicy(policy),
    "docs/orcel/notices/fd04-files.txt": "# FD-04\n",
    [PORT]: "//! Ported from an AGPL-3.0 upstream under FD-06.\npub fn f() {}\n",
    "crates/core/src/lib.rs": "// SPDX-License-Identifier: Apache-2.0\npub mod port;\n",
    "apps/tool/src/main.ts": "// SPDX-License-Identifier: MIT OR Apache-2.0\nexport {};\n",
    "docs/LICENSES.md": "GNU AFFERO GENERAL PUBLIC LICENSE text outside the scanned trees\n",
    ...extra,
  };
  if (!(FD06 in extra)) files[FD06] = `# FD-06\n${pin(PORT, files[PORT])}\n`;
  return files;
}

function run(files) {
  const root = makeTree(files);
  try {
    return checkMarkers(root).errors;
  } finally {
    removeTree(root);
  }
}

test("today's repository passes the marker scan", () => {
  const { errors, accepted } = checkMarkers(REPO);
  assert.deepEqual(errors, []);
  assert.ok(accepted > 0, "the FD-06 and FD-04 files carry markers the scan must see");
});

test("the fixture tree passes: AGPL markers only in the pinned FD-06 file, docs/ is not scanned", () => {
  assert.deepEqual(run(base()), []);
});

test("a planted AGPL header outside the allowlist fails, in every scanned tree", () => {
  const roots = ["crates/core/src", "apps/tool/src", "packages/sdk", "tests/fixture", "distribution/linux", "examples/x", "scripts/x", "third_party/x"];
  for (const dir of roots) {
    const path = `${dir}/new.rs`;
    const errors = run(base({ [path]: "// SPDX-License-Identifier: AGPL-3.0-only\n" }));
    assert.equal(errors.length, 1, `${path}: ${errors.join("; ")}`);
    assert.ok(errors[0].startsWith(`${path}:1: AGPL licence marker`), errors[0]);
  }
});

test("the GNU AFFERO licence text fails outside the allowlist", () => {
  const errors = run(base({ "apps/tool/LICENSE": "                    GNU AFFERO GENERAL PUBLIC LICENSE\n" }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /apps\/tool\/LICENSE:1: AGPL/);
});

test("each restricted family is refused outside the allowlists", () => {
  const cases = {
    GPL: "Licensed under the GNU General Public License v3",
    LGPL: "// SPDX-License-Identifier: LGPL-2.1-or-later",
    MPL: "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.",
    SSPL: "Server Side Public License, v 1",
    BUSL: "Business Source License 1.1",
    FSL: "// SPDX-License-Identifier: FSL-1.1-MIT",
    COMMERCIAL: "// SPDX-License-Identifier: LicenseRef-Commercial",
    OTHER: "// SPDX-License-Identifier: CC-BY-NC-4.0",
  };
  for (const [family, line] of Object.entries(cases)) {
    const errors = run(base({ "crates/core/src/planted.rs": `${line}\n` }));
    assert.ok(errors.length >= 1 && errors.every((e) => e.includes(`${family} licence marker`)), `${family}: ${errors}`);
  }
});

test("permissive SPDX identifiers and ordinary words are not markers", () => {
  assert.deepEqual(markerFamilies("// SPDX-License-Identifier: MIT", ALLOWED), []);
  assert.deepEqual(markerFamilies("/* SPDX-License-Identifier: Apache-2.0 OR MIT */", ALLOWED), []);
  assert.deepEqual(markerFamilies('"// SPDX-License-Identifier: Apache-2.0\\npub mod x;",', ALLOWED), []);
  assert.deepEqual(markerFamilies("let gplot = sample_1 + simple_2; // the GPU", ALLOWED), []);
  assert.deepEqual(markerFamilies("an AGPL-3.0 port", ALLOWED), ["AGPL"]);
  assert.deepEqual(markerFamilies("LGPL-2.1+", ALLOWED), ["LGPL"]);
});

test("an allowlist admits only its own family", () => {
  const errors = run(base({ [PORT]: "// AGPL-3.0 upstream\n// SPDX-License-Identifier: FSL-1.1-MIT\n" }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /port\.rs:2: FSL licence marker/);
});

test("an allowlisted file whose content changed fails until re-pinned (C-15: no new AGPL code)", () => {
  const root = makeTree(base());
  try {
    writeTree(root, { [PORT]: "//! Ported from an AGPL-3.0 upstream under FD-06.\npub fn f() {}\npub fn new_agpl_code() {}\n" });
    const { errors } = checkMarkers(root);
    assert.equal(errors.length, 1, errors.join("; "));
    assert.match(errors[0], /fd06-files\.txt: crates\/core\/src\/port\.rs changed \(pinned [0-9a-f]{64}, now [0-9a-f]{64}\)/);
  } finally {
    removeTree(root);
  }
});

test("the pin ignores CRLF line endings, so it holds on a Windows checkout", () => {
  const root = makeTree(base());
  try {
    writeTree(root, { [PORT]: "//! Ported from an AGPL-3.0 upstream under FD-06.\r\npub fn f() {}\r\n" });
    assert.deepEqual(checkMarkers(root).errors, []);
  } finally {
    removeTree(root);
  }
});

test("an unpinned allowlist entry or one that does not exist fails", () => {
  const unpinned = run(base({ [FD06]: `${PORT}\n` }));
  assert.ok(unpinned.some((e) => e.includes(`${PORT} is not pinned`)), unpinned.join("; "));
  const gone = run(base({ [FD06]: `${"0".repeat(64)}  crates/core/src/gone.rs\n` }));
  assert.ok(gone.some((e) => e.includes("crates/core/src/gone.rs does not exist")), gone.join("; "));
});

test("an isolated component admits its families; a core crate cannot be one", () => {
  const component = { path: "apps/sidecar/", families: ["AGPL"], attestation: "FD-06", reason: "fixture" };
  const files = base({ "apps/sidecar/src/server.ts": "// SPDX-License-Identifier: AGPL-3.0-only\n" }, {
    isolated_components: [component],
  });
  assert.deepEqual(run(files), []);
  const core = { ...component, path: "crates/core/" };
  const errors = run(base({}, { isolated_components: [core] }));
  assert.ok(errors.some((e) => e.includes("a core crate cannot be an isolated component")), errors.join("; "));
});

test("marker exceptions pin the marker count per family", () => {
  const exception = { path: "apps/tool/NOTICES.md", markers: { MPL: 1 }, reason: "dependency inventory" };
  const notices = { "apps/tool/NOTICES.md": "| cssparser | MPL-2.0 |\n" };
  assert.deepEqual(run(base(notices, { marker_exceptions: [exception] })), []);
  const gpl = run(base({ "apps/tool/NOTICES.md": "| x | GPL-3.0 |\n| y | MPL-2.0 |\n" }, { marker_exceptions: [exception] }));
  assert.equal(gpl.length, 1);
  assert.match(gpl[0], /NOTICES\.md:1: GPL/);
  const more = run(base({ "apps/tool/NOTICES.md": "| y | MPL-2.0 |\n| z | MPL-2.0 |\n" }, { marker_exceptions: [exception] }));
  assert.equal(more.length, 1);
  assert.match(more[0], /MPL marker count is 2, pinned 1/);
  const stale = run(base({ "apps/tool/NOTICES.md": "nothing restricted\n" }, { marker_exceptions: [exception] }));
  assert.ok(stale.some((e) => e.includes("MPL marker count is 0, pinned 1")), stale.join("; "));
});

test("binary, archive and oversized files fail unless provenance or an exception covers them", () => {
  const binary = { "apps/tool/blob.bin": "\u0000\u0001AGPL hidden\u0000" };
  const errors = run(base(binary));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /apps\/tool\/blob\.bin: binary file the marker scan cannot read/);
  const archive = run(base({ "tests/fixture/lib.whl": "PK not really a zip" }));
  assert.match(archive.join("; "), /tests\/fixture\/lib\.whl: archive file/);
  const big = run(base({ "apps/tool/big.txt": "a".repeat(4 * 1024 * 1024 + 1) }));
  assert.match(big.join("; "), /apps\/tool\/big\.txt: larger than 4 MiB file/);
  const excepted = { path: "apps/tool/blob.bin", reason: "fixture image" };
  assert.deepEqual(run(base(binary, { unreadable_exceptions: [excepted] })), []);
  const covered = {
    ...binary,
    "docs/orcel/notices/donor-provenance.json": { files: [{ path: "apps/tool/blob.bin", donor: "x" }], references: [] },
  };
  assert.deepEqual(run(base(covered)), []);
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

test("a second file added next to an allowlisted one is still refused", () => {
  const root = makeTree(base());
  try {
    writeTree(root, { "crates/core/src/port2.rs": "//! Ported from an AGPL-3.0 upstream.\n" });
    const { errors } = checkMarkers(root);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /port2\.rs:1: AGPL/);
  } finally {
    removeTree(root);
  }
});
