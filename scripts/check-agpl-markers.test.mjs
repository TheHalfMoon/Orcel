import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkMarkers } from "./check-agpl-markers.mjs";
import { basePolicy, makeTree, removeTree, writeTree } from "./licence-gate-fixture.mjs";
import { markerFamilies } from "./licence-gate-lib.mjs";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWED = new Set(basePolicy().allowed_licences);

function base(extra = {}, policy = {}) {
  return {
    "docs/orcel/notices/licence-policy.json": basePolicy(policy),
    "docs/orcel/notices/fd06-files.txt": "# FD-06\ncrates/core/src/port.rs\n",
    "docs/orcel/notices/fd04-files.txt": "# FD-04\n",
    "crates/core/src/port.rs": "//! Ported from an AGPL-3.0 upstream under FD-06.\npub fn f() {}\n",
    "crates/core/src/lib.rs": "// SPDX-License-Identifier: Apache-2.0\npub mod port;\n",
    "apps/tool/src/main.ts": "// SPDX-License-Identifier: MIT OR Apache-2.0\nexport {};\n",
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

test("today's repository passes the marker scan", () => {
  const { errors, accepted } = checkMarkers(REPO);
  assert.deepEqual(errors, []);
  assert.ok(accepted > 0, "the FD-06 and FD-04 files carry markers the scan must see");
});

test("the fixture tree passes: AGPL markers only in the FD-06 file, docs/ is not scanned", () => {
  assert.deepEqual(run(base()), []);
});

test("a planted AGPL header outside the allowlist fails, in every scanned tree", () => {
  for (const path of ["crates/core/src/new.rs", "apps/tool/src/new.ts", "packages/sdk/index.js", "tests/fixture/x.py"]) {
    const errors = run(base({ [path]: "// SPDX-License-Identifier: AGPL-3.0-only\n" }));
    assert.equal(errors.length, 1, `${path}: ${errors.join("; ")}`);
    assert.match(errors[0], new RegExp(`^${path.replace(/[.]/g, "\\.")}:1: AGPL licence marker`));
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
  assert.deepEqual(markerFamilies("let gplot = sample_1 + simple_2; // the GPU", ALLOWED), []);
  assert.deepEqual(markerFamilies("an AGPL-3.0 port", ALLOWED), ["AGPL"]);
  assert.deepEqual(markerFamilies("LGPL-2.1+", ALLOWED), ["LGPL"]);
});

test("an allowlist admits only its own family", () => {
  const errors = run(base({ "crates/core/src/port.rs": "// AGPL-3.0 upstream\n// SPDX-License-Identifier: FSL-1.1-MIT\n" }));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /port\.rs:2: FSL licence marker/);
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

test("marker exceptions are scoped by family and must stay in use", () => {
  const exception = { path: "apps/tool/NOTICES.md", families: ["MPL"], reason: "dependency inventory" };
  const notices = { "apps/tool/NOTICES.md": "| cssparser | MPL-2.0 |\n" };
  assert.deepEqual(run(base(notices, { marker_exceptions: [exception] })), []);
  const gpl = run(base({ "apps/tool/NOTICES.md": "| x | GPL-3.0 |\n| y | MPL-2.0 |\n" }, { marker_exceptions: [exception] }));
  assert.equal(gpl.length, 1);
  assert.match(gpl[0], /NOTICES\.md:1: GPL/);
  const stale = run(base({ "apps/tool/NOTICES.md": "nothing restricted\n" }, { marker_exceptions: [exception] }));
  assert.ok(stale.some((e) => e.includes("no MPL marker left")), stale.join("; "));
});

test("an allowlist path that does not exist fails", () => {
  const errors = run(base({ "docs/orcel/notices/fd06-files.txt": "crates/core/src/port.rs\ncrates/core/src/gone.rs\n" }));
  assert.ok(errors.some((e) => e.includes("crates/core/src/gone.rs does not exist")), errors.join("; "));
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
