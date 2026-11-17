import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkMarkers } from "./check-agpl-markers.mjs";
import { basePolicy, makeTree, removeTree, writeTree } from "./licence-gate-fixture.mjs";
import { markerFamilies, readScan } from "./licence-gate-lib.mjs";

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
  const notes = { "apps/tool/NOTICES.md": "cssparser: Mozilla Public License, v. 2.0\n" };
  assert.equal(run(base(notes)).length, 1);
  const references = [{ path: "apps/tool/NOTICES.md", reason: "dependency inventory" }];
  assert.deepEqual(run(base(notes, {}, undefined, references)), []);
});

test("Orcel's own SPDX identifier and prose naming a licence are not markers", () => {
  assert.deepEqual(markerFamilies("// SPDX-License-Identifier: Apache-2.0", OWN), []);
  assert.deepEqual(markerFamilies('"// SPDX-License-Identifier: Apache-2.0\\npub mod x;",', OWN), []);
  assert.deepEqual(markerFamilies("let gplot = sample_1 + simple_2; // the GPU", OWN), []);
  assert.deepEqual(markerFamilies("// unlike GPLv3 tools, this is Orcel's own code", OWN), []);
  assert.deepEqual(markerFamilies("an AGPL-3.0 port, LGPL-2.1+ and MPL-2.0 dependencies", OWN), []);
  assert.deepEqual(markerFamilies("// SPDX-License-Identifier: MIT", OWN), ["OTHER"]);
  assert.deepEqual(markerFamilies("Permission is hereby granted, free of charge, to any person", OWN), ["OTHER"]);
  assert.deepEqual(markerFamilies(" * This program is free software: you can redistribute it", OWN), ["GPL"]);
});

test("an Orcel comment such as 'unlike GPLv3 tools' needs no provenance", () => {
  const prose = { "crates/core/src/notes.rs": "// Orcel's own code: unlike GPLv3 tools, nothing here is copied.\n" };
  assert.deepEqual(run(base(prose)), []);
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

test("a directory in the file list (a tracked symlink to a directory) is reported, not a crash", () => {
  const root = makeTree(base());
  try {
    mkdirSync(join(root, "apps/tool/linked"), { recursive: true });
    assert.deepEqual(readScan(root, "apps/tool/linked"), { unreadable: "a directory (a symbolic link to a directory)" });
  } finally {
    removeTree(root);
  }
});

test("--root without a directory exits with a clear message", () => {
  for (const script of ["check-agpl-markers.mjs", "check-npm-licenses.mjs", "check-donor-provenance.mjs"]) {
    const path = join(REPO, "scripts", script);
    const missing = spawnSync(process.execPath, [path, "--root"], { encoding: "utf8" });
    assert.equal(missing.status, 2, `${script}: ${missing.stderr}`);
    assert.match(missing.stderr, /--root needs a directory/);
    const bogus = spawnSync(process.execPath, [path, "--root", join(REPO, "no-such-dir")], { encoding: "utf8" });
    assert.equal(bogus.status, 2, `${script}: ${bogus.stderr}`);
    assert.match(bogus.stderr, /is not a directory/);
  }
});

test("Apache header text, the ISC grant, Boost and the Unlicense are markers that require provenance", () => {
  const cases = {
    APACHE: " * Licensed under the Apache License, Version 2.0 (the \"License\");",
    ISC: "Permission to use, copy, modify, and/or distribute this software for any",
    BSL: "Distributed under the Boost Software License, Version 1.0.",
    UNLICENSE: "This is free and unencumbered software released into the public domain.",
  };
  for (const [family, line] of Object.entries(cases)) {
    assert.deepEqual(markerFamilies(line, OWN), [family], family);
    const errors = run(base({ "apps/tool/src/copied.js": `${line}\n` }));
    assert.equal(errors.length, 1, `${family}: ${errors}`);
    assert.ok(errors[0].includes(`${family} licence marker in a file with no provenance entry`), errors[0]);
    const covered = [
      { path: "crates/core/src/port.rs", donor: "x" },
      { path: "apps/tool/src/copied.js", donor: "x" },
    ];
    assert.deepEqual(run(base({ "apps/tool/src/copied.js": `${line}\n` }, {}, covered)), [], family);
  }
  assert.deepEqual(markerFamilies("// Orcel is Apache-licensed; Boost and ISC crates are reported", OWN), []);
});
