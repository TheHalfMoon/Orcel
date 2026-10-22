// The dev pin calculator agrees with the host's runtime_pin.rs: the same
// fixed vector (computed independently with Python) and the same tree.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runtimeFiles, runtimePin, treeDigest } from "./dev-pin.mjs";

test("the tree digest matches the host's fixed vector", () => {
  assert.equal(
    treeDigest([["package.json", "00"]]),
    "6d3883c7d40e441a60db788a61be5882768e105b6b356b64960d16d7b5134535"
  );
  // Length-prefixed: no two trees frame alike.
  assert.notEqual(treeDigest([["a", "1"], ["b", "2"]]), treeDigest([["ab", "1"], ["", "2"]]));
});

test("only the loadable runtime is pinned, as the host measures it", () => {
  const root = mkdtempSync(join(tmpdir(), "orcel-dev-pin-"));
  try {
    for (const dir of ["dist/extract", "node_modules/playwright-core/lib", "node_modules/typescript"]) {
      mkdirSync(join(root, dir), { recursive: true });
    }
    for (const [file, body] of [
      ["package.json", "{}"],
      ["dist/main.js", "import './worker.js';"],
      ["dist/runtime-manifest.json", "{}"],
      ["dist/worker.js", "export {};"],
      ["dist/worker.test.js", "test"],
      ["dist/extract/clean.js", "export {};"],
      ["node_modules/playwright-core/package.json", "{}"],
      ["node_modules/playwright-core/lib/index.js", "x"],
      ["node_modules/typescript/index.js", "not loaded"],
      ["node.exe", "MZ fake node"]
    ]) {
      writeFileSync(join(root, file), body);
    }
    // The same list runtime_pin.rs's own unit test expects.
    assert.deepEqual(runtimeFiles(root), [
      "dist/extract/clean.js",
      "dist/main.js",
      "dist/runtime-manifest.json",
      "dist/worker.js",
      "node_modules/playwright-core/lib/index.js",
      "node_modules/playwright-core/package.json",
      "package.json"
    ]);
    const before = runtimePin(join(root, "node.exe"), root);
    assert.match(before.ORCEL_LIVE_BROWSER_TREE_SHA256, /^[0-9a-f]{64}$/);
    assert.ok(before.ORCEL_LIVE_BROWSER_WORKER_MAIN.endsWith(join("dist", "main.js")));
    // Tests and other packages do not move the pin; runtime files do.
    writeFileSync(join(root, "dist/worker.test.js"), "changed");
    writeFileSync(join(root, "node_modules/typescript/index.js"), "changed");
    assert.equal(runtimePin(join(root, "node.exe"), root).ORCEL_LIVE_BROWSER_TREE_SHA256, before.ORCEL_LIVE_BROWSER_TREE_SHA256);
    writeFileSync(join(root, "dist/worker.js"), "export const changed = 1;");
    assert.notEqual(runtimePin(join(root, "node.exe"), root).ORCEL_LIVE_BROWSER_TREE_SHA256, before.ORCEL_LIVE_BROWSER_TREE_SHA256);
    writeFileSync(join(root, "node.exe"), "MZ other node");
    assert.notEqual(runtimePin(join(root, "node.exe"), root).ORCEL_LIVE_BROWSER_NODE_SHA256, before.ORCEL_LIVE_BROWSER_NODE_SHA256);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
