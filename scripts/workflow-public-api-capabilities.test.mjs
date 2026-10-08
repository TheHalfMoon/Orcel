import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import { join } from "node:path";
import { test } from "node:test";

// Inspect ONLY currently installed package public entrypoints. No model, network,
// patching, private API invocation, or speculative handoff execution.
const packageRoot = fileURLToPath(new URL("../packages/orcel/", import.meta.url));
const manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
const requireSDK = createRequire(join(packageRoot, "package.json"));

const packages = [
  ["@workflow/core", manifest.devDependencies["@workflow/core"]],
  ["@workflow/world-local", manifest.devDependencies["@workflow/world-local"]],
];
const installedMetadata = new Map();

test("the installed Workflow packages match Orcel's pinned versions", async () => {
  for (const [name, wanted] of packages) {
    const modulePath = requireSDK.resolve(name);
    let candidate = new URL(".", pathToFileURL(modulePath));
    let found;
    for (let i = 0; i < 8; i++) {
      try {
        const read = JSON.parse(await readFile(new URL("package.json", candidate), "utf8"));
        if (read.name === name) {
          found = read;
          break;
        }
      } catch {
        /* keep walking to the package root */
      }
      candidate = new URL("../", candidate);
    }
    assert.ok(found, `Could not inspect installed ${name} package metadata`);
    assert.equal(found.version, wanted, `Mismatch for ${name}`);
    installedMetadata.set(name, found);
  }
});

test("the installed documented root and runtime entrypoints expose hook/resume/start primitives", async () => {
  const root = await import(pathToFileURL(requireSDK.resolve("@workflow/core")).href);
  const runtime = await import(pathToFileURL(requireSDK.resolve("@workflow/core/runtime")).href);
  assert.equal(typeof root.createHook, "function");
  assert.equal(typeof runtime.resumeHook, "function");
  assert.equal(typeof runtime.start, "function");

  const published = {
    sdkVersion: manifest.devDependencies["@workflow/core"],
    worldLocalVersion: manifest.devDependencies["@workflow/world-local"],
    checkedPublicEntrypoints: ["@workflow/core", "@workflow/core/runtime"],
    declaredExportPaths: Object.keys(installedMetadata.get("@workflow/core").exports ?? {}),
    rootHookExports: Object.keys(root).filter((name) =>
      /hook|handoff|transfer|owner|claim/i.test(name),
    ),
    runtimeHookExports: Object.keys(runtime).filter((name) =>
      /hook|handoff|transfer|owner|claim|start/i.test(name),
    ),
    candidateTransferNamedExports: [
      ...new Set(
        [...Object.keys(root), ...Object.keys(runtime)].filter((name) =>
          /handoff|transfer.*hook|hook.*transfer|atomic.*claim/i.test(name),
        ),
      ),
    ],
    evidenceScope:
      "public exported names + installed versions only; never proof of unlisted or internal operations",
  };
  console.info("WORKFLOW_PUBLIC_API_CAPABILITY_PROBE=" + JSON.stringify(published));
});
