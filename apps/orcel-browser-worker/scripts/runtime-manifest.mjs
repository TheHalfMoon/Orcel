// SG-000108 decision 7: writes dist/runtime-manifest.json after the build.
//
// The manifest names every runtime file but itself, exactly as
// crates/orcel-browser-host/src/runtime_pin.rs enumerates the tree:
// `package.json`, every file under `dist/` except `*.test.js`, and every
// file under `node_modules/playwright-core/`, as `/` relative paths in byte
// order. The worker's resolve guard loads nothing else, and a pinned launch
// refuses a manifest that differs from the tree it measures.
//
// Usage: node runtime-manifest.mjs [<worker root>]

import { lstatSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const MANIFEST = "dist/runtime-manifest.json";
export const MANIFEST_SCHEMA = "orcel-worker-runtime-manifest/1";

function refuse(why) {
  throw new Error(`the runtime manifest cannot be written: ${why}`);
}

/// The runtime tree's files under `root`, sorted, the manifest included if
/// present. A link anywhere refuses the tree, as the host does.
export function runtimeFiles(root) {
  const files = [];
  const stat = lstatSync(join(root, "package.json"), { throwIfNoEntry: false });
  if (!stat || !stat.isFile()) refuse("package.json is missing");
  files.push("package.json");
  const collect = (relative, keep) => {
    const dir = join(root, ...relative.split("/"));
    const meta = lstatSync(dir, { throwIfNoEntry: false });
    if (!meta || !meta.isDirectory() || meta.isSymbolicLink()) refuse(`${relative} is not a plain directory`);
    for (const name of readdirSync(dir)) {
      if (/[\u0000-\u001f\u007f-\u009f]/.test(name)) refuse("a file name carries control characters");
      const child = `${relative}/${name}`;
      const entry = lstatSync(join(dir, name));
      if (entry.isSymbolicLink()) refuse(`${child} is a link`);
      if (entry.isDirectory()) collect(child, keep);
      else if (entry.isFile()) {
        if (keep(child)) files.push(child);
      } else refuse(`${child} is neither a file nor a directory`);
    }
  };
  collect("dist", (relative) => !relative.endsWith(".test.js"));
  collect("node_modules/playwright-core", () => true);
  return files.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

/// Write the manifest for the worker at `root`.
export function writeManifest(root) {
  const files = runtimeFiles(root).filter((relative) => relative !== MANIFEST);
  writeFileSync(join(root, ...MANIFEST.split("/")), `${JSON.stringify({ schema: MANIFEST_SCHEMA, files })}\n`);
  return files;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] ? resolve(process.argv[2]) : resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const files = writeManifest(root);
  process.stdout.write(`runtime manifest: ${files.length} files\n`);
}
