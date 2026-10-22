// SG-000108 slice 3b-ii (decision 7): the worker runtime pin a
// `live-browser-dev` build compiles in.
//
// Prints the four build variables `orcel-browser-host` reads at compile
// time (never at run time):
//   ORCEL_LIVE_BROWSER_NODE         node.exe that runs the worker
//   ORCEL_LIVE_BROWSER_WORKER_MAIN  <worker>/dist/main.js
//   ORCEL_LIVE_BROWSER_NODE_SHA256  node.exe's SHA-256
//   ORCEL_LIVE_BROWSER_TREE_SHA256  the runtime tree digest
//
// The tree and its digest follow crates/orcel-browser-host/src/runtime_pin.rs
// exactly: `package.json`, every file under `dist/` except `*.test.js` (the
// runtime manifest among them), and every file under
// `node_modules/playwright-core/`, sorted by their `/` relative paths
// (enumerated by scripts/runtime-manifest.mjs), framed under
// `orcel-worker-runtime-tree/2` with each path length-prefixed. This is a
// second, independent implementation: the host
// measures the files itself at every launch and refuses any difference, so a
// disagreement here can only refuse a launch, never admit other code.
//
// Usage: node dev-pin.mjs [--node <node.exe>] [--json]

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runtimeFiles } from "./runtime-manifest.mjs";

export const TREE_DOMAIN = "orcel-worker-runtime-tree/2";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function refuse(why) {
  throw new Error(`the worker runtime cannot be pinned: ${why}`);
}

/// The runtime tree's files (scripts/runtime-manifest.mjs enumerates them
/// exactly as the host does, the manifest itself included).
export { runtimeFiles };

/// The tree digest over (relative path, file SHA-256) pairs, in order.
export function treeDigest(entries) {
  const hash = createHash("sha256");
  hash.update(`${TREE_DOMAIN}\n`);
  for (const [path, digest] of entries) {
    hash.update(`${Buffer.byteLength(path)}:${path}\n${digest}\n`);
  }
  return hash.digest("hex");
}

/// The four build variables for `node` and the worker at `root`.
export function runtimePin(node, root) {
  const entries = runtimeFiles(root).map((relative) => [relative, sha256(readFileSync(join(root, ...relative.split("/"))))]);
  return {
    ORCEL_LIVE_BROWSER_NODE: resolve(node),
    ORCEL_LIVE_BROWSER_WORKER_MAIN: join(resolve(root), "dist", "main.js"),
    ORCEL_LIVE_BROWSER_NODE_SHA256: sha256(readFileSync(node)),
    ORCEL_LIVE_BROWSER_TREE_SHA256: treeDigest(entries)
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const at = args.indexOf("--node");
  const node = at >= 0 ? args[at + 1] : process.execPath;
  if (!node) refuse("--node needs a value");
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const pin = runtimePin(node, root);
  if (args.includes("--json")) process.stdout.write(`${JSON.stringify(pin)}\n`);
  else for (const [name, value] of Object.entries(pin)) process.stdout.write(`${name}=${value}\n`);
}
