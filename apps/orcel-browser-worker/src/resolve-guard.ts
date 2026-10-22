// SG-000108 decision 7: the module resolve guard.
//
// The host pins the worker's runtime tree (package.json, dist/ and
// node_modules/playwright-core/) and holds its files, but Node also loads
// files the pin never measured: an optional `require("bufferutil")` in
// playwright-core's bundled `ws` searches <root>/node_modules and every
// parent directory up to the drive root; a `node_modules` created inside
// dist/ would shadow playwright-core; and CommonJS lookup tries an
// extensionless name (`lib/coreBundle`) before `lib/coreBundle.js`, so a
// file created next to a pinned one would load instead (judge, PR #336).
// Pinning cannot stop a new file from appearing. This guard does: every
// module the worker resolves must be a Node built-in or one of the files
// named by dist/runtime-manifest.json. The manifest is part of the pinned
// tree, and a pinned launch refuses a manifest that names anything but the
// tree's other files, so the allowlist is exactly what the host measured
// and holds. Anything else is refused, which an optional require sees as
// "absent".
//
// Paths compare exactly, but for the drive letter: Node builds a module's
// path from its parent's path and the specifier's text, so pinned code
// loses nothing, while a case-folded match could admit a differently cased
// twin (NTFS per-directory case sensitivity, or a character such as U+212A
// that JavaScript folds to an ASCII letter; judge, PR #336). Manifest names
// must be printable ASCII.
//
// The guard governs this thread's module loads only. A worker thread or a
// second Node process would resolve without it, so `closeUnguardedRuntimes`
// makes `worker_threads.Worker`, `child_process.fork` and any spawn of
// Node's own executable throw before the worker loads (playwright-core
// launches the engine, never Node).
//
// Installed by main.js before anything else is imported.

import childProcess from "node:child_process";
import { readFileSync } from "node:fs";
import * as nodeModule from "node:module";
import workerThreads from "node:worker_threads";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The code a refused module raises (an optional require treats it as absent). */
export const MODULE_REFUSED = "ORCEL_MODULE_REFUSED";

/** The manifest's name inside dist/, and its schema. */
export const MANIFEST_NAME = "runtime-manifest.json";
export const MANIFEST_SCHEMA = "orcel-worker-runtime-manifest/1";

/** A path's drive letter in lower case; everything else as it is. */
function comparable(path: string): string {
  return /^[A-Za-z]:/.test(path) ? path[0]!.toLowerCase() + path.slice(1) : path;
}

/**
 * The files the manifest in `dist` names, as absolute paths (compared
 * exactly, but for the drive letter). A missing or malformed manifest, or a
 * name that is not a plain printable-ASCII relative path, throws: the guard
 * is then never installed and the worker does not start.
 */
export function loadAllowlist(dist: string): Set<string> {
  const manifest = JSON.parse(readFileSync(join(dist, MANIFEST_NAME), "utf8")) as { schema?: unknown; files?: unknown };
  if (manifest.schema !== MANIFEST_SCHEMA || !Array.isArray(manifest.files)) {
    throw new Error(`${MODULE_REFUSED}: the runtime manifest is malformed`);
  }
  const root = dirname(dist);
  const allowed = new Set<string>();
  for (const file of manifest.files as unknown[]) {
    if (typeof file !== "string" || file.length === 0 || !/^[\x20-\x7e]+$/.test(file) || /[\\:]/.test(file)) {
      throw new Error(`${MODULE_REFUSED}: the runtime manifest names a malformed path`);
    }
    const segments = file.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error(`${MODULE_REFUSED}: the runtime manifest names a malformed path`);
    }
    allowed.add(comparable(join(root, ...segments)));
  }
  return allowed;
}

/** Why `url` may not be loaded, given the pinned files, or null. */
export function moduleRefusal(url: string, allowed: ReadonlySet<string>): string | null {
  if (url.startsWith("node:")) {
    return null;
  }
  if (!url.startsWith("file:")) {
    return "only Node built-ins and the pinned runtime may be loaded";
  }
  let path: string;
  try {
    path = fileURLToPath(url);
  } catch {
    return "an unreadable module path";
  }
  return allowed.has(comparable(path)) ? null : "a module that is not a file of the pinned runtime";
}

/** Whether this Node has the synchronous module hooks the guard needs (22.15+). */
export function canGuard(): boolean {
  return typeof (nodeModule as { registerHooks?: unknown }).registerHooks === "function";
}

/** Refuse every module resolution outside the pinned runtime's files. */
export function installResolveGuard(dist: string = dirname(fileURLToPath(import.meta.url))): void {
  if (!canGuard()) {
    throw new Error(`${MODULE_REFUSED}: this Node has no module.registerHooks (Node 22.15 or later is required)`);
  }
  const allowed = loadAllowlist(dist);
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      const resolved = nextResolve(specifier, context);
      const refusal = moduleRefusal(resolved.url, allowed);
      if (refusal !== null) {
        const error = new Error(`${MODULE_REFUSED}: ${refusal}`) as Error & { code: string };
        error.code = MODULE_REFUSED;
        throw error;
      }
      return resolved;
    }
  });
}

function refusedRuntime(): never {
  const error = new Error(`${MODULE_REFUSED}: no code may run outside the resolve guard`) as Error & { code: string };
  error.code = MODULE_REFUSED;
  throw error;
}

/**
 * Close the ways code could run without the guard: worker threads, forked
 * Node processes and any spawn of Node's own executable. Spawning another
 * program (playwright-core starts the engine this way) is unchanged.
 */
export function closeUnguardedRuntimes(): void {
  const node = comparable(process.execPath);
  // Node's own executable, by path or by name (a PATH lookup), or any
  // command run through a shell.
  const isNode = (file: unknown): boolean =>
    typeof file === "string" && (comparable(file) === node || /(^|[\\/])node(\.exe)?$/i.test(file.trim()));
  const viaShell = (args: readonly unknown[]): boolean =>
    args.some((arg) => typeof arg === "object" && arg !== null && !Array.isArray(arg) && Boolean((arg as { shell?: unknown }).shell));
  const guarded = <T extends (...args: never[]) => unknown>(original: T): T =>
    ((...args: Parameters<T>) => (isNode(args[0]) || viaShell(args) ? refusedRuntime() : original(...args))) as T;
  const cp = childProcess as unknown as Record<string, unknown>;
  // Shell commands could start anything, Node included.
  for (const name of ["fork", "exec", "execSync"] as const) {
    cp[name] = refusedRuntime;
  }
  for (const name of ["spawn", "spawnSync", "execFile", "execFileSync"] as const) {
    cp[name] = guarded(cp[name] as (...args: never[]) => unknown);
  }
  (workerThreads as unknown as Record<string, unknown>).Worker = function Worker(): never {
    return refusedRuntime();
  };
  nodeModule.syncBuiltinESMExports();
}
