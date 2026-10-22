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
// Installed by main.js before anything else is imported.

import { readFileSync } from "node:fs";
import * as nodeModule from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The code a refused module raises (an optional require treats it as absent). */
export const MODULE_REFUSED = "ORCEL_MODULE_REFUSED";

/** The manifest's name inside dist/, and its schema. */
export const MANIFEST_NAME = "runtime-manifest.json";
export const MANIFEST_SCHEMA = "orcel-worker-runtime-manifest/1";

/**
 * The files the manifest in `dist` names, as absolute paths in lower case
 * (Windows paths compare case-insensitively). A missing or malformed
 * manifest, or a name that is not a plain relative path, throws: the guard
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
    if (typeof file !== "string" || file.length === 0 || /[\\:\u0000-\u001f]/.test(file)) {
      throw new Error(`${MODULE_REFUSED}: the runtime manifest names a malformed path`);
    }
    const segments = file.split("/");
    if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
      throw new Error(`${MODULE_REFUSED}: the runtime manifest names a malformed path`);
    }
    allowed.add(join(root, ...segments).toLowerCase());
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
  return allowed.has(path.toLowerCase()) ? null : "a module that is not a file of the pinned runtime";
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
