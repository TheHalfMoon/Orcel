// SG-000108 decision 7: the module resolve guard.
//
// The host pins the worker's runtime tree (package.json, dist/ and
// node_modules/playwright-core/) and holds its files, but Node also looks
// for modules outside that tree: an optional `require("bufferutil")` in
// playwright-core's bundled `ws` searches <root>/node_modules and every
// parent directory up to the drive root, and a `node_modules` directory
// created inside dist/ would shadow playwright-core itself. Pinning cannot
// stop a new file from appearing there. This guard does: every module the
// worker resolves must be a Node built-in, or a file inside dist/ or
// node_modules/playwright-core/ with no further `node_modules` segment.
// Anything else is refused, which an optional require sees as "absent".
//
// Installed by main.js before anything else is imported.

import { registerHooks } from "node:module";
import { dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** The code a refused module raises (an optional require treats it as absent). */
export const MODULE_REFUSED = "ORCEL_MODULE_REFUSED";

/**
 * Why `url` may not be loaded by a worker whose `dist/` is `dist`, or null.
 * Windows paths compare case-insensitively.
 */
export function moduleRefusal(url: string, dist: string): string | null {
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
  const root = dirname(dist);
  const allowed = [dist + sep, [root, "node_modules", "playwright-core"].join(sep) + sep];
  const lower = path.toLowerCase();
  for (const prefix of allowed) {
    if (lower.startsWith(prefix.toLowerCase())) {
      const rest = lower.slice(prefix.length).split(/[\\/]/);
      if (rest.includes("node_modules") || rest.includes("..")) {
        return "a module below the pinned runtime's own packages";
      }
      return null;
    }
  }
  return "a module outside the pinned runtime";
}

/** Refuse every module resolution outside the pinned runtime. */
export function installResolveGuard(dist: string = dirname(fileURLToPath(import.meta.url))): void {
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const resolved = nextResolve(specifier, context);
      const refusal = moduleRefusal(resolved.url, dist);
      if (refusal !== null) {
        const error = new Error(`${MODULE_REFUSED}: ${refusal}`) as Error & { code: string };
        error.code = MODULE_REFUSED;
        throw error;
      }
      return resolved;
    }
  });
}
