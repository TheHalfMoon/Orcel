import { createRequire } from "node:module";
import { dirname, join } from "node:path";

/**
 * Resolves the absolute path to the installed kaf binary from the app's
 * perspective.
 *
 * Uses module resolution rather than assuming an app-local `node_modules/kaf`:
 * npm workspaces hoist kaf to the workspace root, so the app-local path does
 * not exist there, while pnpm symlinks it app-locally. kaf does not export
 * `./bin/kaf.js`, but it does export `./package.json`, so we resolve that and
 * derive the bin path from the package root. Falls back to the conventional
 * app-local path when kaf cannot be resolved (e.g. before install).
 */
export function resolveKafBinaryPath(appRoot: string): string {
  try {
    const require = createRequire(join(appRoot, "package.json"));
    return join(dirname(require.resolve("kaf/package.json")), "bin", "kaf.js");
  } catch {
    return join(appRoot, "node_modules", "kaf", "bin", "kaf.js");
  }
}
