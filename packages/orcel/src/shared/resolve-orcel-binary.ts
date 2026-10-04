import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { ORCEL_PACKAGE_NAME } from "../internal/package-name.js";

/**
 * Resolves the absolute path to the installed orcel binary from the app's
 * perspective.
 *
 * Uses module resolution rather than assuming an app-local `node_modules/@orcel/orcel`:
 * npm workspaces hoist orcel to the workspace root, so the app-local path does
 * not exist there, while pnpm symlinks it app-locally. orcel does not export
 * `./bin/orcel.js`, but it does export `./package.json`, so we resolve that and
 * derive the bin path from the package root. Falls back to the conventional
 * app-local path when orcel cannot be resolved (e.g. before install).
 */
export function resolveOrcelBinaryPath(appRoot: string): string {
  try {
    const require = createRequire(join(appRoot, "package.json"));
    return join(dirname(require.resolve(`${ORCEL_PACKAGE_NAME}/package.json`)), "bin", "orcel.js");
  } catch {
    return join(appRoot, "node_modules", ...ORCEL_PACKAGE_NAME.split("/"), "bin", "orcel.js");
  }
}
