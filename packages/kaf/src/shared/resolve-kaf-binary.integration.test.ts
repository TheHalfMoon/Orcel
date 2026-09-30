import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { resolveKafBinaryPath } from "./resolve-kaf-binary.js";

// Writes a minimal kaf package at `dir` and returns its realpath'd bin path
// (createRequire canonicalizes symlinks, and macOS routes tmpdir through one).
async function writeKafPackage(dir: string): Promise<string> {
  await mkdir(join(dir, "bin"), { recursive: true });
  await writeFile(join(dir, "package.json"), JSON.stringify({ name: "kaf", version: "0.0.0" }));
  await writeFile(join(dir, "bin", "kaf.js"), "#!/usr/bin/env node\n");
  return join(await realpath(dir), "bin", "kaf.js");
}

describe("resolveKafBinaryPath", () => {
  it("resolves kaf hoisted to the workspace root (npm workspaces)", async () => {
    const workspaceRoot = await mkdtemp(join(tmpdir(), "kaf-resolve-"));
    const expected = await writeKafPackage(join(workspaceRoot, "node_modules", "kaf"));

    // The app has no kaf under its own node_modules; npm hoisted it up.
    const appRoot = join(workspaceRoot, "apps", "web");
    await mkdir(appRoot, { recursive: true });
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ name: "web" }));

    // realpath both sides so Windows short (8.3) paths compare equal.
    expect(await realpath(resolveKafBinaryPath(appRoot))).toBe(expected);
  });

  it("resolves kaf through pnpm's virtual-store symlink", async () => {
    const appRoot = await mkdtemp(join(tmpdir(), "kaf-resolve-"));
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ name: "web" }));

    // pnpm installs the real package under .pnpm and symlinks node_modules/kaf
    // to it; the resolver must follow the link to the store.
    const storeRoot = join(appRoot, "node_modules", ".pnpm", "kaf@0.0.0", "node_modules", "kaf");
    const expected = await writeKafPackage(storeRoot);
    await symlink(storeRoot, join(appRoot, "node_modules", "kaf"), "junction");

    expect(await realpath(resolveKafBinaryPath(appRoot))).toBe(expected);
  });
});
