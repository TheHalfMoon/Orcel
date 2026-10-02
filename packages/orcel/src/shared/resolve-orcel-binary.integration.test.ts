import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { resolveOrcelBinaryPath } from "./resolve-orcel-binary.js";

// Writes a minimal orcel package at `dir` and returns its realpath'd bin path
// (createRequire canonicalizes symlinks, and macOS routes tmpdir through one).
async function writeOrcelPackage(dir: string): Promise<string> {
  await mkdir(join(dir, "bin"), { recursive: true });
  await writeFile(join(dir, "package.json"), JSON.stringify({ name: "orcel", version: "0.0.0" }));
  await writeFile(join(dir, "bin", "orcel.js"), "#!/usr/bin/env node\n");
  return join(await realpath(dir), "bin", "orcel.js");
}

describe("resolveOrcelBinaryPath", () => {
  it("resolves orcel hoisted to the workspace root (npm workspaces)", async () => {
    const workspaceRoot = await mkdtemp(join(tmpdir(), "orcel-resolve-"));
    const expected = await writeOrcelPackage(join(workspaceRoot, "node_modules", "orcel"));

    // The app has no orcel under its own node_modules; npm hoisted it up.
    const appRoot = join(workspaceRoot, "apps", "web");
    await mkdir(appRoot, { recursive: true });
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ name: "web" }));

    // realpath both sides so Windows short (8.3) paths compare equal.
    expect(await realpath(resolveOrcelBinaryPath(appRoot))).toBe(expected);
  });

  it("resolves orcel through pnpm's virtual-store symlink", async () => {
    const appRoot = await mkdtemp(join(tmpdir(), "orcel-resolve-"));
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ name: "web" }));

    // pnpm installs the real package under .pnpm and symlinks node_modules/orcel
    // to it; the resolver must follow the link to the store.
    const storeRoot = join(appRoot, "node_modules", ".pnpm", "orcel@0.0.0", "node_modules", "orcel");
    const expected = await writeOrcelPackage(storeRoot);
    await symlink(storeRoot, join(appRoot, "node_modules", "orcel"), "junction");

    expect(await realpath(resolveOrcelBinaryPath(appRoot))).toBe(expected);
  });
});
