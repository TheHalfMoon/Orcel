import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { extensionUsesState } from "#internal/nitro/host/extension-state-usage.js";

async function createSourceTree(files: Record<string, string>): Promise<string> {
  const sourceRoot = await mkdtemp(join(tmpdir(), "orcel-state-usage-"));
  for (const [logicalPath, content] of Object.entries(files)) {
    const path = join(sourceRoot, logicalPath);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, content, "utf8");
  }
  return sourceRoot;
}

describe("extensionUsesState", () => {
  it("detects a direct aliased import", async () => {
    const sourceRoot = await createSourceTree({
      "lib/budget.ts": [
        'import { defineState as state } from "orcel/context";',
        'export const budget = state("budget", () => 1);',
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(true);
  });

  it("detects usage through a local re-export barrel", async () => {
    const sourceRoot = await createSourceTree({
      "lib/orcel.ts": 'export { defineState } from "orcel/context";\n',
      "tools/budget.ts": [
        'import { defineState } from "../lib/orcel";',
        'export const budget = defineState("budget", () => 1);',
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(true);
  });

  it("detects usage through an aliased multi-hop barrel chain", async () => {
    const sourceRoot = await createSourceTree({
      "lib/deep.ts": 'export { defineState as state } from "orcel/context";\n',
      "lib/orcel.ts": 'export { state } from "./deep";\n',
      "tools/budget.ts": [
        'import { state } from "../lib/orcel";',
        'export const budget = state("budget", () => 1);',
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(true);
  });

  it("detects usage through an `export *` barrel and a namespace import", async () => {
    const sourceRoot = await createSourceTree({
      "lib/orcel.ts": 'export * from "orcel/context";\n',
      "tools/budget.ts": [
        'import * as ctx from "../lib/orcel";',
        'export const budget = ctx.defineState("budget", () => 1);',
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(true);
  });

  it("detects an import-then-re-export barrel", async () => {
    const sourceRoot = await createSourceTree({
      "lib/orcel.ts": [
        'import { defineState } from "orcel/context";',
        "export { defineState as state };",
        "",
      ].join("\n"),
      "tools/budget.ts": [
        'import { state } from "../lib/orcel.js";',
        'export const budget = state("budget", () => 1);',
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(true);
  });

  it("ignores an imported defineState that is never called", async () => {
    const sourceRoot = await createSourceTree({
      "lib/orcel.ts": 'export { defineState } from "orcel/context";\n',
      "tools/idle.ts": [
        'import { defineState } from "../lib/orcel";',
        "export const unused = defineState;",
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(false);
  });

  it("ignores an unrelated local function named defineState", async () => {
    const sourceRoot = await createSourceTree({
      "tools/local.ts": [
        "const defineState = (name: string) => name;",
        'export const value = defineState("not-orcel-state");',
        "",
      ].join("\n"),
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(false);
  });

  it("returns false for a tree without state", async () => {
    const sourceRoot = await createSourceTree({
      "extension.ts":
        'import { defineExtension } from "orcel/extension";\nexport default defineExtension();\n',
    });
    await expect(extensionUsesState(sourceRoot)).resolves.toBe(false);
  });
});
