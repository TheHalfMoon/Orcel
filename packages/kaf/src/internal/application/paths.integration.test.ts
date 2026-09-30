import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { resolvePackageRoot } from "#internal/application/package.js";
import { resolveWorkflowBuildDirectory } from "#internal/application/paths.js";

describe("resolveWorkflowBuildDirectory prune (integration)", () => {
  const workflowCacheRoot = join(resolvePackageRoot(), ".kaf", "workflow-cache");
  const createdEntries: string[] = [];

  afterEach(() => {
    for (const entry of createdEntries) {
      rmSync(entry, { force: true, recursive: true });
    }
    createdEntries.length = 0;
  });

  it("removes a sibling workflow-cache directory whose kafVersion mismatches", () => {
    mkdirSync(workflowCacheRoot, { recursive: true });
    const staleDir = mkdtempSync(join(workflowCacheRoot, "stale-test-"));
    createdEntries.push(staleDir);
    writeFileSync(join(staleDir, "kaf-cache.json"), JSON.stringify({ kafVersion: "0.0.0-stale" }));

    resolveWorkflowBuildDirectory("/tmp/kaf-app");

    expect(readdirSync(workflowCacheRoot)).not.toContain(basename(staleDir));
  });

  it("preserves a sibling workflow-cache directory without kaf-cache.json", () => {
    mkdirSync(workflowCacheRoot, { recursive: true });
    const unknownDir = mkdtempSync(join(workflowCacheRoot, "unknown-test-"));
    createdEntries.push(unknownDir);

    resolveWorkflowBuildDirectory("/tmp/kaf-app");

    expect(readdirSync(workflowCacheRoot)).toContain(basename(unknownDir));
  });
});
