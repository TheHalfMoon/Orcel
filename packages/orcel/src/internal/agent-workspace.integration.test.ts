import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createMemoryProjectSource } from "#discover/project-source.js";
import { resolveDiscoveryProject } from "#discover/project.js";
import { findOrcelProjectContext, resolveOrcelProjectContext } from "#internal/project-context.js";

async function createWorkspace(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "orcel-workspace-"));
  await Promise.all([
    mkdir(join(root, "agents", "support", "agent"), { recursive: true }),
    mkdir(join(root, "agents", "research", "agent"), { recursive: true }),
    writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } })),
  ]);
  return root;
}

describe("resolveOrcelProjectContext", () => {
  it("discovers direct agents/ children in deterministic order", async () => {
    const root = await createWorkspace();
    await expect(resolveOrcelProjectContext(root)).resolves.toEqual({
      environmentRoot: root,
      kind: "workspace",
      workspace: {
        members: [
          { name: "research", appRoot: join(root, "agents", "research") },
          { name: "support", appRoot: join(root, "agents", "support") },
        ],
        root,
      },
    });
  });

  it("requires the root package to declare orcel as a runtime dependency", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-workspace-no-dependency-"));
    await Promise.all([
      mkdir(join(root, "agents", "support", "agent"), { recursive: true }),
      writeFile(join(root, "package.json"), JSON.stringify({ devDependencies: { "@orcel/orcel": "*" } })),
    ]);
    await expect(findOrcelProjectContext(root)).resolves.toBeUndefined();
  });

  it("treats agents in a monorepo that only develops with orcel as standalone projects", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-agent-monorepo-"));
    const appRoot = join(root, "agents", "support");
    await mkdir(join(appRoot, "agent"), { recursive: true });
    await Promise.all([
      writeFile(join(root, "package.json"), JSON.stringify({ devDependencies: { "@orcel/orcel": "*" } })),
      writeFile(
        join(appRoot, "package.json"),
        JSON.stringify({ dependencies: { "@orcel/orcel": "*" }, name: "support" }),
      ),
    ]);

    await expect(resolveOrcelProjectContext(join(appRoot, "agent"))).resolves.toEqual({
      appRoot,
      environmentRoot: appRoot,
      kind: "standalone",
    });
  });

  it("treats agent/ as standalone even when agents/ also exists", async () => {
    const root = await createWorkspace();
    await mkdir(join(root, "agent"));

    await expect(resolveOrcelProjectContext(root)).resolves.toEqual({
      appRoot: root,
      environmentRoot: root,
      kind: "standalone",
    });
  });

  it("allows an empty workspace", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-workspace-empty-"));
    await mkdir(join(root, "agents"));
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } }));

    await expect(resolveOrcelProjectContext(root)).resolves.toMatchObject({
      kind: "workspace",
      workspace: { members: [], root },
    });
  });

  it("discovers flat workspace members", async () => {
    const root = await createWorkspace();
    const appRoot = join(root, "agents", "flat");
    await mkdir(appRoot);
    await writeFile(join(appRoot, "agent.ts"), "export default {};\n");

    await expect(resolveOrcelProjectContext(appRoot)).resolves.toMatchObject({
      kind: "workspace-member",
      member: { appRoot, name: "flat" },
    });
  });

  it("excludes independently packaged orcel projects from a workspace", async () => {
    const root = await createWorkspace();
    const appRoot = join(root, "agents", "billing");
    await mkdir(join(appRoot, "agent"), { recursive: true });
    await writeFile(
      join(appRoot, "package.json"),
      JSON.stringify({ dependencies: { "@orcel/orcel": "*" }, name: "billing" }),
    );

    await expect(resolveOrcelProjectContext(root)).resolves.toMatchObject({
      kind: "workspace",
      workspace: {
        members: [
          { name: "research", appRoot: join(root, "agents", "research") },
          { name: "support", appRoot: join(root, "agents", "support") },
        ],
      },
    });
    await expect(resolveOrcelProjectContext(appRoot)).resolves.toEqual({
      appRoot,
      environmentRoot: appRoot,
      kind: "standalone",
    });
  });

  it("excludes packaged non-orcel directories from a workspace", async () => {
    const root = await createWorkspace();
    const appRoot = join(root, "agents", "utilities");
    await mkdir(join(appRoot, "src"), { recursive: true });
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ name: "utilities" }));

    await expect(resolveOrcelProjectContext(root)).resolves.toMatchObject({
      kind: "workspace",
      workspace: {
        members: [
          { name: "research", appRoot: join(root, "agents", "research") },
          { name: "support", appRoot: join(root, "agents", "support") },
        ],
      },
    });
    await expect(findOrcelProjectContext(appRoot)).resolves.toBeUndefined();
  });

  it("excludes package-less directories without agent files from a workspace", async () => {
    const root = await createWorkspace();
    const sharedRoot = join(root, "agents", "Internal Helpers");
    await mkdir(sharedRoot);
    await writeFile(join(sharedRoot, "helpers.ts"), "export {};\n");

    await expect(resolveOrcelProjectContext(root)).resolves.toMatchObject({
      kind: "workspace",
      workspace: {
        members: [
          { name: "research", appRoot: join(root, "agents", "research") },
          { name: "support", appRoot: join(root, "agents", "support") },
        ],
      },
    });
  });

  it("keeps conventional members discoverable without project metadata", async () => {
    const root = await createWorkspace();
    const supportRoot = join(root, "agents", "support");
    await expect(resolveDiscoveryProject(supportRoot)).resolves.toEqual({
      agentRoot: join(supportRoot, "agent"),
      appRoot: supportRoot,
      layout: "nested",
    });
  });

  it("supports conventional discovery through an in-memory project source", async () => {
    const root = join(process.cwd(), "memory", "project");
    const supportRoot = join(root, "agents", "support");
    const source = createMemoryProjectSource({
      files: {
        [join(root, "package.json")]: JSON.stringify({ dependencies: { "@orcel/orcel": "*" } }),
        [join(supportRoot, "agent", "instructions.md")]: "Support users.",
      },
    });

    await expect(resolveDiscoveryProject(supportRoot, { source })).resolves.toEqual({
      agentRoot: join(supportRoot, "agent"),
      appRoot: supportRoot,
      layout: "nested",
    });
  });

  it("resolves a workspace member from any file in its tree", async () => {
    const root = await createWorkspace();
    const supportRoot = join(root, "agents", "support");
    const toolPath = join(supportRoot, "agent", "tools", "search.ts");
    await mkdir(join(supportRoot, "agent", "tools"), { recursive: true });
    await writeFile(toolPath, "export default {};\n");
    await expect(resolveOrcelProjectContext(toolPath)).resolves.toMatchObject({
      workspace: { root },
      environmentRoot: root,
      kind: "workspace-member",
      member: { appRoot: supportRoot, name: "support" },
    });
  });

  it("ignores unrelated agents directories above a standalone project", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-standalone-unrelated-agents-"));
    const appRoot = join(root, "orcel", "apps", "fixtures", "weather-agent");
    await mkdir(join(appRoot, "agent"), { recursive: true });
    await mkdir(join(root, "agents", "apps"), { recursive: true });
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } }));

    await expect(resolveOrcelProjectContext(appRoot)).resolves.toEqual({
      appRoot,
      environmentRoot: appRoot,
      kind: "standalone",
    });
  });

  it("preserves a standalone project boundary above an agents directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-standalone-boundary-"));
    const appRoot = join(root, "agents", "support");
    await mkdir(join(root, "agent"), { recursive: true });
    await mkdir(join(appRoot, "agent"), { recursive: true });
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } }));
    await writeFile(join(appRoot, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } }));

    await expect(resolveOrcelProjectContext(appRoot)).resolves.toEqual({
      appRoot,
      environmentRoot: appRoot,
      kind: "standalone",
    });
  });

  it("resolves a flat standalone agent", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-flat-agent-"));
    await Promise.all([
      writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } })),
      writeFile(join(root, "agent.ts"), "export default {};\n"),
    ]);

    await expect(resolveOrcelProjectContext(root)).resolves.toEqual({
      appRoot: root,
      environmentRoot: root,
      kind: "standalone",
    });
  });

  it("keeps a flat standalone agent above an unrelated agents directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-flat-agent-unrelated-agents-"));
    await mkdir(join(root, "agents", "customer-support"), { recursive: true });
    await Promise.all([
      writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } })),
      writeFile(join(root, "agent.ts"), "export default {};\n"),
      writeFile(join(root, "agents", "customer-support", "index.ts"), "export {};\n"),
    ]);

    await expect(resolveOrcelProjectContext(root)).resolves.toEqual({
      appRoot: root,
      environmentRoot: root,
      kind: "standalone",
    });
  });

  it("resolves workspace-owned paths outside any member to the workspace", async () => {
    const root = await createWorkspace();
    const sourceRoot = join(root, "src");
    await mkdir(sourceRoot);

    await expect(resolveOrcelProjectContext(sourceRoot)).resolves.toMatchObject({
      workspace: { root },
      environmentRoot: root,
      kind: "workspace",
    });
  });

  it("stops at the nearest non-orcel package boundary", async () => {
    const root = await createWorkspace();
    const packageRoot = join(root, "packages", "unrelated");
    await mkdir(packageRoot, { recursive: true });
    await writeFile(join(packageRoot, "package.json"), JSON.stringify({ dependencies: {} }));

    await expect(findOrcelProjectContext(packageRoot)).resolves.toBeUndefined();
  });

  it("rejects an orcel package without agent files", async () => {
    const root = await mkdtemp(join(tmpdir(), "orcel-invalid-shape-"));
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { "@orcel/orcel": "*" } }));

    await expect(resolveOrcelProjectContext(root)).rejects.toThrow(/found no agent files/);
  });
});
