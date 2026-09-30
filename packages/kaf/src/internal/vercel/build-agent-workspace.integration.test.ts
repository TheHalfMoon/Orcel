import { access, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-kaf-binary.js", () => ({
  resolveKafBinaryPath: (root: string) => join(root, "node_modules", "kaf", "bin", "kaf.js"),
}));

import { resolveKafProjectContext } from "#internal/project-context.js";
import { buildAgentWorkspace } from "#internal/vercel/build-agent-workspace.js";

async function createWorkspace(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "kaf-workspace-build-"));
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      dependencies: { kaf: "*" },
      packageManager: "pnpm@10.0.0",
      private: true,
    }),
  );
  await Promise.all([
    mkdir(join(root, "agents", "support", "agent"), { recursive: true }),
    mkdir(join(root, "agents", "research", "agent"), { recursive: true }),
  ]);
  return root;
}

async function resolveWorkspace(root: string) {
  const context = await resolveKafProjectContext(root);
  if (context.kind !== "workspace") throw new Error("Expected a workspace context.");
  return context.workspace;
}

describe("buildAgentWorkspace", () => {
  it("emits peer services and canonical public routes", async () => {
    const root = await createWorkspace();
    const workspace = await resolveWorkspace(root);
    expect(workspace).toBeDefined();

    const output = await buildAgentWorkspace(workspace);
    const config = JSON.parse(await readFile(join(output, "config.json"), "utf8"));
    const multiAgentSummary = JSON.parse(
      await readFile(join(root, ".kaf", "agent-summary.json"), "utf8"),
    );

    expect(multiAgentSummary).toMatchObject({
      agents: [
        {
          name: "research",
          routePrefix: "/kaf/research",
          summaryPath: "agents/research/.kaf/agent-summary.json",
        },
        {
          name: "support",
          routePrefix: "/kaf/support",
          summaryPath: "agents/support/.kaf/agent-summary.json",
        },
      ],
      kind: "vercel-kaf-multi-agent-summary",
      schemaVersion: 1,
    });

    expect(config.routes).toEqual([
      {
        destination: { service: "kaf-research", type: "service" },
        src: "^/kaf/research/v1/(.*)$",
      },
      {
        destination: { service: "kaf-research", type: "service" },
        src: "^/kaf/research/?$",
      },
      {
        destination: { service: "kaf-support", type: "service" },
        src: "^/kaf/support/v1/(.*)$",
      },
      {
        destination: { service: "kaf-support", type: "service" },
        src: "^/kaf/support/?$",
      },
      { handle: "filesystem" },
    ]);
    await expect(readFile(join(output, "static", "index.html"), "utf8")).resolves.toContain(
      "2 agents are up and accepting messages.",
    );
    await expect(
      access(join(root, ".kaf", "vercel-services", "kaf-support")),
    ).resolves.toBeUndefined();

    expect(config.services["kaf-support"]).toEqual({
      buildCommand:
        "cd '../../../agents/support' && export KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY='../../.kaf/vercel-services/kaf-support/.vercel/output' && export KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../../.vercel/output' && export KAF_PUBLIC_ROUTE_PREFIX='/kaf/support' && export KAF_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && node 'node_modules/kaf/bin/kaf.js' build",
      devCommand:
        "cd '../../../agents/support' && export KAF_PUBLIC_ROUTE_PREFIX='/kaf/support' && export KAF_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && node 'node_modules/kaf/bin/kaf.js' dev --no-ui",
      framework: "kaf",
      outputDirectory: ".vercel/output",
      root: ".kaf/vercel-services/kaf-support",
      routePrefix: "/kaf/support",
      routes: [
        {
          src: "^/kaf/support/?$",
          transforms: [{ args: "/", op: "set", type: "request.path" }],
        },
        {
          src: "^/kaf/support/v1/(.*)$",
          transforms: [{ args: "/kaf/v1/$1", op: "set", type: "request.path" }],
        },
      ],
    });
  });

  it("keeps digit-bearing public names while encoding the generated service name", async () => {
    const root = await createWorkspace();
    await mkdir(join(root, "agents", "support2", "agent"), { recursive: true });
    const workspace = await resolveWorkspace(root);
    const output = await buildAgentWorkspace(workspace);
    const config = JSON.parse(await readFile(join(output, "config.json"), "utf8"));
    const supportServiceName = Object.keys(config.services).find((name) =>
      name.startsWith("kaf-support-"),
    );

    expect(supportServiceName).toMatch(/^kaf-support-[a-z]+$/);
    expect(config.routes).toContainEqual({
      destination: { service: supportServiceName, type: "service" },
      src: "^/kaf/support2/v1/(.*)$",
    });
  });

  it("refuses to assemble an authored graph", async () => {
    const root = await createWorkspace();
    await writeFile(join(root, "vercel.json"), JSON.stringify({ services: {} }));
    const workspace = await resolveWorkspace(root);
    await expect(buildAgentWorkspace(workspace)).rejects.toThrow(/vercel\.ts.*kaf\/vercel/);
  });
});
