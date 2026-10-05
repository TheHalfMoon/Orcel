import { access, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-orcel-binary.js", () => ({
  resolveOrcelBinaryPath: (root: string) => join(root, "node_modules", "@orcel", "orcel", "bin", "orcel.js"),
}));

import { resolveOrcelProjectContext } from "#internal/project-context.js";
import { buildAgentWorkspace } from "#internal/vercel/build-agent-workspace.js";

async function createWorkspace(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "orcel-workspace-build-"));
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      dependencies: { "@orcel/orcel": "*" },
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
  const context = await resolveOrcelProjectContext(root);
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
      await readFile(join(root, ".orcel", "agent-summary.json"), "utf8"),
    );

    expect(multiAgentSummary).toMatchObject({
      agents: [
        {
          name: "research",
          routePrefix: "/orcel/research",
          summaryPath: "agents/research/.orcel/agent-summary.json",
        },
        {
          name: "support",
          routePrefix: "/orcel/support",
          summaryPath: "agents/support/.orcel/agent-summary.json",
        },
      ],
      kind: "vercel-orcel-multi-agent-summary",
      schemaVersion: 1,
    });

    expect(config.routes).toEqual([
      {
        destination: { service: "orcel-research", type: "service" },
        src: "^/orcel/research/v1/(.*)$",
      },
      {
        destination: { service: "orcel-research", type: "service" },
        src: "^/orcel/research/?$",
      },
      {
        destination: { service: "orcel-support", type: "service" },
        src: "^/orcel/support/v1/(.*)$",
      },
      {
        destination: { service: "orcel-support", type: "service" },
        src: "^/orcel/support/?$",
      },
      { handle: "filesystem" },
    ]);
    await expect(readFile(join(output, "static", "index.html"), "utf8")).resolves.toContain(
      "2 agents are up and accepting messages.",
    );
    await expect(
      access(join(root, ".orcel", "vercel-services", "orcel-support")),
    ).resolves.toBeUndefined();

    expect(config.services["orcel-support"]).toEqual({
      buildCommand:
        "cd '../../../agents/support' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='../../.orcel/vercel-services/orcel-support/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../../.vercel/output' && export ORCEL_PUBLIC_ROUTE_PREFIX='/orcel/support' && export ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && node 'node_modules/@orcel/orcel/bin/orcel.js' build",
      devCommand:
        "cd '../../../agents/support' && export ORCEL_PUBLIC_ROUTE_PREFIX='/orcel/support' && export ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && node 'node_modules/@orcel/orcel/bin/orcel.js' dev --no-ui",
      framework: "eve",
      outputDirectory: ".vercel/output",
      root: ".orcel/vercel-services/orcel-support",
      routePrefix: "/orcel/support",
      routes: [
        {
          src: "^/orcel/support/?$",
          transforms: [{ args: "/", op: "set", type: "request.path" }],
        },
        {
          src: "^/orcel/support/v1/(.*)$",
          transforms: [{ args: "/orcel/v1/$1", op: "set", type: "request.path" }],
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
      name.startsWith("orcel-support-"),
    );

    expect(supportServiceName).toMatch(/^orcel-support-[a-z]+$/);
    expect(config.routes).toContainEqual({
      destination: { service: supportServiceName, type: "service" },
      src: "^/orcel/support2/v1/(.*)$",
    });
  });

  it("refuses to assemble an authored graph", async () => {
    const root = await createWorkspace();
    await writeFile(join(root, "vercel.json"), JSON.stringify({ services: {} }));
    const workspace = await resolveWorkspace(root);
    await expect(buildAgentWorkspace(workspace)).rejects.toThrow(/vercel\.ts.*orcel\/vercel/);
  });
});
