import { access, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-kaf-binary.js", () => ({
  resolveKafBinaryPath: (root: string) => join(root, "node_modules", "kaf", "bin", "kaf.js"),
}));

import { withEve } from "./index.js";

async function createWorkspace(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "kaf-vercel-config-"));
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({ dependencies: { kaf: "*" }, packageManager: "pnpm@10.0.0", private: true }),
  );
  await Promise.all([
    mkdir(join(root, "agents", "support", "agent"), { recursive: true }),
    mkdir(join(root, "agents", "research", "agent"), { recursive: true }),
  ]);
  return root;
}

describe("withEve", () => {
  it("composes workspace agents with authored Vercel services and routes", async () => {
    const root = await createWorkspace();
    const config = await withEve(
      {
        crons: [{ path: "/api/dispatch", schedule: "* * * * *" }],
        routes: [
          { destination: { service: "web", type: "service" }, src: "^/api/(.*)$" },
          { handle: "filesystem" },
        ],
        services: { web: { framework: "nextjs", root: "apps/web" } },
      },
      { root },
    );

    expect(config.crons).toEqual([{ path: "/api/dispatch", schedule: "* * * * *" }]);
    expect(config.routes).toEqual([
      { destination: { service: "web", type: "service" }, src: "^/api/(.*)$" },
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
    expect(config.services.web).toEqual({ framework: "nextjs", root: "apps/web" });
    expect(config.services["kaf-support"]).toEqual({
      buildCommand:
        "cd '../../../agents/support' && export KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY='../../.kaf/vercel-services/kaf-support/.vercel/output' && export KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../../.vercel/output' && export KAF_PUBLIC_ROUTE_PREFIX='/kaf/support' && export KAF_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && node 'node_modules/kaf/bin/kaf.js' build",
      devCommand:
        "cd '../../../agents/support' && export KAF_PUBLIC_ROUTE_PREFIX='/kaf/support' && export KAF_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && node 'node_modules/kaf/bin/kaf.js' dev --no-ui",
      framework: "kaf",
      outputDirectory: ".vercel/output",
      root: ".kaf/vercel-services/kaf-support",
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
    await expect(
      access(join(root, ".kaf", "vercel-services", "kaf-support")),
    ).resolves.toBeUndefined();
  });

  it("discovers the workspace when Vercel evaluates config from .vercel", async () => {
    const root = await createWorkspace();
    const configDirectory = join(root, ".vercel");
    await mkdir(configDirectory);
    const originalCwd = process.cwd();
    process.chdir(configDirectory);
    try {
      const config = await withEve({});
      expect(config.services["kaf-support"]).toBeDefined();
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("does not modify the root Build Output", async () => {
    const root = await createWorkspace();
    const marker = join(root, ".vercel", "output", "services", "web", "config.json");
    await mkdir(join(marker, ".."), { recursive: true });
    await writeFile(marker, "web output");

    await withEve({}, { root });

    await expect(access(marker)).resolves.toBeUndefined();
  });

  it("rejects authored service keys owned by generated agents", async () => {
    const root = await createWorkspace();

    await expect(
      withEve({ services: { "kaf-support": { framework: "nextjs" } } }, { root }),
    ).rejects.toThrow(
      'Vercel service key "kaf-support" conflicts with the service generated for kaf agent "support". Remove or rename the authored service; withEve owns this key.',
    );
  });

  it("rejects authored kaf services when composing a standalone agent", async () => {
    const root = await mkdtemp(join(tmpdir(), "kaf-vercel-config-standalone-conflict-"));
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { kaf: "*" } }));
    await mkdir(join(root, "agent"), { recursive: true });

    await expect(withEve({ services: { legacy: { framework: "kaf" } } }, { root })).rejects.toThrow(
      'Vercel service key "kaf" conflicts with the service generated for kaf agent "the default agent". Remove or rename the authored service; withEve owns this key.',
    );
  });

  it("rejects authored routes owned by generated agents", async () => {
    const root = await createWorkspace();

    await expect(
      withEve({ routes: [{ src: "^/kaf/support/v1/(.*)$" }] }, { root }),
    ).rejects.toThrow(
      'Vercel route "^/kaf/support/v1/(.*)$" conflicts with the route generated for kaf agent "support". Remove the authored route; withEve adds it automatically.',
    );
  });

  it("rejects authored routes owned by generated agent home pages", async () => {
    const root = await createWorkspace();

    await expect(withEve({ routes: [{ src: "^/kaf/support/?$" }] }, { root })).rejects.toThrow(
      'Vercel route "^/kaf/support/?$" conflicts with the route generated for kaf agent "support". Remove the authored route; withEve adds it automatically.',
    );
  });

  it("rejects duplicate names in a service array", async () => {
    const root = await createWorkspace();

    await expect(
      withEve(
        {
          services: [
            { framework: "nextjs", name: "web", root: "apps/first" },
            { framework: "nuxtjs", name: "web", root: "apps/second" },
          ],
        },
        { root },
      ),
    ).rejects.toThrow('Duplicate Vercel service name "web".');
  });

  it("rejects obsolete service fields", async () => {
    const root = await createWorkspace();

    await expect(withEve({ experimentalServicesV2: {} }, { root })).rejects.toThrow(
      "withEve cannot compose experimentalServices or experimentalServicesV2. Remove the obsolete field and define authored services under services.",
    );
  });

  it("requires at least one workspace agent", async () => {
    const root = await mkdtemp(join(tmpdir(), "kaf-vercel-config-empty-workspace-"));
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { kaf: "*" } }));
    await mkdir(join(root, "agents"));

    await expect(withEve({}, { root })).rejects.toThrow(
      `withEve found no workspace agents under ${join(root, "agents")}. Add an agent or remove withEve from vercel.ts.`,
    );
  });

  it("composes a standalone agent at the unprefixed protocol route", async () => {
    const root = await mkdtemp(join(tmpdir(), "kaf-vercel-config-standalone-"));
    await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { kaf: "*" } }));
    await mkdir(join(root, "agent"), { recursive: true });

    const config = await withEve({}, { root });

    expect(config.routes).toEqual([
      { destination: { service: "kaf", type: "service" }, src: "^/kaf/v1/(.*)$" },
    ]);
    expect(config.services.kaf).toEqual({
      buildCommand:
        "cd '../../..' && export KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY='.kaf/vercel-services/kaf/.vercel/output' && export KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && node 'node_modules/kaf/bin/kaf.js' build",
      devCommand: "cd '../../..' && node 'node_modules/kaf/bin/kaf.js' dev --no-ui",
      framework: "kaf",
      outputDirectory: ".vercel/output",
      root: ".kaf/vercel-services/kaf",
      routes: [
        {
          src: "^/kaf/v1/(.*)$",
          transforms: [{ args: "/kaf/v1/$1", op: "set", type: "request.path" }],
        },
      ],
    });
  });
});
