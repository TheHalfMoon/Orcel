import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-orcel-binary.js", async () => {
  const { join } = await import("node:path");
  return {
    // Pin resolution to the conventional app-local path so build-command
    // assertions stay deterministic without a real orcel install on disk. The
    // real resolver is exercised in resolve-orcel-binary.integration.test.ts.
    resolveOrcelBinaryPath: (nextRoot: string) =>
      join(nextRoot, "node_modules", "orcel", "bin", "orcel.js"),
  };
});

import { withEve, type OrcelNextConfig, type OrcelNextRewriteSections } from "./index.js";

interface TestConfig extends OrcelNextConfig {
  readonly basePath?: string;
}

async function createTempAppRoot(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "orcel-next-config-"));
}

async function readJsonFile(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

async function resolveConfig(config: ReturnType<typeof withEve<TestConfig>>): Promise<TestConfig> {
  return await config("phase-test", {
    defaultConfig: {},
  });
}

describe("withEve Vercel config", () => {
  const originalCwd = process.cwd();

  afterEach(() => {
    process.chdir(originalCwd);
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("requires a local orcel build outside Vercel", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");

    const config = await resolveConfig(withEve<TestConfig>({}));
    await expect(config.rewrites?.()).rejects.toThrow(
      /Run orcel build from .+ before starting Next\.js\./u,
    );
    await expect(
      readFile(join(appRoot, ".vercel", "output", "config.json"), "utf8"),
    ).rejects.toThrow();
  });

  it("writes Build Output config in Vercel even when no linked project is detected", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toEqual({
      routes: [
        {
          destination: {
            service: "orcel",
            type: "service",
          },
          src: "^/orcel/v1/(.*)$",
        },
      ],
      services: {
        orcel: {
          buildCommand:
            "cd '../../..' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && node 'node_modules/orcel/bin/orcel.js' build",
          framework: "eve",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/orcel/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".orcel/vercel-services/orcel",
        },
      },
      version: 3,
    });
    expect(rewrites).toBeUndefined();
  });

  it("isolates a colocated generated orcel service from the Next.js Build Output", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    await resolveConfig(withEve<TestConfig>({}));

    const serviceRoot = join(appRoot, ".orcel", "vercel-services", "orcel");
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect((await stat(serviceRoot)).isDirectory()).toBe(true);
    expect(outputConfig).toMatchObject({
      services: {
        orcel: {
          buildCommand:
            "cd '../../..' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && node 'node_modules/orcel/bin/orcel.js' build",
          root: ".orcel/vercel-services/orcel",
        },
      },
    });
  });

  it("writes fallback Build Output config under the app in a linked monorepo", async () => {
    const projectRoot = await createTempAppRoot();
    const appRoot = join(projectRoot, "apps", "web");
    await mkdir(join(projectRoot, ".vercel"), { recursive: true });
    await writeFile(
      join(projectRoot, ".vercel", "project.json"),
      JSON.stringify({ settings: { rootDirectory: "apps/web" } }),
    );
    await mkdir(join(projectRoot, "custom-staging"));
    await writeFile(join(projectRoot, "custom-staging", "builds.json"), "{}\n");
    await mkdir(appRoot, { recursive: true });
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    await resolveConfig(withEve<TestConfig>({}));

    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toEqual({
      routes: [
        {
          destination: {
            service: "orcel",
            type: "service",
          },
          src: "^/orcel/v1/(.*)$",
        },
      ],
      services: {
        orcel: {
          buildCommand:
            "cd '../../..' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && node 'node_modules/orcel/bin/orcel.js' build",
          framework: "eve",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/orcel/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".orcel/vercel-services/orcel",
        },
      },
      version: 3,
    });
    await expect(
      readFile(join(projectRoot, ".vercel", "output", "config.json"), "utf8"),
    ).rejects.toThrow();
  });

  it("uses an already configured root orcel service", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");
    await writeFile(
      join(appRoot, "vercel.json"),
      `${JSON.stringify(
        {
          $schema: "https://openapi.vercel.sh/vercel.json",
          services: {
            agent: {
              entrypoint: "package.json",
              framework: "eve",
              root: "agent",
            },
          },
        },
        null,
        2,
      )}\n`,
    );

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    await expect(
      readFile(join(appRoot, ".vercel", "output", "config.json"), "utf8"),
    ).rejects.toThrow();
    expect(rewrites).toBeUndefined();
  });

  it("preserves an already configured Build Output orcel service and inserts its route", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");
    await mkdir(join(appRoot, ".vercel", "output"), { recursive: true });
    await writeFile(join(appRoot, ".vercel", "project.json"), "{}\n");
    await writeFile(
      join(appRoot, ".vercel", "output", "config.json"),
      `${JSON.stringify(
        {
          version: 3,
          routes: [
            { handle: "filesystem" },
            {
              destination: {
                service: "agent",
                type: "service",
              },
              src: "^/orcel/v1/(.*)$",
            },
          ],
          services: {
            agent: {
              entrypoint: "package.json",
              framework: "eve",
              root: "agent",
            },
          },
        },
        null,
        2,
      )}\n`,
    );

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toEqual({
      routes: [
        {
          destination: {
            service: "agent",
            type: "service",
          },
          src: "^/orcel/v1/(.*)$",
        },
        { handle: "filesystem" },
      ],
      services: {
        agent: {
          entrypoint: "package.json",
          framework: "eve",
          routes: [
            {
              src: "^/orcel/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: "agent",
        },
      },
      version: 3,
    });
    expect(rewrites).toBeUndefined();
  });

  it("discovers workspace agents when the Next.js app owns the workspace", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    await Promise.all([
      mkdir(join(appRoot, "agents", "support", "agent"), { recursive: true }),
      mkdir(join(appRoot, "agents", "research", "agent"), { recursive: true }),
      writeFile(join(appRoot, "package.json"), JSON.stringify({ dependencies: { orcel: "*" } })),
    ]);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toMatchObject({
      routes: expect.arrayContaining([
        expect.objectContaining({
          destination: { service: "orcel-research", type: "service" },
          src: "^/orcel/research/v1/(.*)$",
        }),
        expect.objectContaining({
          destination: { service: "orcel-support", type: "service" },
          src: "^/orcel/support/v1/(.*)$",
        }),
        expect.objectContaining({
          destination: { service: "orcel-research", type: "service" },
          src: "^/orcel/research/?$",
        }),
        expect.objectContaining({
          destination: { service: "orcel-support", type: "service" },
          src: "^/orcel/support/?$",
        }),
      ]),
      services: expect.objectContaining({
        "orcel-research": expect.objectContaining({
          buildCommand: expect.stringContaining("ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER=1"),
          routePrefix: "/orcel/research",
        }),
        "orcel-support": expect.objectContaining({
          buildCommand: expect.stringContaining("ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER=1"),
          routePrefix: "/orcel/support",
        }),
      }),
    });
    expect(rewrites).toBeUndefined();
  });

  it("discovers a peer workspace through orcelRoot", async () => {
    const workspaceRoot = await createTempAppRoot();
    const nextRoot = join(workspaceRoot, "apps", "web");
    await Promise.all([
      mkdir(join(workspaceRoot, "agents", "support", "agent"), { recursive: true }),
      mkdir(join(workspaceRoot, "agents", "research", "agent"), { recursive: true }),
      mkdir(nextRoot, { recursive: true }),
      writeFile(
        join(workspaceRoot, "package.json"),
        JSON.stringify({ dependencies: { orcel: "*" } }),
      ),
    ]);
    process.chdir(nextRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    await resolveConfig(withEve<TestConfig>({}, { orcelRoot: "../.." }));
    const outputConfig = await readJsonFile(join(nextRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toMatchObject({
      routes: expect.arrayContaining([
        expect.objectContaining({ src: "^/orcel/research/v1/(.*)$" }),
        expect.objectContaining({ src: "^/orcel/support/v1/(.*)$" }),
      ]),
      services: expect.objectContaining({
        "orcel-research": expect.objectContaining({ routePrefix: "/orcel/research" }),
        "orcel-support": expect.objectContaining({ routePrefix: "/orcel/support" }),
      }),
    });
  });

  it("accepts a custom orcel service build command", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    await mkdir(join(appRoot, ".vercel"), { recursive: true });
    await writeFile(join(appRoot, ".vercel", "project.json"), "{}\n");
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    await resolveConfig(
      withEve<TestConfig>(
        {},
        {
          orcelBuildCommand: "pnpm build:orcel",
        },
      ),
    );
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toMatchObject({
      services: {
        orcel: {
          buildCommand:
            "cd '../../..' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && pnpm build:orcel",
        },
      },
    });
  });

  it("discovers workspace members from an absolute orcelRoot with a trailing slash", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    await mkdir(join(appRoot, "agents", "a", "agent"), { recursive: true });
    await mkdir(join(appRoot, "agents", "b", "agent"), { recursive: true });
    await writeFile(
      join(appRoot, "package.json"),
      `${JSON.stringify({ dependencies: { orcel: "0.0.0" } })}\n`,
    );
    await writeFile(join(appRoot, "agents", "a", "agent", "agent.ts"), "export default {};\n");
    await writeFile(join(appRoot, "agents", "b", "agent", "agent.ts"), "export default {};\n");
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");

    await resolveConfig(withEve<TestConfig>({}, { orcelRoot: `${appRoot}/` }));
    const outputConfig = (await readJsonFile(
      join(appRoot, ".vercel", "output", "config.json"),
    )) as { services?: Record<string, unknown> };

    expect(Object.keys(outputConfig.services ?? {})).toEqual(["orcel-a", "orcel-b"]);
  });

  it("writes one Build Output service and route for each named agent", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    const config = await resolveConfig(
      withEve<TestConfig>(
        {},
        {
          agents: {
            billing: {
              buildCommand: "pnpm build:billing-agent",
              root: "./agents/billing",
              servicePrefix: "/_orcel_internal/billing",
            },
            support: "./agents/support",
          },
        },
      ),
    );
    const rewrites = await config.rewrites?.();
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toEqual({
      routes: [
        {
          destination: {
            service: "orcel-billing",
            type: "service",
          },
          src: "^/orcel/billing/v1/(.*)$",
        },
        {
          destination: {
            service: "orcel-support",
            type: "service",
          },
          src: "^/orcel/support/v1/(.*)$",
        },
      ],
      services: {
        "orcel-billing": {
          buildCommand:
            "cd '../../../agents/billing' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='../../.orcel/vercel-services/orcel-billing/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../../.vercel/output' && export ORCEL_PUBLIC_ROUTE_PREFIX='/orcel/billing' && pnpm build:billing-agent",
          framework: "eve",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/orcel/billing/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".orcel/vercel-services/orcel-billing",
          routePrefix: "/orcel/billing",
        },
        "orcel-support": {
          buildCommand:
            "cd '../../../agents/support' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='../../.orcel/vercel-services/orcel-support/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../../.vercel/output' && export ORCEL_PUBLIC_ROUTE_PREFIX='/orcel/support' && node 'node_modules/orcel/bin/orcel.js' build",
          framework: "eve",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/orcel/support/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".orcel/vercel-services/orcel-support",
          routePrefix: "/orcel/support",
        },
      },
      version: 3,
    });
    expect(rewrites).toBeUndefined();
  });

  it("normalizes existing Build Output service arrays before adding named agents", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    await mkdir(join(appRoot, ".vercel", "output"), { recursive: true });
    await writeFile(join(appRoot, ".vercel", "project.json"), "{}\n");
    await writeFile(join(appRoot, ".vercel", "output", "builds.json"), "{}\n");
    await writeFile(
      join(appRoot, ".vercel", "output", "config.json"),
      `${JSON.stringify(
        {
          version: 3,
          routes: [
            {
              destination: {
                service: "orcel-billing",
                type: "service",
              },
              src: "^/orcel/billing/v1/(.*)$",
            },
            { handle: "filesystem" },
          ],
          services: [
            {
              buildCommand: "orcel build:support",
              entrypoint: "package.json",
              framework: "eve",
              name: "orcel-support",
              root: "agents/support",
              routePrefix: "/orcel/support",
              schema: "experimentalServicesV2",
            },
          ],
        },
        null,
        2,
      )}\n`,
    );
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    const config = await resolveConfig(
      withEve<TestConfig>(
        {},
        {
          agents: {
            billing: "./agents/billing",
            support: "./agents/support",
          },
        },
      ),
    );
    const rewrites = await config.rewrites?.();
    const outputConfig = await readJsonFile(join(appRoot, ".vercel", "output", "config.json"));

    expect(outputConfig).toEqual({
      routes: [
        {
          destination: {
            service: "orcel-billing",
            type: "service",
          },
          src: "^/orcel/billing/v1/(.*)$",
        },
        {
          destination: {
            service: "orcel-support",
            type: "service",
          },
          src: "^/orcel/support/v1/(.*)$",
        },
        { handle: "filesystem" },
      ],
      services: {
        "orcel-billing": {
          buildCommand:
            "cd '../../../agents/billing' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='../../.orcel/vercel-services/orcel-billing/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../../.vercel/output' && export ORCEL_PUBLIC_ROUTE_PREFIX='/orcel/billing' && node 'node_modules/orcel/bin/orcel.js' build",
          framework: "eve",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/orcel/billing/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".orcel/vercel-services/orcel-billing",
          routePrefix: "/orcel/billing",
        },
        "orcel-support": {
          buildCommand: "orcel build:support",
          entrypoint: "package.json",
          framework: "eve",
          routes: [
            {
              src: "^/orcel/support/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: "agents/support",
          routePrefix: "/orcel/support",
          schema: "experimentalServicesV2",
        },
      },
      version: 3,
    });
    expect(rewrites).toBeUndefined();
  });

  it("does not start a local orcel build while Next.js is building", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    vi.stubEnv("NODE_ENV", "production");
    await mkdir(join(appRoot, ".output", "server"), {
      recursive: true,
    });
    await writeFile(join(appRoot, ".output", "server", "index.mjs"), "process.exit(1);\n");

    const config = await withEve<TestConfig>({})("phase-production-build", {
      defaultConfig: {},
    });
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: "http://127.0.0.1:4274/orcel/v1/:path+",
      source: "/orcel/v1/:path+",
    });
  });

  it("reuses an app-local development server registry before spawning", async () => {
    const appRoot = await createTempAppRoot();
    process.chdir(appRoot);
    const resolvedAppRoot = process.cwd();
    vi.stubEnv("NODE_ENV", "development");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ revision: "rev-1" })),
    );
    await mkdir(join(resolvedAppRoot, ".orcel"), {
      recursive: true,
    });
    await writeFile(
      join(resolvedAppRoot, ".orcel", "next-dev-server.json"),
      `${JSON.stringify(
        {
          appRoot: resolvedAppRoot,
          origin: "http://127.0.0.1:49152",
          pid: null,
          updatedAt: new Date().toISOString(),
        },
        null,
        2,
      )}\n`,
    );

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(fetch).toHaveBeenCalledWith(
      new URL("/orcel/v1/dev/runtime-artifacts", "http://127.0.0.1:49152"),
      { redirect: "error", signal: expect.any(AbortSignal) },
    );
    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: "http://127.0.0.1:49152/orcel/v1/:path+",
      source: "/orcel/v1/:path+",
    });
  });
});

function getBeforeFiles(
  rewrites: Awaited<ReturnType<NonNullable<TestConfig["rewrites"]>>> | undefined,
): readonly NonNullable<OrcelNextRewriteSections["beforeFiles"]>[number][] {
  expect(isRewriteSections(rewrites)).toBe(true);
  if (!isRewriteSections(rewrites)) {
    return [];
  }

  return rewrites.beforeFiles ?? [];
}

function isRewriteSections(
  rewrites: Awaited<ReturnType<NonNullable<TestConfig["rewrites"]>>> | undefined,
): rewrites is OrcelNextRewriteSections {
  return rewrites !== undefined && !Array.isArray(rewrites);
}
