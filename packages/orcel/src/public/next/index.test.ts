import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-orcel-binary.js", async () => {
  const { join } = await import("node:path");
  return {
    // Pin resolution to the conventional app-local path so the default
    // build-command assertion is deterministic without touching the
    // filesystem. The real resolver is covered by its own integration test.
    resolveOrcelBinaryPath: (nextRoot: string) =>
      join(nextRoot, "node_modules", "@orcel", "orcel", "bin", "orcel.js"),
  };
});

vi.mock("./vercel-output-config.js", () => ({
  ensureOrcelVercelOutputConfig: vi.fn(
    async (input: {
      readonly agents: readonly {
        readonly name?: string;
        readonly servicePrefix: string;
      }[];
    }) => ({
      agents: input.agents.map((agent) => ({
        name: agent.name,
        servicePrefix: agent.servicePrefix,
      })),
    }),
  ),
}));

const { ensureOrcelVercelOutputConfig } = await import("./vercel-output-config.js");

vi.mock("./server.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./server.js")>();
  return {
    ...original,
    resolveOrcelDestinationPrefix: vi.fn(original.resolveOrcelDestinationPrefix),
  };
});

const { resolveOrcelDestinationPrefix } = await import("./server.js");

vi.mock("#internal/nitro/host/workspace-extensions.js", () => ({
  buildWorkspaceExtensions: vi.fn(async () => undefined),
}));

const { buildWorkspaceExtensions } = await import("#internal/nitro/host/workspace-extensions.js");

import {
  ORCEL_NEXT_SERVICE_PREFIX,
  withEve,
  type OrcelNextConfig,
  type OrcelNextRewriteSections,
} from "./index.js";

interface TestConfig extends OrcelNextConfig {
  readonly basePath?: string;
}

async function resolveConfig(config: ReturnType<typeof withEve<TestConfig>>): Promise<TestConfig> {
  return await config("phase-test", {
    defaultConfig: {},
  });
}

describe("withEve", () => {
  afterEach(() => {
    vi.mocked(resolveOrcelDestinationPrefix).mockClear();
    vi.mocked(ensureOrcelVercelOutputConfig).mockClear();
    vi.mocked(buildWorkspaceExtensions).mockClear();
    vi.unstubAllEnvs();
  });

  it("builds each agent's workspace extensions while Next.js is building", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");

    await withEve<TestConfig>(
      {},
      { agents: { billing: "./agents/billing", support: "./agents/support" } },
    )("phase-production-build", { defaultConfig: {} });

    expect(vi.mocked(buildWorkspaceExtensions).mock.calls).toEqual([
      [expect.stringMatching(/\/agents\/billing$/)],
      [expect.stringMatching(/\/agents\/support$/)],
    ]);
  });

  it("does not build workspace extensions outside the Next.js build phase", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");

    await resolveConfig(withEve<TestConfig>({}));

    expect(buildWorkspaceExtensions).not.toHaveBeenCalled();
  });

  it("does not add Next.js rewrites on Vercel", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "preview.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(rewrites).toBeUndefined();
  });

  it("omits the basePath override so Next.js applies a configured basePath", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(
      withEve<TestConfig>({
        basePath: "/web",
      }),
    );
    const rewrites = await config.rewrites?.();
    const [orcelRewrite] = getBeforeFiles(rewrites);

    expect(orcelRewrite).toEqual({
      destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/orcel/v1/:path+`,
      source: "/orcel/v1/:path+",
    });
    expect(orcelRewrite).not.toHaveProperty("basePath");
  });

  it("adds non-Vercel production rewrites to the configured orcel service namespace", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/orcel/v1/:path+`,
      source: "/orcel/v1/:path+",
    });
  });

  it("only rewrites orcel-prefixed non-index routes", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();
    const beforeFiles = getBeforeFiles(rewrites);

    expect(beforeFiles.map((rewrite) => rewrite.source)).not.toContain("/");
    expect(beforeFiles.map((rewrite) => rewrite.source)).not.toContain("/orcel/v1");
    expect(beforeFiles.every((rewrite) => rewrite.source.startsWith("/orcel/v1/"))).toBe(true);
  });

  it("rewrites authored channel routes under the orcel protocol prefix", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/orcel/v1/:path+`,
      source: "/orcel/v1/:path+",
    });
  });

  it("uses ORCEL_BASE_URL in development instead of starting a server", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("ORCEL_BASE_URL", " http://127.0.0.1:49152/ ");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: "http://127.0.0.1:49152/orcel/v1/:path+",
      source: "/orcel/v1/:path+",
    });
  });

  it("ignores Vercel deployment URL by leaving routing to Build Output config", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("VERCEL_URL", "http://preview.example.com");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(rewrites).toBeUndefined();
  });

  it("ignores production origin overrides on Vercel", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com/root");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(rewrites).toBeUndefined();
  });

  it("preserves object config values and existing array rewrites", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(
      withEve<TestConfig>({
        basePath: "/web",
        async rewrites() {
          return [
            {
              destination: "/legacy",
              source: "/legacy",
            },
          ];
        },
      }),
    );
    const rewrites = await config.rewrites?.();

    expect(config.basePath).toBe("/web");
    expect(isRewriteSections(rewrites)).toBe(true);
    if (!isRewriteSections(rewrites)) {
      return;
    }

    expect(rewrites.beforeFiles).toContainEqual({
      destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/orcel/v1/:path+`,
      source: "/orcel/v1/:path+",
    });
    expect(rewrites.afterFiles).toContainEqual({
      destination: "/legacy",
      source: "/legacy",
    });
  });

  it("prepends orcel rewrites to beforeFiles when user rewrites use sections", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(
      withEve<TestConfig>({
        async rewrites() {
          return {
            afterFiles: [
              {
                destination: "/after",
                source: "/after",
              },
            ],
            beforeFiles: [
              {
                destination: "/before",
                source: "/before",
              },
            ],
          };
        },
      }),
    );
    const rewrites = await config.rewrites?.();

    expect(isRewriteSections(rewrites)).toBe(true);
    if (!isRewriteSections(rewrites)) {
      return;
    }

    expect(rewrites.beforeFiles?.at(0)).toEqual({
      destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/orcel/v1/:path+`,
      source: "/orcel/v1/:path+",
    });
    expect(rewrites.beforeFiles).toContainEqual({
      destination: "/before",
      source: "/before",
    });
    expect(rewrites.afterFiles).toEqual([
      {
        destination: "/after",
        source: "/after",
      },
    ]);
  });

  it("accepts a custom private service prefix", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

    const config = await resolveConfig(
      withEve<TestConfig>(
        {},
        {
          servicePrefix: "internal/orcel",
        },
      ),
    );
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: "https://agent.example.com/internal/orcel/orcel/v1/:path+",
      source: "/orcel/v1/:path+",
    });
  });

  it("accepts a production origin override outside Vercel", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com/root");

    const config = await resolveConfig(withEve<TestConfig>({}));
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/orcel/v1/:path+`,
      source: "/orcel/v1/:path+",
    });
  });

  it("uses a stable local production port while Next.js is building outside Vercel", async () => {
    vi.stubEnv("NODE_ENV", "production");

    const config = await withEve<TestConfig>({})("phase-production-build", {
      defaultConfig: {},
    });
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: "http://127.0.0.1:4274/orcel/v1/:path+",
      source: "/orcel/v1/:path+",
    });
  });

  it("accepts a custom stable local production port", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_PORT", "51234");

    const config = await withEve<TestConfig>({})("phase-production-build", {
      defaultConfig: {},
    });
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toContainEqual({
      destination: "http://127.0.0.1:51234/orcel/v1/:path+",
      source: "/orcel/v1/:path+",
    });
  });

  it("adds named agent rewrites with derived and per-agent service prefixes", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_NEXT_PRODUCTION_ORIGIN", "https://agent.example.com");

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

    expect(getBeforeFiles(rewrites)).toEqual(
      expect.arrayContaining([
        {
          destination: `https://agent.example.com${ORCEL_NEXT_SERVICE_PREFIX}/support/orcel/v1/:path+`,
          source: "/orcel/support/v1/:path+",
        },
        {
          destination: "https://agent.example.com/_orcel_internal/billing/orcel/v1/:path+",
          source: "/orcel/billing/v1/:path+",
        },
      ]),
    );
    expect(ensureOrcelVercelOutputConfig).toHaveBeenCalledWith({
      agents: [
        {
          appRoot: expect.stringContaining("/agents/billing"),
          buildCommand: "pnpm build:billing-agent",
          name: "billing",
          publicRoutePrefix: "/orcel/billing",
          servicePrefix: "/_orcel_internal/billing",
        },
        {
          appRoot: expect.stringContaining("/agents/support"),
          buildCommand: "node 'node_modules/@orcel/orcel/bin/orcel.js' build",
          name: "support",
          publicRoutePrefix: "/orcel/support",
          servicePrefix: `${ORCEL_NEXT_SERVICE_PREFIX}/support`,
        },
      ],
      nextRoot: process.cwd(),
    });
  });

  it("uses adjacent stable local production ports for named agents", async () => {
    vi.stubEnv("NODE_ENV", "production");

    const config = await withEve<TestConfig>(
      {},
      {
        agents: {
          billing: "./agents/billing",
          support: "./agents/support",
        },
      },
    )("phase-production-build", {
      defaultConfig: {},
    });
    const rewrites = await config.rewrites?.();

    expect(getBeforeFiles(rewrites)).toEqual(
      expect.arrayContaining([
        {
          destination: "http://127.0.0.1:4274/orcel/v1/:path+",
          source: "/orcel/billing/v1/:path+",
        },
        {
          destination: "http://127.0.0.1:4275/orcel/v1/:path+",
          source: "/orcel/support/v1/:path+",
        },
      ]),
    );
  });

  it("accepts digit-bearing public agent names", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const config = await withEve<TestConfig>({}, { agents: { support2: "./agents/support" } })(
      "phase-production-build",
      { defaultConfig: {} },
    );

    await expect(config.rewrites?.()).resolves.toEqual(
      expect.objectContaining({
        beforeFiles: expect.arrayContaining([
          expect.objectContaining({ source: "/orcel/support2/v1/:path+" }),
        ]),
      }),
    );
  });

  it("rejects orcelRoot when named agents are configured", () => {
    expect(() =>
      withEve<TestConfig>(
        {},
        {
          agents: { support: "./agents/support" },
          orcelRoot: "./agent",
        },
      ),
    ).toThrow("withEve cannot combine orcelRoot with agents");
  });

  it("rejects invalid named agent route segments", () => {
    expect(() =>
      withEve<TestConfig>(
        {},
        {
          agents: {
            Support: "./agents/support",
          },
        },
      ),
    ).toThrow("orcel Next.js agent name");
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
