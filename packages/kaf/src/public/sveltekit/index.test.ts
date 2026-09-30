import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConfigEnv, Plugin, UserConfig } from "vite";

import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";
import { ensureKafVercelServicesConfig } from "#shared/vercel-services.js";

import { kafSvelteKit } from "./index.js";
import { resolveSharedKafDevServer } from "./dev-server.js";

vi.mock("./dev-server.js", () => ({
  KAF_BASE_URL_ENV: "KAF_BASE_URL",
  resolveSharedKafDevServer: vi.fn(async () => ({ origin: "http://127.0.0.1:49152" })),
}));

vi.mock("#shared/vercel-services.js", () => ({
  ensureKafVercelServicesConfig: vi.fn(async () => ({ mode: "root" })),
  mergeKafVercelConfig: vi.fn(),
}));

const resolveSharedKafDevServerMock = vi.mocked(resolveSharedKafDevServer);
const ensureKafVercelServicesConfigMock = vi.mocked(ensureKafVercelServicesConfig);

type ConfigHook = (config: UserConfig, env: ConfigEnv) => unknown;

function getConfigHook(plugin: Plugin): ConfigHook {
  if (typeof plugin.config !== "function") {
    throw new Error("expected plugin config hook");
  }
  return plugin.config as ConfigHook;
}

afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
});

describe("kafSvelteKit", () => {
  it("configures Vite dev server proxy to a shared kaf server", async () => {
    const plugin = kafSvelteKit();
    const result = (await getConfigHook(plugin)(
      {
        server: {
          proxy: {
            "/api": "http://127.0.0.1:3000",
          },
        },
      },
      { command: "serve", mode: "development" },
    )) as UserConfig;

    expect(resolveSharedKafDevServerMock).toHaveBeenCalledWith(process.cwd());
    expect(result).toEqual({
      server: {
        proxy: {
          "/api": "http://127.0.0.1:3000",
          [KAF_ROUTE_PREFIX]: {
            changeOrigin: true,
            target: "http://127.0.0.1:49152",
          },
        },
      },
    });
  });

  it("configures Vite preview proxy and starts kaf for local production preview", async () => {
    const plugin = kafSvelteKit();
    const result = (await getConfigHook(plugin)(
      {
        preview: {
          proxy: {
            "/api": "http://127.0.0.1:3000",
          },
        },
      },
      { command: "serve", isPreview: true, mode: "production" },
    )) as UserConfig;

    expect(resolveSharedKafDevServerMock).toHaveBeenCalledWith(process.cwd());
    expect(result).toEqual({
      preview: {
        proxy: {
          "/api": "http://127.0.0.1:3000",
          [KAF_ROUTE_PREFIX]: {
            changeOrigin: true,
            target: "http://127.0.0.1:49152",
          },
        },
      },
    });
  });

  it("prefers KAF_BASE_URL over spawning a shared server", async () => {
    vi.stubEnv("KAF_BASE_URL", "https://agent.example.com/root");
    const plugin = kafSvelteKit();
    const result = (await getConfigHook(plugin)(
      {},
      { command: "serve", mode: "development" },
    )) as UserConfig;

    expect(resolveSharedKafDevServerMock).not.toHaveBeenCalled();
    expect(result.server?.proxy).toEqual({
      [KAF_ROUTE_PREFIX]: {
        changeOrigin: true,
        target: "https://agent.example.com",
      },
    });
  });

  it("configures a generated Vercel service during Vercel production builds", async () => {
    vi.stubEnv("VERCEL", "1");
    const plugin = kafSvelteKit({ kafBuildCommand: "pnpm build:kaf", kafRoot: "agent" });

    await getConfigHook(plugin)({}, { command: "build", mode: "production" });

    expect(ensureKafVercelServicesConfigMock).toHaveBeenCalledWith({
      appRoot: expect.stringMatching(/agent$/),
      kafBuildCommand: "pnpm build:kaf",
      frameworkName: "SvelteKit",
      hostRoot: process.cwd(),
    });
  });
});
