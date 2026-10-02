import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConfigEnv, Plugin, UserConfig } from "vite";

import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";
import { ensureOrcelVercelServicesConfig } from "#shared/vercel-services.js";

import { orcelSvelteKit } from "./index.js";
import { resolveSharedOrcelDevServer } from "./dev-server.js";

vi.mock("./dev-server.js", () => ({
  ORCEL_BASE_URL_ENV: "ORCEL_BASE_URL",
  resolveSharedOrcelDevServer: vi.fn(async () => ({ origin: "http://127.0.0.1:49152" })),
}));

vi.mock("#shared/vercel-services.js", () => ({
  ensureOrcelVercelServicesConfig: vi.fn(async () => ({ mode: "root" })),
  mergeOrcelVercelConfig: vi.fn(),
}));

const resolveSharedOrcelDevServerMock = vi.mocked(resolveSharedOrcelDevServer);
const ensureOrcelVercelServicesConfigMock = vi.mocked(ensureOrcelVercelServicesConfig);

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

describe("orcelSvelteKit", () => {
  it("configures Vite dev server proxy to a shared orcel server", async () => {
    const plugin = orcelSvelteKit();
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

    expect(resolveSharedOrcelDevServerMock).toHaveBeenCalledWith(process.cwd());
    expect(result).toEqual({
      server: {
        proxy: {
          "/api": "http://127.0.0.1:3000",
          [ORCEL_ROUTE_PREFIX]: {
            changeOrigin: true,
            target: "http://127.0.0.1:49152",
          },
        },
      },
    });
  });

  it("configures Vite preview proxy and starts orcel for local production preview", async () => {
    const plugin = orcelSvelteKit();
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

    expect(resolveSharedOrcelDevServerMock).toHaveBeenCalledWith(process.cwd());
    expect(result).toEqual({
      preview: {
        proxy: {
          "/api": "http://127.0.0.1:3000",
          [ORCEL_ROUTE_PREFIX]: {
            changeOrigin: true,
            target: "http://127.0.0.1:49152",
          },
        },
      },
    });
  });

  it("prefers ORCEL_BASE_URL over spawning a shared server", async () => {
    vi.stubEnv("ORCEL_BASE_URL", "https://agent.example.com/root");
    const plugin = orcelSvelteKit();
    const result = (await getConfigHook(plugin)(
      {},
      { command: "serve", mode: "development" },
    )) as UserConfig;

    expect(resolveSharedOrcelDevServerMock).not.toHaveBeenCalled();
    expect(result.server?.proxy).toEqual({
      [ORCEL_ROUTE_PREFIX]: {
        changeOrigin: true,
        target: "https://agent.example.com",
      },
    });
  });

  it("configures a generated Vercel service during Vercel production builds", async () => {
    vi.stubEnv("VERCEL", "1");
    const plugin = orcelSvelteKit({ orcelBuildCommand: "pnpm build:orcel", orcelRoot: "agent" });

    await getConfigHook(plugin)({}, { command: "build", mode: "production" });

    expect(ensureOrcelVercelServicesConfigMock).toHaveBeenCalledWith({
      appRoot: expect.stringMatching(/agent$/),
      orcelBuildCommand: "pnpm build:orcel",
      frameworkName: "SvelteKit",
      hostRoot: process.cwd(),
    });
  });
});
