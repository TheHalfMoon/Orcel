import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import type { Plugin, ResolvedConfig, UserConfig } from "vite";

import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";
import {
  ensureOrcelVercelServicesConfig,
  mergeOrcelVercelConfig,
  type EnsureOrcelVercelServicesConfigResult,
  type VercelBuildConfig,
} from "#shared/vercel-services.js";

import { ORCEL_BASE_URL_ENV, resolveSharedOrcelDevServer } from "./dev-server.js";
import { normalizeOrigin } from "./routing.js";

/**
 * Options for the orcel SvelteKit Vite plugin.
 */
export interface OrcelSvelteKitPluginOptions {
  /**
   * Path to the orcel application root, relative to the SvelteKit project root
   * unless absolute. Defaults to the SvelteKit project root.
   */
  readonly orcelRoot?: string;
  /**
   * Command that builds the orcel app inside the generated Vercel orcel service.
   * Defaults to running the installed orcel binary from the SvelteKit app's
   * dependencies (`node <path-to>/orcel/bin/orcel.js build`).
   */
  readonly orcelBuildCommand?: string;
}

function resolveApplicationRoot(svelteKitRoot: string, appPath: string | undefined): string {
  if (appPath === undefined || appPath.length === 0) {
    return svelteKitRoot;
  }
  return isAbsolute(appPath) ? appPath : resolve(svelteKitRoot, appPath);
}

function mergeProxyConfig(
  existingProxy: NonNullable<UserConfig["server"]>["proxy"],
  orcelTarget: string,
): NonNullable<UserConfig["server"]>["proxy"] {
  return {
    ...existingProxy,
    [ORCEL_ROUTE_PREFIX]: {
      changeOrigin: true,
      target: orcelTarget,
    },
  };
}

async function resolveOrcelDevProxyTarget(appRoot: string): Promise<string> {
  const configuredOrcelBaseUrl = process.env[ORCEL_BASE_URL_ENV]?.trim();
  if (configuredOrcelBaseUrl && configuredOrcelBaseUrl.length > 0) {
    return normalizeOrigin(configuredOrcelBaseUrl);
  }

  return (await resolveSharedOrcelDevServer(appRoot)).origin;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function mergeGeneratedVercelServicesConfig(input: {
  readonly generated: Extract<EnsureOrcelVercelServicesConfigResult, { mode: "generated" }>;
  readonly outputConfigPath: string;
}): Promise<void> {
  let outputConfigContents: string;

  try {
    outputConfigContents = await readFile(input.outputConfigPath, "utf8");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }

    throw error;
  }

  const outputConfig: unknown = JSON.parse(outputConfigContents);

  if (!isRecord(outputConfig)) {
    throw new Error("Vercel Build Output config.json must contain a JSON object.");
  }

  const merged = mergeOrcelVercelConfig(outputConfig as VercelBuildConfig, input.generated);
  await writeFile(input.outputConfigPath, `${JSON.stringify(merged, null, 2)}\n`);
}

/**
 * Vite plugin for running an orcel agent alongside a SvelteKit app.
 *
 * In development and local preview, `orcelSvelteKit` proxies orcel protocol
 * endpoints to a local orcel server. It resolves the server in order: the
 * `ORCEL_BASE_URL` env var if set, then a healthy shared orcel dev server already
 * running for the app, then a freshly spawned `orcel dev --no-ui --port 0`.
 *
 * On Vercel builds, `orcelSvelteKit` adds the orcel runtime as a sibling Vercel
 * service and routes its transport requests before SvelteKit filesystem
 * routing.
 */
export function orcelSvelteKit(options: OrcelSvelteKitPluginOptions = {}): Plugin {
  let svelteKitRoot = process.cwd();
  let appRoot = resolveApplicationRoot(svelteKitRoot, options.orcelRoot);
  let isSsrBuild = false;
  let generatedVercelServices:
    | Extract<EnsureOrcelVercelServicesConfigResult, { mode: "generated" }>
    | undefined;

  return {
    enforce: "post",
    name: "orcel:sveltekit",
    async config(config, env) {
      svelteKitRoot =
        config.root === undefined ? process.cwd() : resolve(process.cwd(), config.root);
      appRoot = resolveApplicationRoot(svelteKitRoot, options.orcelRoot);

      if (env.command === "build" && process.env.VERCEL) {
        const configured = await ensureOrcelVercelServicesConfig({
          appRoot,
          orcelBuildCommand: options.orcelBuildCommand,
          frameworkName: "SvelteKit",
          hostRoot: svelteKitRoot,
        });

        generatedVercelServices = configured.mode === "generated" ? configured : undefined;
      }

      if (env.command !== "serve") {
        return {};
      }

      const proxyTarget = await resolveOrcelDevProxyTarget(appRoot);

      if (env.isPreview) {
        return {
          preview: {
            proxy: mergeProxyConfig(config.preview?.proxy, proxyTarget),
          },
        };
      }

      return {
        server: {
          proxy: mergeProxyConfig(config.server?.proxy, proxyTarget),
        },
      };
    },
    configResolved(config: ResolvedConfig) {
      isSsrBuild = Boolean(config.build.ssr);
      svelteKitRoot = config.root;
    },
    closeBundle: {
      sequential: true,
      async handler() {
        if (!isSsrBuild || generatedVercelServices === undefined) {
          return;
        }

        await mergeGeneratedVercelServicesConfig({
          generated: generatedVercelServices,
          outputConfigPath: join(svelteKitRoot, ".vercel", "output", "config.json"),
        });
      },
    },
  };
}
