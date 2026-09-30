import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

import type { Plugin, ResolvedConfig, UserConfig } from "vite";

import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";
import {
  ensureKafVercelServicesConfig,
  mergeKafVercelConfig,
  type EnsureKafVercelServicesConfigResult,
  type VercelBuildConfig,
} from "#shared/vercel-services.js";

import { KAF_BASE_URL_ENV, resolveSharedKafDevServer } from "./dev-server.js";
import { normalizeOrigin } from "./routing.js";

/**
 * Options for the kaf SvelteKit Vite plugin.
 */
export interface KafSvelteKitPluginOptions {
  /**
   * Path to the kaf application root, relative to the SvelteKit project root
   * unless absolute. Defaults to the SvelteKit project root.
   */
  readonly kafRoot?: string;
  /**
   * Command that builds the kaf app inside the generated Vercel kaf service.
   * Defaults to running the installed kaf binary from the SvelteKit app's
   * dependencies (`node <path-to>/kaf/bin/kaf.js build`).
   */
  readonly kafBuildCommand?: string;
}

function resolveApplicationRoot(svelteKitRoot: string, appPath: string | undefined): string {
  if (appPath === undefined || appPath.length === 0) {
    return svelteKitRoot;
  }
  return isAbsolute(appPath) ? appPath : resolve(svelteKitRoot, appPath);
}

function mergeProxyConfig(
  existingProxy: NonNullable<UserConfig["server"]>["proxy"],
  kafTarget: string,
): NonNullable<UserConfig["server"]>["proxy"] {
  return {
    ...existingProxy,
    [KAF_ROUTE_PREFIX]: {
      changeOrigin: true,
      target: kafTarget,
    },
  };
}

async function resolveKafDevProxyTarget(appRoot: string): Promise<string> {
  const configuredKafBaseUrl = process.env[KAF_BASE_URL_ENV]?.trim();
  if (configuredKafBaseUrl && configuredKafBaseUrl.length > 0) {
    return normalizeOrigin(configuredKafBaseUrl);
  }

  return (await resolveSharedKafDevServer(appRoot)).origin;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function mergeGeneratedVercelServicesConfig(input: {
  readonly generated: Extract<EnsureKafVercelServicesConfigResult, { mode: "generated" }>;
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

  const merged = mergeKafVercelConfig(outputConfig as VercelBuildConfig, input.generated);
  await writeFile(input.outputConfigPath, `${JSON.stringify(merged, null, 2)}\n`);
}

/**
 * Vite plugin for running an kaf agent alongside a SvelteKit app.
 *
 * In development and local preview, `kafSvelteKit` proxies kaf protocol
 * endpoints to a local kaf server. It resolves the server in order: the
 * `KAF_BASE_URL` env var if set, then a healthy shared kaf dev server already
 * running for the app, then a freshly spawned `kaf dev --no-ui --port 0`.
 *
 * On Vercel builds, `kafSvelteKit` adds the kaf runtime as a sibling Vercel
 * service and routes its transport requests before SvelteKit filesystem
 * routing.
 */
export function kafSvelteKit(options: KafSvelteKitPluginOptions = {}): Plugin {
  let svelteKitRoot = process.cwd();
  let appRoot = resolveApplicationRoot(svelteKitRoot, options.kafRoot);
  let isSsrBuild = false;
  let generatedVercelServices:
    | Extract<EnsureKafVercelServicesConfigResult, { mode: "generated" }>
    | undefined;

  return {
    enforce: "post",
    name: "kaf:sveltekit",
    async config(config, env) {
      svelteKitRoot =
        config.root === undefined ? process.cwd() : resolve(process.cwd(), config.root);
      appRoot = resolveApplicationRoot(svelteKitRoot, options.kafRoot);

      if (env.command === "build" && process.env.VERCEL) {
        const configured = await ensureKafVercelServicesConfig({
          appRoot,
          kafBuildCommand: options.kafBuildCommand,
          frameworkName: "SvelteKit",
          hostRoot: svelteKitRoot,
        });

        generatedVercelServices = configured.mode === "generated" ? configured : undefined;
      }

      if (env.command !== "serve") {
        return {};
      }

      const proxyTarget = await resolveKafDevProxyTarget(appRoot);

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
