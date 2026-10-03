import type { ChildProcess } from "node:child_process";
import { isAbsolute, resolve } from "node:path";

import { addImports, defineNuxtModule, extendRouteRules } from "@nuxt/kit";
import type { NuxtModule } from "@nuxt/schema";

import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";
import {
  ensureOrcelVercelServicesConfig,
  mergeOrcelVercelConfig,
  type VercelBuildConfig,
} from "#shared/vercel-services.js";

import { ORCEL_BASE_URL_ENV, resolveSharedOrcelDevServer } from "./dev-server.js";
import { joinRoutePrefix, normalizeOrigin, resolveProductionTarget } from "./routing.js";

/**
 * Options for the orcel Nuxt module.
 */
export interface OrcelNuxtModuleOptions {
  /**
   * Path to the orcel application root, resolved relative to the Nuxt project
   * root unless absolute. Defaults to the Nuxt project root. The dev server is
   * spawned here, and on Vercel it is the root the generated orcel service
   * builds from.
   */
  orcelRoot?: string;
  /**
   * Command that builds the orcel app inside the generated Vercel orcel service.
   * Defaults to running the installed orcel binary from the Nuxt app's
   * dependencies (`node <path-to>/orcel/bin/orcel.js build`).
   */
  orcelBuildCommand?: string;
}

function resolveApplicationRoot(nuxtRoot: string, appPath: string | undefined): string {
  if (appPath === undefined || appPath.length === 0) {
    return nuxtRoot;
  }
  return isAbsolute(appPath) ? appPath : resolve(nuxtRoot, appPath);
}

/**
 * Minimal view of the Nitro Vercel build-output config the module merges the
 * orcel service into. The full `nitro` typing lives behind the nitropack/Nuxt
 * augmentation, which is not loaded in this package's build, so model only the
 * surface we touch.
 */
interface NitroVercelConfigHost {
  vercel?: {
    config?: VercelBuildConfig;
    [key: string]: unknown;
  };
}

/**
 * Resolve the destination orcel routes proxy to. In dev this is an explicit
 * `ORCEL_BASE_URL` or a shared dev server spawned on demand; in non-Vercel
 * production it is a configured origin/port.
 *
 * When a dev server is spawned by this process, `onDevServerSpawned` is invoked
 * with the child handle so the caller can wire lifecycle-scoped cleanup.
 */
async function resolveOrcelProxyTarget(input: {
  readonly appRoot: string;
  readonly dev: boolean;
  readonly onDevServerSpawned?: (child: ChildProcess) => void;
}): Promise<string> {
  if (!input.dev) {
    return resolveProductionTarget();
  }

  const configuredOrcelBaseUrl = process.env[ORCEL_BASE_URL_ENV]?.trim();
  if (configuredOrcelBaseUrl && configuredOrcelBaseUrl.length > 0) {
    return joinRoutePrefix(normalizeOrigin(configuredOrcelBaseUrl), ORCEL_ROUTE_PREFIX);
  }

  const handle = await resolveSharedOrcelDevServer(input.appRoot);
  if (handle.process !== undefined) {
    input.onDevServerSpawned?.(handle.process);
  }

  return joinRoutePrefix(handle.origin, ORCEL_ROUTE_PREFIX);
}

/**
 * Nuxt module that wires an orcel agent into a Nuxt app. Register under `modules`
 * (configured via the `orcel` config key). It auto-imports the `useOrcelAgent()`
 * composable and routes orcel transport requests (`/orcel/v1/**`) to the orcel
 * service: a shared dev server spawned on demand in dev, a generated Vercel
 * service on Vercel deployments, and a configured origin/port in non-Vercel
 * production. Requires Nuxt >= 4.0.0. Configure via
 * {@link OrcelNuxtModuleOptions}.
 */
const orcelNuxtModule: NuxtModule<OrcelNuxtModuleOptions> = defineNuxtModule<OrcelNuxtModuleOptions>({
  meta: {
    name: "orcel",
    configKey: "orcel",
    compatibility: {
      nuxt: ">=4.0.0",
    },
  },
  defaults: {},
  async setup(options, nuxt) {
    const nuxtRoot = nuxt.options.rootDir;
    const appRoot = resolveApplicationRoot(nuxtRoot, options.orcelRoot);

    // Auto-import the Vue composable so app code can call `useOrcelAgent()`
    // without an explicit import, matching Nuxt's composable conventions.
    addImports({ name: "useOrcelAgent", from: "orcel/vue" });

    // On Vercel the orcel app deploys as a sibling service. A Nitro runtime
    // `proxy` rule can't reach it — the proxied request loops back into the
    // Nuxt function and 404s — so declare the service and route orcel transport
    // to it at the edge through the build output config, mirroring the Next.js
    // integration.
    if (!nuxt.options.dev && process.env.VERCEL) {
      const configured = await ensureOrcelVercelServicesConfig({
        appRoot,
        orcelBuildCommand: options.orcelBuildCommand,
        frameworkName: "Nuxt",
        hostRoot: nuxtRoot,
      });

      if (configured.mode === "generated") {
        const nitro = (nuxt.options as typeof nuxt.options & { nitro: NitroVercelConfigHost })
          .nitro;
        nitro.vercel = {
          ...nitro.vercel,
          config: mergeOrcelVercelConfig(nitro.vercel?.config, configured),
        };
      }
    } else {
      // Dev (and non-Vercel production, which proxies to an absolute origin):
      // booting the shared orcel dev server can take a while, so defer it out of
      // module setup. `modules:done` still runs before Nitro is configured, so
      // the proxy route rule is registered in time while other modules' setup
      // isn't blocked behind the spawn.
      nuxt.hook("modules:done", async () => {
        const proxyTarget = await resolveOrcelProxyTarget({
          appRoot,
          dev: nuxt.options.dev,
          onDevServerSpawned: (child) => {
            // Prefer Nuxt's lifecycle for cleanup so the dev server is torn
            // down on graceful shutdown and dev restarts. The process-exit
            // guard in dev-server.ts remains as a fallback for non-graceful
            // exits.
            nuxt.hook("close", () => {
              if (!child.killed) {
                child.kill();
              }
            });
          },
        });

        extendRouteRules(`${ORCEL_ROUTE_PREFIX}/**`, {
          proxy: `${proxyTarget}/**`,
        });
      });
    }
  },
});

export default orcelNuxtModule;
