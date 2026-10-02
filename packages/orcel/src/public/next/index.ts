import { resolve } from "node:path";

import type { NextConfig } from "next";

import { assertValidPublicAgentName } from "#internal/agent-name.js";
import { findOrcelProjectContext } from "#internal/project-context.js";
import { quoteVercelShellArgument, toVercelRelativePath } from "#internal/vercel/build-command.js";
import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";
import { joinOrcelRoutePath } from "#shared/orcel-route-path.js";
import { resolveOrcelBinaryPath } from "#shared/resolve-orcel-binary.js";
import { NEXT_PHASE_PRODUCTION_BUILD, resolveOrcelDestinationPrefix } from "./server.js";
import { ensureOrcelVercelOutputConfig } from "./vercel-output-config.js";

/**
 * Default private route namespace for legacy manually configured Vercel
 * services. {@link WithOrcelOptions.servicePrefix} defaults to this value.
 */
export const ORCEL_NEXT_SERVICE_PREFIX = "/_orcel_internal/orcel";

const ORCEL_NEXT_PRODUCTION_ORIGIN_ENV = "ORCEL_NEXT_PRODUCTION_ORIGIN";
const ORCEL_NEXT_PRODUCTION_PORT_ENV = "ORCEL_NEXT_PRODUCTION_PORT";
const DEFAULT_ORCEL_NEXT_PRODUCTION_PORT = 4274;
const ORCEL_NAMED_AGENT_ROUTE_PREFIX = "/orcel";

type ArrayElement<T> = T extends readonly (infer TElement)[] ? TElement : never;
type NextRewrites = Awaited<ReturnType<NonNullable<NextConfig["rewrites"]>>>;

/**
 * Next.js rewrite rule that {@link withEve} emits.
 */
export type OrcelNextRewriteRule = ArrayElement<NextRewrites>;

/**
 * Resolved return type of a Next.js `rewrites` function: an array of rules, or
 * the sectioned `{ beforeFiles, afterFiles, fallback }` object.
 */
export type OrcelNextRewrites = NextRewrites;

/**
 * Sectioned Next.js rewrite rules.
 */
export type OrcelNextRewriteSections = Extract<
  NextRewrites,
  {
    readonly afterFiles?: OrcelNextRewriteRule[];
    readonly beforeFiles?: OrcelNextRewriteRule[];
    readonly fallback?: OrcelNextRewriteRule[];
  }
>;

/**
 * Alias of Next.js's `NextConfig`, the config object form {@link withEve}
 * accepts (the other being {@link OrcelNextConfigFunction}).
 */
export type OrcelNextConfig = NextConfig;

/**
 * Structural shape of a Next.js config function: receives the build `phase` and
 * a `context` containing `defaultConfig`, and returns a config (or a promise of
 * one). This is the form {@link withEve} returns.
 */
export type OrcelNextConfigFunction<TConfig extends OrcelNextConfig = OrcelNextConfig> = (
  phase: string,
  context: {
    readonly defaultConfig: TConfig;
  },
) => TConfig | Promise<TConfig>;

/**
 * Next.js config input that {@link withEve} accepts.
 */
export type OrcelNextConfigInput<TConfig extends OrcelNextConfig = OrcelNextConfig> =
  | OrcelNextConfigFunction<TConfig>
  | TConfig;

/**
 * Configuration for one named orcel agent mounted by {@link withEve}.
 */
export interface WithOrcelAgentOptions {
  /**
   * Path to the orcel application root, relative to `process.cwd()` unless
   * absolute.
   */
  readonly root: string;
  /**
   * Build command for this generated orcel Vercel service. Defaults to
   * {@link WithOrcelOptions.orcelBuildCommand}, then a generated command that runs
   * the installed orcel binary from this agent root.
   */
  readonly buildCommand?: string;
  /**
   * Private route namespace for this agent's legacy manually configured Vercel
   * service and non-Vercel production proxying.
   */
  readonly servicePrefix?: string;
}

/**
 * Map of agent names to roots or per-agent configuration.
 */
export type WithOrcelAgentsConfig = Record<string, string | WithOrcelAgentOptions>;

/**
 * Options for {@link withEve}.
 */
export interface WithOrcelOptions {
  /**
   * Maximum time in milliseconds to wait for the orcel development server to
   * start, including waiting for another Next.js process to start it. Defaults
   * to 180000 (three minutes).
   */
  readonly devServerTimeoutMs?: number;
  /**
   * Path to an orcel project root, relative to the Next.js app root unless
   * absolute. The root may contain one `agent/` or an `agents/` workspace.
   * Defaults to the Next.js app root.
   */
  readonly orcelRoot?: string;
  /**
   * Named orcel agents to mount under `/orcel/<name>/v1/*`.
   *
   * Use this when one Next.js app needs to talk to multiple orcel agents outside
   * a project-level `agents/` workspace. When unset, withEve discovers a
   * workspace at the Next.js app root automatically. Do not combine with
   * {@link orcelRoot}; the single-agent form remains the shorthand for one
   * unnamed agent mounted at `/orcel/v1/*`.
   */
  readonly agents?: WithOrcelAgentsConfig;
  /**
   * Build command for the generated orcel Vercel service. In multi-agent mode
   * this is the default for agents without their own `buildCommand`.
   *
   * When omitted, withEve generates a command that runs the installed orcel
   * binary from the agent root.
   */
  readonly orcelBuildCommand?: string;
  /**
   * Private route namespace for legacy manually configured Vercel services and
   * non-Vercel production proxying. Defaults to {@link ORCEL_NEXT_SERVICE_PREFIX}
   * (`/_orcel_internal/orcel`). `withEve` normalizes the prefix (adds a leading
   * slash, strips trailing slashes) and rejects a prefix that resolves to the
   * root route.
   */
  readonly servicePrefix?: string;
}

interface ResolvedOrcelNextAgent {
  readonly appRoot: string;
  readonly buildCommand: string;
  readonly localProductionPortOffset: number;
  readonly name?: string;
  readonly publicRoutePrefix: string;
  readonly servicePrefix: string;
  readonly workspaceMember?: boolean;
}

function resolveApplicationRoot(appPath: string | undefined): string {
  if (appPath === undefined || appPath.length === 0) {
    return process.cwd();
  }

  return resolve(process.cwd(), appPath);
}

function resolveDevServerTimeout(timeoutMs: number | undefined): number | undefined {
  if (timeoutMs === undefined) {
    return undefined;
  }

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("orcel Next.js development server timeout must be a positive number.");
  }

  return timeoutMs;
}

function normalizeRoutePrefix(prefix: string): string {
  const prefixed = prefix.startsWith("/") ? prefix : `/${prefix}`;
  const normalized = prefixed.replace(/\/+$/, "");

  if (normalized.length === 0) {
    throw new Error("orcel Next.js service prefix cannot resolve to the root route.");
  }

  return normalized;
}

function joinRoutePrefix(prefix: string, path: string): string {
  return `${prefix.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

function createNamedAgentRoutePrefix(name: string): string {
  return joinRoutePrefix(ORCEL_NAMED_AGENT_ROUTE_PREFIX, name);
}

function createNamedAgentServicePrefix(basePrefix: string, name: string): string {
  return joinRoutePrefix(basePrefix, name);
}

function createAgentRewriteSource(publicRoutePrefix: string): string {
  return joinOrcelRoutePath(publicRoutePrefix, `${ORCEL_ROUTE_PREFIX}/:path+`);
}

function normalizeOrigin(origin: string): string {
  return new URL(origin.trim()).origin;
}

function readLocalProductionPort(portOffset: number): number {
  const configuredPort = process.env[ORCEL_NEXT_PRODUCTION_PORT_ENV];

  const basePort =
    configuredPort === undefined || configuredPort.trim().length === 0
      ? DEFAULT_ORCEL_NEXT_PRODUCTION_PORT
      : Number.parseInt(configuredPort, 10);

  if (
    configuredPort !== undefined &&
    configuredPort.trim().length > 0 &&
    String(basePort) !== configuredPort.trim()
  ) {
    throw new Error(`${ORCEL_NEXT_PRODUCTION_PORT_ENV} must be an integer between 1 and 65535.`);
  }

  const port = basePort + portOffset;
  if (port < 1 || port > 65_535) {
    throw new Error(`${ORCEL_NEXT_PRODUCTION_PORT_ENV} plus the orcel agent count exceeds 65535.`);
  }

  return port;
}

function resolveProductionDestination(input: {
  readonly localProductionPortOffset: number;
  readonly servicePrefix: string;
}): {
  readonly destinationPrefix: string;
  readonly localServerOrigin?: string;
} {
  if (process.env.VERCEL) {
    return {
      destinationPrefix: input.servicePrefix,
    };
  }

  const configuredOrigin = process.env[ORCEL_NEXT_PRODUCTION_ORIGIN_ENV];

  if (configuredOrigin !== undefined && configuredOrigin.trim().length > 0) {
    return {
      destinationPrefix: joinRoutePrefix(normalizeOrigin(configuredOrigin), input.servicePrefix),
    };
  }

  const localServerOrigin = `http://127.0.0.1:${String(
    readLocalProductionPort(input.localProductionPortOffset),
  )}`;
  return {
    destinationPrefix: localServerOrigin,
    localServerOrigin,
  };
}

function createOrcelRewriteRule(input: {
  readonly destinationPrefix: string;
  readonly publicRoutePrefix: string;
}): OrcelNextRewriteRule {
  const source = createAgentRewriteSource(input.publicRoutePrefix);
  return {
    destination: joinRoutePrefix(input.destinationPrefix, `${ORCEL_ROUTE_PREFIX}/:path+`),
    source,
  };
}

async function resolveExistingRewrites(
  rewrites: OrcelNextConfig["rewrites"],
): Promise<OrcelNextRewrites | undefined> {
  return await rewrites?.();
}

function mergeRewriteRules(
  existing: OrcelNextRewrites | undefined,
  orcelRules: OrcelNextRewriteRule[],
): OrcelNextRewrites {
  if (existing === undefined) {
    return {
      beforeFiles: orcelRules,
    };
  }

  if (!isRewriteSections(existing)) {
    return {
      afterFiles: existing,
      beforeFiles: orcelRules,
    };
  }

  return {
    ...existing,
    beforeFiles: [...orcelRules, ...(existing.beforeFiles ?? [])],
  };
}

function isRewriteSections(rewrites: OrcelNextRewrites): rewrites is OrcelNextRewriteSections {
  return !Array.isArray(rewrites);
}

async function resolveNextConfig<TConfig extends OrcelNextConfig>(
  configOrFunction: OrcelNextConfigInput<TConfig>,
  phase: string,
  context: {
    readonly defaultConfig: TConfig;
  },
): Promise<TConfig> {
  return typeof configOrFunction === "function"
    ? await configOrFunction(phase, context)
    : configOrFunction;
}

function assertValidAgentName(name: string): void {
  assertValidPublicAgentName(name, "orcel Next.js agent name");
}

function assertValidWithOrcelOptions(options: WithOrcelOptions): void {
  if (options.orcelRoot !== undefined && options.agents !== undefined) {
    throw new Error("withEve cannot combine orcelRoot with agents. Use one configuration form.");
  }
  if (options.agents === undefined) return;
  const agentNames = Object.keys(options.agents);
  if (agentNames.length === 0) {
    throw new Error("withEve agents must contain at least one named orcel agent.");
  }
  for (const name of agentNames) assertValidAgentName(name);
}

function createDefaultBuildCommand(input: { readonly agentRoot: string }): string {
  const orcelBinaryPath = toVercelRelativePath(
    input.agentRoot,
    resolveOrcelBinaryPath(input.agentRoot),
  );
  return `node ${quoteVercelShellArgument(orcelBinaryPath)} build`;
}

async function normalizeAgentsConfig(
  options: WithOrcelOptions,
): Promise<readonly ResolvedOrcelNextAgent[]> {
  const servicePrefixBase = normalizeRoutePrefix(options.servicePrefix ?? ORCEL_NEXT_SERVICE_PREFIX);
  const resolveBuildCommand = (agentRoot: string, buildCommand: string | undefined) =>
    buildCommand ?? options.orcelBuildCommand ?? createDefaultBuildCommand({ agentRoot });

  if (options.agents === undefined) {
    const orcelRoot = resolveApplicationRoot(options.orcelRoot);
    const context = await findOrcelProjectContext(orcelRoot);
    if (
      context?.kind === "workspace" &&
      context.workspace.root === orcelRoot &&
      context.workspace.members.length > 0
    ) {
      return context.workspace.members.map((member, index) => ({
        appRoot: member.appRoot,
        buildCommand: resolveBuildCommand(member.appRoot, undefined),
        localProductionPortOffset: index,
        name: member.name,
        publicRoutePrefix: createNamedAgentRoutePrefix(member.name),
        servicePrefix: createNamedAgentServicePrefix(servicePrefixBase, member.name),
        workspaceMember: true,
      }));
    }

    const appRoot = orcelRoot;
    return [
      {
        appRoot,
        buildCommand: resolveBuildCommand(appRoot, undefined),
        localProductionPortOffset: 0,
        publicRoutePrefix: "",
        servicePrefix: servicePrefixBase,
      },
    ];
  }

  const entries = Object.entries(options.agents);
  if (entries.length === 0) {
    throw new Error("withEve agents must contain at least one named orcel agent.");
  }

  return entries.map(([name, config], index) => {
    assertValidAgentName(name);

    const agentConfig = typeof config === "string" ? { root: config } : config;
    const appRoot = resolveApplicationRoot(agentConfig.root);

    return {
      appRoot,
      buildCommand: resolveBuildCommand(appRoot, agentConfig.buildCommand),
      localProductionPortOffset: index,
      name,
      publicRoutePrefix: createNamedAgentRoutePrefix(name),
      servicePrefix: normalizeRoutePrefix(
        agentConfig.servicePrefix ?? createNamedAgentServicePrefix(servicePrefixBase, name),
      ),
    };
  });
}

async function buildAgentWorkspaceExtensions(
  agents: readonly ResolvedOrcelNextAgent[],
): Promise<void> {
  // Loaded lazily so development config loads skip the extension builder.
  const [{ buildWorkspaceExtensions }, { DiscoveryProjectResolutionError }] = await Promise.all([
    import("#internal/nitro/host/workspace-extensions.js"),
    import("#discover/project.js"),
  ]);
  // Agents can mount the same extension, so build them one at a time.
  for (const agent of agents) {
    try {
      await buildWorkspaceExtensions(agent.appRoot);
    } catch (error) {
      // The Next.js app can proxy to an agent built and deployed elsewhere.
      if (error instanceof DiscoveryProjectResolutionError) continue;
      throw error;
    }
  }
}

/**
 * Wraps a Next.js config so same-origin orcel endpoints proxy to a separate orcel
 * service.
 *
 * In development, starts `orcel dev --no-ui --port 0` for the orcel app and
 * rewrites orcel protocol endpoints to that local URL. During `next build`,
 * builds each agent's mounted source-backed workspace extensions so the
 * Next.js type check can resolve them. In Vercel production,
 * writes Build Output service routes so Vercel sends orcel protocol endpoints to
 * the orcel service directly.
 * Outside Vercel production, serves an existing `.output/server/index.mjs` build
 * on a stable local port when present; otherwise set `ORCEL_NEXT_PRODUCTION_ORIGIN`
 * to the origin serving the orcel service namespace.
 */
export function withEve<TConfig extends OrcelNextConfig>(
  configOrFunction: OrcelNextConfigInput<TConfig>,
  options: WithOrcelOptions = {},
): OrcelNextConfigFunction<TConfig> {
  const nextRoot = process.cwd();
  const devServerTimeoutMs = resolveDevServerTimeout(options.devServerTimeoutMs);
  assertValidWithOrcelOptions(options);
  return async function orcelNextConfig(phase, context) {
    const [agents, nextConfig] = await Promise.all([
      normalizeAgentsConfig(options),
      resolveNextConfig(configOrFunction, phase, context),
    ]);
    if (phase === NEXT_PHASE_PRODUCTION_BUILD) {
      await buildAgentWorkspaceExtensions(agents);
    }
    const existingRewrites = nextConfig.rewrites;
    const configuredVercel = await ensureOrcelVercelOutputConfig({
      agents: agents.map((agent) => {
        const outputAgent: {
          appRoot: string;
          buildCommand: string;
          name?: string;
          publicRoutePrefix: string;
          servicePrefix: string;
          workspaceMember?: boolean;
        } = {
          appRoot: agent.appRoot,
          buildCommand: agent.buildCommand,
          name: agent.name,
          publicRoutePrefix: agent.publicRoutePrefix,
          servicePrefix: agent.servicePrefix,
        };
        if (agent.workspaceMember === true) {
          outputAgent.workspaceMember = true;
        }
        return outputAgent;
      }),
      nextRoot,
    });

    if (process.env.VERCEL) {
      return nextConfig;
    }

    const configuredAgentByName = new Map(
      configuredVercel.agents.map((agent) => [agent.name, agent] as const),
    );
    const agentsWithDestinations = agents.map((agent) => {
      const configuredAgent = configuredAgentByName.get(agent.name);
      const productionDestination = resolveProductionDestination({
        localProductionPortOffset: agent.localProductionPortOffset,
        servicePrefix: configuredAgent?.servicePrefix ?? agent.servicePrefix,
      });

      return {
        ...agent,
        productionDestination,
      };
    });

    return {
      ...nextConfig,
      async rewrites() {
        const [existing, orcelRules] = await Promise.all([
          resolveExistingRewrites(existingRewrites),
          Promise.all(
            agentsWithDestinations.map(async (agent) => {
              const destinationPrefix = await resolveOrcelDestinationPrefix({
                appRoot: agent.appRoot,
                devServerTimeoutMs,
                logLabel: agent.name,
                phase,
                productionDestinationPrefix: agent.productionDestination.destinationPrefix,
                productionServerOrigin: agent.productionDestination.localServerOrigin,
                workspaceAgentName: agent.workspaceMember === true ? agent.name : undefined,
              });

              return createOrcelRewriteRule({
                destinationPrefix,
                publicRoutePrefix: agent.publicRoutePrefix,
              });
            }),
          ),
        ]);

        return mergeRewriteRules(existing, orcelRules);
      },
    };
  };
}
