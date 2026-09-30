import { resolve } from "node:path";

import type { NextConfig } from "next";

import { assertValidPublicAgentName } from "#internal/agent-name.js";
import { findKafProjectContext } from "#internal/project-context.js";
import { quoteVercelShellArgument, toVercelRelativePath } from "#internal/vercel/build-command.js";
import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";
import { joinKafRoutePath } from "#shared/kaf-route-path.js";
import { resolveKafBinaryPath } from "#shared/resolve-kaf-binary.js";
import { NEXT_PHASE_PRODUCTION_BUILD, resolveKafDestinationPrefix } from "./server.js";
import { ensureKafVercelOutputConfig } from "./vercel-output-config.js";

/**
 * Default private route namespace for legacy manually configured Vercel
 * services. {@link WithKafOptions.servicePrefix} defaults to this value.
 */
export const KAF_NEXT_SERVICE_PREFIX = "/_kaf_internal/kaf";

const KAF_NEXT_PRODUCTION_ORIGIN_ENV = "KAF_NEXT_PRODUCTION_ORIGIN";
const KAF_NEXT_PRODUCTION_PORT_ENV = "KAF_NEXT_PRODUCTION_PORT";
const DEFAULT_KAF_NEXT_PRODUCTION_PORT = 4274;
const KAF_NAMED_AGENT_ROUTE_PREFIX = "/kaf";

type ArrayElement<T> = T extends readonly (infer TElement)[] ? TElement : never;
type NextRewrites = Awaited<ReturnType<NonNullable<NextConfig["rewrites"]>>>;

/**
 * Next.js rewrite rule that {@link withEve} emits.
 */
export type KafNextRewriteRule = ArrayElement<NextRewrites>;

/**
 * Resolved return type of a Next.js `rewrites` function: an array of rules, or
 * the sectioned `{ beforeFiles, afterFiles, fallback }` object.
 */
export type KafNextRewrites = NextRewrites;

/**
 * Sectioned Next.js rewrite rules.
 */
export type KafNextRewriteSections = Extract<
  NextRewrites,
  {
    readonly afterFiles?: KafNextRewriteRule[];
    readonly beforeFiles?: KafNextRewriteRule[];
    readonly fallback?: KafNextRewriteRule[];
  }
>;

/**
 * Alias of Next.js's `NextConfig`, the config object form {@link withEve}
 * accepts (the other being {@link KafNextConfigFunction}).
 */
export type KafNextConfig = NextConfig;

/**
 * Structural shape of a Next.js config function: receives the build `phase` and
 * a `context` containing `defaultConfig`, and returns a config (or a promise of
 * one). This is the form {@link withEve} returns.
 */
export type KafNextConfigFunction<TConfig extends KafNextConfig = KafNextConfig> = (
  phase: string,
  context: {
    readonly defaultConfig: TConfig;
  },
) => TConfig | Promise<TConfig>;

/**
 * Next.js config input that {@link withEve} accepts.
 */
export type KafNextConfigInput<TConfig extends KafNextConfig = KafNextConfig> =
  | KafNextConfigFunction<TConfig>
  | TConfig;

/**
 * Configuration for one named kaf agent mounted by {@link withEve}.
 */
export interface WithKafAgentOptions {
  /**
   * Path to the kaf application root, relative to `process.cwd()` unless
   * absolute.
   */
  readonly root: string;
  /**
   * Build command for this generated kaf Vercel service. Defaults to
   * {@link WithKafOptions.kafBuildCommand}, then a generated command that runs
   * the installed kaf binary from this agent root.
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
export type WithKafAgentsConfig = Record<string, string | WithKafAgentOptions>;

/**
 * Options for {@link withEve}.
 */
export interface WithKafOptions {
  /**
   * Maximum time in milliseconds to wait for the kaf development server to
   * start, including waiting for another Next.js process to start it. Defaults
   * to 180000 (three minutes).
   */
  readonly devServerTimeoutMs?: number;
  /**
   * Path to an kaf project root, relative to the Next.js app root unless
   * absolute. The root may contain one `agent/` or an `agents/` workspace.
   * Defaults to the Next.js app root.
   */
  readonly kafRoot?: string;
  /**
   * Named kaf agents to mount under `/kaf/<name>/v1/*`.
   *
   * Use this when one Next.js app needs to talk to multiple kaf agents outside
   * a project-level `agents/` workspace. When unset, withEve discovers a
   * workspace at the Next.js app root automatically. Do not combine with
   * {@link kafRoot}; the single-agent form remains the shorthand for one
   * unnamed agent mounted at `/kaf/v1/*`.
   */
  readonly agents?: WithKafAgentsConfig;
  /**
   * Build command for the generated kaf Vercel service. In multi-agent mode
   * this is the default for agents without their own `buildCommand`.
   *
   * When omitted, withEve generates a command that runs the installed kaf
   * binary from the agent root.
   */
  readonly kafBuildCommand?: string;
  /**
   * Private route namespace for legacy manually configured Vercel services and
   * non-Vercel production proxying. Defaults to {@link KAF_NEXT_SERVICE_PREFIX}
   * (`/_kaf_internal/kaf`). `withEve` normalizes the prefix (adds a leading
   * slash, strips trailing slashes) and rejects a prefix that resolves to the
   * root route.
   */
  readonly servicePrefix?: string;
}

interface ResolvedKafNextAgent {
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
    throw new Error("kaf Next.js development server timeout must be a positive number.");
  }

  return timeoutMs;
}

function normalizeRoutePrefix(prefix: string): string {
  const prefixed = prefix.startsWith("/") ? prefix : `/${prefix}`;
  const normalized = prefixed.replace(/\/+$/, "");

  if (normalized.length === 0) {
    throw new Error("kaf Next.js service prefix cannot resolve to the root route.");
  }

  return normalized;
}

function joinRoutePrefix(prefix: string, path: string): string {
  return `${prefix.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

function createNamedAgentRoutePrefix(name: string): string {
  return joinRoutePrefix(KAF_NAMED_AGENT_ROUTE_PREFIX, name);
}

function createNamedAgentServicePrefix(basePrefix: string, name: string): string {
  return joinRoutePrefix(basePrefix, name);
}

function createAgentRewriteSource(publicRoutePrefix: string): string {
  return joinKafRoutePath(publicRoutePrefix, `${KAF_ROUTE_PREFIX}/:path+`);
}

function normalizeOrigin(origin: string): string {
  return new URL(origin.trim()).origin;
}

function readLocalProductionPort(portOffset: number): number {
  const configuredPort = process.env[KAF_NEXT_PRODUCTION_PORT_ENV];

  const basePort =
    configuredPort === undefined || configuredPort.trim().length === 0
      ? DEFAULT_KAF_NEXT_PRODUCTION_PORT
      : Number.parseInt(configuredPort, 10);

  if (
    configuredPort !== undefined &&
    configuredPort.trim().length > 0 &&
    String(basePort) !== configuredPort.trim()
  ) {
    throw new Error(`${KAF_NEXT_PRODUCTION_PORT_ENV} must be an integer between 1 and 65535.`);
  }

  const port = basePort + portOffset;
  if (port < 1 || port > 65_535) {
    throw new Error(`${KAF_NEXT_PRODUCTION_PORT_ENV} plus the kaf agent count exceeds 65535.`);
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

  const configuredOrigin = process.env[KAF_NEXT_PRODUCTION_ORIGIN_ENV];

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

function createKafRewriteRule(input: {
  readonly destinationPrefix: string;
  readonly publicRoutePrefix: string;
}): KafNextRewriteRule {
  const source = createAgentRewriteSource(input.publicRoutePrefix);
  return {
    destination: joinRoutePrefix(input.destinationPrefix, `${KAF_ROUTE_PREFIX}/:path+`),
    source,
  };
}

async function resolveExistingRewrites(
  rewrites: KafNextConfig["rewrites"],
): Promise<KafNextRewrites | undefined> {
  return await rewrites?.();
}

function mergeRewriteRules(
  existing: KafNextRewrites | undefined,
  kafRules: KafNextRewriteRule[],
): KafNextRewrites {
  if (existing === undefined) {
    return {
      beforeFiles: kafRules,
    };
  }

  if (!isRewriteSections(existing)) {
    return {
      afterFiles: existing,
      beforeFiles: kafRules,
    };
  }

  return {
    ...existing,
    beforeFiles: [...kafRules, ...(existing.beforeFiles ?? [])],
  };
}

function isRewriteSections(rewrites: KafNextRewrites): rewrites is KafNextRewriteSections {
  return !Array.isArray(rewrites);
}

async function resolveNextConfig<TConfig extends KafNextConfig>(
  configOrFunction: KafNextConfigInput<TConfig>,
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
  assertValidPublicAgentName(name, "kaf Next.js agent name");
}

function assertValidWithKafOptions(options: WithKafOptions): void {
  if (options.kafRoot !== undefined && options.agents !== undefined) {
    throw new Error("withEve cannot combine kafRoot with agents. Use one configuration form.");
  }
  if (options.agents === undefined) return;
  const agentNames = Object.keys(options.agents);
  if (agentNames.length === 0) {
    throw new Error("withEve agents must contain at least one named kaf agent.");
  }
  for (const name of agentNames) assertValidAgentName(name);
}

function createDefaultBuildCommand(input: { readonly agentRoot: string }): string {
  const kafBinaryPath = toVercelRelativePath(
    input.agentRoot,
    resolveKafBinaryPath(input.agentRoot),
  );
  return `node ${quoteVercelShellArgument(kafBinaryPath)} build`;
}

async function normalizeAgentsConfig(
  options: WithKafOptions,
): Promise<readonly ResolvedKafNextAgent[]> {
  const servicePrefixBase = normalizeRoutePrefix(options.servicePrefix ?? KAF_NEXT_SERVICE_PREFIX);
  const resolveBuildCommand = (agentRoot: string, buildCommand: string | undefined) =>
    buildCommand ?? options.kafBuildCommand ?? createDefaultBuildCommand({ agentRoot });

  if (options.agents === undefined) {
    const kafRoot = resolveApplicationRoot(options.kafRoot);
    const context = await findKafProjectContext(kafRoot);
    if (
      context?.kind === "workspace" &&
      context.workspace.root === kafRoot &&
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

    const appRoot = kafRoot;
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
    throw new Error("withEve agents must contain at least one named kaf agent.");
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
  agents: readonly ResolvedKafNextAgent[],
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
 * Wraps a Next.js config so same-origin kaf endpoints proxy to a separate kaf
 * service.
 *
 * In development, starts `kaf dev --no-ui --port 0` for the kaf app and
 * rewrites kaf protocol endpoints to that local URL. During `next build`,
 * builds each agent's mounted source-backed workspace extensions so the
 * Next.js type check can resolve them. In Vercel production,
 * writes Build Output service routes so Vercel sends kaf protocol endpoints to
 * the kaf service directly.
 * Outside Vercel production, serves an existing `.output/server/index.mjs` build
 * on a stable local port when present; otherwise set `KAF_NEXT_PRODUCTION_ORIGIN`
 * to the origin serving the kaf service namespace.
 */
export function withEve<TConfig extends KafNextConfig>(
  configOrFunction: KafNextConfigInput<TConfig>,
  options: WithKafOptions = {},
): KafNextConfigFunction<TConfig> {
  const nextRoot = process.cwd();
  const devServerTimeoutMs = resolveDevServerTimeout(options.devServerTimeoutMs);
  assertValidWithKafOptions(options);
  return async function kafNextConfig(phase, context) {
    const [agents, nextConfig] = await Promise.all([
      normalizeAgentsConfig(options),
      resolveNextConfig(configOrFunction, phase, context),
    ]);
    if (phase === NEXT_PHASE_PRODUCTION_BUILD) {
      await buildAgentWorkspaceExtensions(agents);
    }
    const existingRewrites = nextConfig.rewrites;
    const configuredVercel = await ensureKafVercelOutputConfig({
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
        const [existing, kafRules] = await Promise.all([
          resolveExistingRewrites(existingRewrites),
          Promise.all(
            agentsWithDestinations.map(async (agent) => {
              const destinationPrefix = await resolveKafDestinationPrefix({
                appRoot: agent.appRoot,
                devServerTimeoutMs,
                logLabel: agent.name,
                phase,
                productionDestinationPrefix: agent.productionDestination.destinationPrefix,
                productionServerOrigin: agent.productionDestination.localServerOrigin,
                workspaceAgentName: agent.workspaceMember === true ? agent.name : undefined,
              });

              return createKafRewriteRule({
                destinationPrefix,
                publicRoutePrefix: agent.publicRoutePrefix,
              });
            }),
          ),
        ]);

        return mergeRewriteRules(existing, kafRules);
      },
    };
  };
}
