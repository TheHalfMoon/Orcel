import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

import { resolveKafProjectContext } from "#internal/project-context.js";
import { assembleKafVercelServices } from "#internal/vercel/assemble-kaf-services.js";
import { quoteVercelShellArgument, toVercelRelativePath } from "#internal/vercel/build-command.js";
import {
  createKafHomeRouteSrc,
  createKafServiceName,
  createKafServiceRouteSrc,
} from "#internal/vercel/kaf-service-contribution.js";
import {
  createServiceConfigRecord,
  type VercelServicesConfig,
} from "#internal/vercel/vercel-services-config.js";
import { resolveKafBinaryPath } from "#shared/resolve-kaf-binary.js";

/** A route accepted by kaf's Vercel configuration composer. */
export interface KafVercelRouteConfig {
  readonly destination?: string | { readonly service?: string; readonly type?: string };
  readonly handle?: string;
  readonly src?: string;
  readonly transforms?: readonly Record<string, unknown>[];
  readonly [key: string]: unknown;
}

/** A service accepted by kaf's Vercel configuration composer. */
export interface KafVercelServiceConfig {
  readonly buildCommand?: string;
  readonly entrypoint?: string;
  readonly framework?: string;
  readonly mount?: string | { readonly path?: string; readonly subdomain?: string };
  readonly outputDirectory?: string;
  readonly routes?: readonly KafVercelRouteConfig[];
  readonly root?: string;
  readonly type?: string;
  readonly [key: string]: unknown;
}

/** The portion of a programmatic Vercel configuration composed by kaf. */
export interface KafVercelConfig {
  readonly experimentalServices?: unknown;
  readonly experimentalServicesV2?: unknown;
  readonly routes?: readonly KafVercelRouteConfig[];
  readonly services?:
    | Readonly<Record<string, KafVercelServiceConfig>>
    | readonly (KafVercelServiceConfig & { readonly name: string })[];
  readonly [key: string]: unknown;
}

/** Options for composing an kaf workspace into a programmatic Vercel configuration. */
export interface WithKafOptions {
  /** Kaf workspace root. Defaults to the workspace containing the directory evaluating `vercel.ts`. */
  readonly root?: string;
}

function toInternalConfig(config: KafVercelConfig): VercelServicesConfig {
  return config as VercelServicesConfig;
}

function assertComposableConfig(
  config: KafVercelConfig,
  agentNames: readonly (string | undefined)[],
): void {
  if (config.experimentalServices !== undefined || config.experimentalServicesV2 !== undefined) {
    throw new Error(
      "withEve cannot compose experimentalServices or experimentalServicesV2. Remove the obsolete field and define authored services under services.",
    );
  }

  const internalConfig = toInternalConfig(config);
  const services = createServiceConfigRecord(internalConfig.services);
  for (const name of agentNames) {
    const agentLabel = JSON.stringify(name ?? "the default agent");
    const serviceName = createKafServiceName(name);
    if (
      Object.hasOwn(services, serviceName) ||
      (name === undefined && Object.values(services).some((service) => service.framework === "kaf"))
    ) {
      throw new Error(
        `Vercel service key ${JSON.stringify(serviceName)} conflicts with the service generated for kaf agent ${agentLabel}. Remove or rename the authored service; withEve owns this key.`,
      );
    }

    const publicRoutePrefix = name === undefined ? "" : `/kaf/${name}`;
    const routeSources = [
      createKafServiceRouteSrc(publicRoutePrefix),
      createKafHomeRouteSrc(publicRoutePrefix),
    ].filter((routeSrc): routeSrc is string => routeSrc !== undefined);
    for (const routeSrc of routeSources) {
      if (config.routes?.some((route) => route.src === routeSrc)) {
        throw new Error(
          `Vercel route ${JSON.stringify(routeSrc)} conflicts with the route generated for kaf agent ${agentLabel}. Remove the authored route; withEve adds it automatically.`,
        );
      }
    }
  }
}

/**
 * Add an kaf project's generated agent services and transport routes to `vercel.ts`.
 *
 * The returned object is a plain Vercel configuration. Vercel resolves it before independently
 * building the authored services and each generated kaf agent service.
 */
export async function withEve<TConfig extends KafVercelConfig>(
  config: TConfig,
  options: WithKafOptions = {},
): Promise<
  Omit<TConfig, "routes" | "services"> & {
    readonly routes: readonly KafVercelRouteConfig[];
    readonly services: Readonly<Record<string, KafVercelServiceConfig>>;
  }
> {
  const requestedRoot = resolve(options.root ?? process.cwd());
  const context = await resolveKafProjectContext(requestedRoot);
  if (
    context.kind === "workspace-member" ||
    (options.root !== undefined && context.environmentRoot !== requestedRoot)
  ) {
    throw new Error(`withEve must run at an kaf project root; received ${requestedRoot}.`);
  }
  const root = context.environmentRoot;

  const agents =
    context.kind === "standalone"
      ? [
          {
            appRoot: context.appRoot,
            name: undefined,
            publicRoutePrefix: "",
            workspaceMember: false,
          },
        ]
      : context.workspace.members.map((member) => ({
          appRoot: member.appRoot,
          name: member.name,
          publicRoutePrefix: `/kaf/${member.name}`,
          workspaceMember: true,
        }));
  if (agents.length === 0) {
    throw new Error(
      `withEve found no workspace agents under ${join(root, "agents")}. Add an agent or remove withEve from vercel.ts.`,
    );
  }

  const agentNames = agents.map((agent) => agent.name);
  const generatedServiceNames = new Set(agentNames.map(createKafServiceName));
  assertComposableConfig(config, agentNames);

  const outputDirectory = join(root, ".vercel", "output");
  const internalConfig = toInternalConfig(config);
  const assembled = assembleKafVercelServices({
    agents: agents.map((agent) => ({
      agent: {
        appRoot: agent.appRoot,
        buildCommand: `node ${quoteVercelShellArgument(
          toVercelRelativePath(agent.appRoot, resolveKafBinaryPath(agent.appRoot)),
        )} build`,
        devCommand: `node ${quoteVercelShellArgument(
          toVercelRelativePath(agent.appRoot, resolveKafBinaryPath(agent.appRoot)),
        )} dev --no-ui`,
        name: agent.name,
        publicRoutePrefix: agent.publicRoutePrefix,
        workspaceMember: agent.workspaceMember,
      },
      target: {
        hostOutputDirectory: outputDirectory,
        projectRoot: root,
      },
    })),
    routes: internalConfig.routes,
    services: createServiceConfigRecord(internalConfig.services),
  });

  await Promise.all(
    assembled.rootDirectories.map((directory) => mkdir(directory, { recursive: true })),
  );

  const services = Object.fromEntries(
    Object.entries(assembled.services).map(([name, service]) => {
      if (!generatedServiceNames.has(name)) {
        return [name, service];
      }
      const { routePrefix: _routePrefix, ...vercelSourceService } = service;
      return [name, vercelSourceService];
    }),
  );

  return {
    ...config,
    routes: assembled.routes as readonly KafVercelRouteConfig[],
    services: services as Readonly<Record<string, KafVercelServiceConfig>>,
  };
}
