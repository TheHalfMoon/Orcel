import {
  compileOrcelVercelService,
  type OrcelVercelAgentTarget,
  type OrcelVercelBuildTarget,
} from "#internal/vercel/orcel-service-contribution.js";
import {
  findConfiguredOrcelServiceEntry,
  insertOrcelServiceRequestPathRoute,
  insertOrcelServiceRoutes,
} from "#internal/vercel/vercel-service-config-operations.js";
import type {
  VercelRouteConfig,
  VercelServiceConfig,
} from "#internal/vercel/vercel-services-config.js";

interface OrcelVercelServiceTarget {
  readonly agent: OrcelVercelAgentTarget;
  readonly target: OrcelVercelBuildTarget;
}

interface AssembledOrcelVercelServices {
  readonly rootDirectories: readonly string[];
  readonly routes: readonly VercelRouteConfig[];
  readonly services: Readonly<Record<string, VercelServiceConfig>>;
}

/** Merge orcel agents into one Vercel service graph. */
export function assembleOrcelVercelServices(input: {
  readonly agents: readonly OrcelVercelServiceTarget[];
  readonly routes?: readonly VercelRouteConfig[];
  readonly services?: Readonly<Record<string, VercelServiceConfig>>;
}): AssembledOrcelVercelServices {
  const existingServices = input.services ?? {};
  const services: Record<string, VercelServiceConfig> = { ...existingServices };
  const rootDirectories: string[] = [];
  const orcelRoutes: { routeSrc: string; serviceName: string }[] = [];

  for (const { agent, target } of input.agents) {
    const contribution = compileOrcelVercelService({ agent, target });
    const configured = findConfiguredOrcelServiceEntry(existingServices, agent);
    const serviceName = configured?.name ?? contribution.serviceName;

    if (configured === undefined) rootDirectories.push(contribution.rootDirectory);
    services[serviceName] =
      configured === undefined
        ? contribution.service
        : {
            ...configured.service,
            routes: insertOrcelServiceRequestPathRoute(
              configured.service.routes,
              contribution.routeSrc,
            ),
          };
    orcelRoutes.push({ routeSrc: contribution.routeSrc, serviceName });
    if (contribution.homeRouteSrc !== undefined) {
      orcelRoutes.push({ routeSrc: contribution.homeRouteSrc, serviceName });
    }
  }

  return {
    rootDirectories,
    routes: insertOrcelServiceRoutes(input.routes ?? [], orcelRoutes),
    services,
  };
}
