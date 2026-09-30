import {
  compileKafVercelService,
  type KafVercelAgentTarget,
  type KafVercelBuildTarget,
} from "#internal/vercel/kaf-service-contribution.js";
import {
  findConfiguredKafServiceEntry,
  insertKafServiceRequestPathRoute,
  insertKafServiceRoutes,
} from "#internal/vercel/vercel-service-config-operations.js";
import type {
  VercelRouteConfig,
  VercelServiceConfig,
} from "#internal/vercel/vercel-services-config.js";

interface KafVercelServiceTarget {
  readonly agent: KafVercelAgentTarget;
  readonly target: KafVercelBuildTarget;
}

interface AssembledKafVercelServices {
  readonly rootDirectories: readonly string[];
  readonly routes: readonly VercelRouteConfig[];
  readonly services: Readonly<Record<string, VercelServiceConfig>>;
}

/** Merge kaf agents into one Vercel service graph. */
export function assembleKafVercelServices(input: {
  readonly agents: readonly KafVercelServiceTarget[];
  readonly routes?: readonly VercelRouteConfig[];
  readonly services?: Readonly<Record<string, VercelServiceConfig>>;
}): AssembledKafVercelServices {
  const existingServices = input.services ?? {};
  const services: Record<string, VercelServiceConfig> = { ...existingServices };
  const rootDirectories: string[] = [];
  const kafRoutes: { routeSrc: string; serviceName: string }[] = [];

  for (const { agent, target } of input.agents) {
    const contribution = compileKafVercelService({ agent, target });
    const configured = findConfiguredKafServiceEntry(existingServices, agent);
    const serviceName = configured?.name ?? contribution.serviceName;

    if (configured === undefined) rootDirectories.push(contribution.rootDirectory);
    services[serviceName] =
      configured === undefined
        ? contribution.service
        : {
            ...configured.service,
            routes: insertKafServiceRequestPathRoute(
              configured.service.routes,
              contribution.routeSrc,
            ),
          };
    kafRoutes.push({ routeSrc: contribution.routeSrc, serviceName });
    if (contribution.homeRouteSrc !== undefined) {
      kafRoutes.push({ routeSrc: contribution.homeRouteSrc, serviceName });
    }
  }

  return {
    rootDirectories,
    routes: insertKafServiceRoutes(input.routes ?? [], kafRoutes),
    services,
  };
}
