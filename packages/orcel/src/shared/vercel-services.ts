import { mkdir, readFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";

import { shellQuote } from "#shared/shell-quote.js";

import {
  ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY_ENV,
  ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY_ENV,
} from "#internal/application/paths.js";
import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";
import { resolveOrcelBinaryPath } from "#shared/resolve-orcel-binary.js";
import { findClosestLinkedVercelDirectory } from "#shared/vercel-output-directory.js";

const VERCEL_JSON_FILE_NAME = "vercel.json";
const ORCEL_SERVICE_NAME = "orcel";
const ORCEL_SERVICE_ROUTE_SRC = `^${ORCEL_ROUTE_PREFIX}/(.*)$`;
const ORCEL_SERVICE_ROUTE_PATH = `${ORCEL_ROUTE_PREFIX}/$1`;
const ORCEL_VERCEL_SERVICES_DIRECTORY = ".orcel/vercel-services";

interface VercelRequestPathTransform {
  readonly args: string;
  readonly op: "set";
  readonly type: "request.path";
}

interface VercelServiceRouteDestination {
  readonly service?: string;
  readonly type?: string;
}

interface VercelRouteConfig {
  readonly destination?: string | VercelServiceRouteDestination;
  readonly handle?: string;
  readonly src?: string;
  readonly transforms?: readonly VercelRequestPathTransform[];
  readonly [key: string]: unknown;
}

interface VercelServiceConfig {
  readonly framework?: string;
  readonly routes?: readonly VercelRouteConfig[];
  readonly [key: string]: unknown;
}

interface VercelNamedServiceConfig extends VercelServiceConfig {
  readonly name?: string;
}

type VercelServicesCollection =
  | Record<string, VercelServiceConfig>
  | readonly VercelNamedServiceConfig[];

interface VercelJsonConfig {
  readonly experimentalServices?: unknown;
  readonly services?: VercelServicesCollection;
  readonly [key: string]: unknown;
}

/**
 * The top-level Vercel Build Output route that sends orcel transport requests to
 * the generated orcel service.
 */
type OrcelVercelServiceRoute = {
  readonly destination: {
    readonly service: string;
    readonly type: "service";
  };
  readonly src: string;
};

/**
 * A service-scoped route carrying the `request.path` transform that pins the
 * path the orcel runtime observes to the orcel transport namespace.
 */
type OrcelVercelServiceRequestPathRoute = {
  readonly src: string;
  readonly transforms: readonly [VercelRequestPathTransform];
};

/**
 * The generated orcel service entry written into the Vercel Build Output
 * `services` record.
 */
export type OrcelVercelGeneratedService = {
  readonly buildCommand: string;
  readonly framework: "eve";
  readonly outputDirectory: ".vercel/output";
  readonly routes: readonly VercelRouteConfig[];
  readonly root: string;
};

/**
 * Minimal shape of a Vercel Build Output config that can carry generated orcel
 * services.
 */
export interface VercelBuildConfig {
  version?: number;
  routes?: unknown[];
  services?: Record<string, VercelServiceConfig>;
  [key: string]: unknown;
}

/**
 * Result of {@link ensureOrcelVercelServicesConfig}: `root` when `vercel.json`
 * already declares stable services (the user owns routing; nothing is
 * generated), `generated` with the service record to merge into a Vercel Build
 * Output config otherwise.
 */
export type EnsureOrcelVercelServicesConfigResult =
  | { readonly mode: "root" }
  | {
      readonly mode: "generated";
      readonly services: Record<string, OrcelVercelGeneratedService>;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function toPosixRelative(from: string, to: string): string {
  const relativePath = relative(from, to);
  return relativePath.length === 0 ? "." : relativePath.replaceAll("\\", "/");
}

function isNamedServiceConfigArray(
  services: VercelServicesCollection,
): services is readonly VercelNamedServiceConfig[] {
  return Array.isArray(services);
}

function createServiceConfigRecord(
  services: VercelServicesCollection | undefined,
): Record<string, VercelServiceConfig> {
  if (services === undefined) {
    return {};
  }

  if (isNamedServiceConfigArray(services)) {
    const record: Record<string, VercelServiceConfig> = {};

    for (const service of services) {
      if (typeof service.name === "string" && service.name.trim().length > 0) {
        const { name, ...serviceConfig } = service;
        record[name] = serviceConfig;
      }
    }

    return record;
  }

  return services;
}

function normalizeVercelJsonConfig(value: unknown): VercelJsonConfig {
  if (!isRecord(value)) {
    throw new Error(`${VERCEL_JSON_FILE_NAME} must contain a JSON object.`);
  }

  const services = value.services;

  if (
    services !== undefined &&
    !isRecord(services) &&
    !(
      Array.isArray(services) &&
      services.every(
        (service) =>
          isRecord(service) && typeof service.name === "string" && service.name.trim().length > 0,
      )
    )
  ) {
    throw new Error(
      `${VERCEL_JSON_FILE_NAME} services must be a JSON object or named service array.`,
    );
  }

  return value as VercelJsonConfig;
}

async function readVercelJsonConfig(path: string): Promise<VercelJsonConfig> {
  try {
    return normalizeVercelJsonConfig(JSON.parse(await readFile(path, "utf8")) as unknown);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return {};
    }

    throw error;
  }
}

function findOrcelService(
  services: Record<string, VercelServiceConfig>,
): VercelServiceConfig | undefined {
  return Object.values(services).find((service) => service.framework === "eve");
}

function assertRootServicesIncludeEve(
  services: Record<string, VercelServiceConfig>,
  frameworkName: string,
): void {
  if (findOrcelService(services) === undefined) {
    throw new Error(
      `${VERCEL_JSON_FILE_NAME} already defines services, so the orcel ${frameworkName} integration cannot add a generated orcel service. Add an orcel service (framework "eve") and a rewrite from ${ORCEL_ROUTE_PREFIX}/(.*) to it in ${VERCEL_JSON_FILE_NAME}, or remove services from ${VERCEL_JSON_FILE_NAME}.`,
    );
  }
}

/**
 * Build the top-level Build Output route that exposes the orcel service on the
 * orcel transport namespace (`/orcel/v1/*`).
 */
export function createOrcelServiceRoute(
  serviceName: string = ORCEL_SERVICE_NAME,
): OrcelVercelServiceRoute {
  return {
    destination: {
      service: serviceName,
      type: "service",
    },
    src: ORCEL_SERVICE_ROUTE_SRC,
  };
}

/**
 * Build the orcel service's own route that sets `request.path` so the orcel
 * runtime observes the transport path regardless of how the platform routed
 * the request into the service.
 */
export function createOrcelServiceRequestPathRoute(): OrcelVercelServiceRequestPathRoute {
  return {
    src: ORCEL_SERVICE_ROUTE_SRC,
    transforms: [
      {
        args: ORCEL_SERVICE_ROUTE_PATH,
        op: "set",
        type: "request.path",
      },
    ],
  };
}

function isOrcelServiceRoute(route: VercelRouteConfig, serviceName: string): boolean {
  const destination = route.destination;

  return (
    route.src === ORCEL_SERVICE_ROUTE_SRC &&
    isRecord(destination) &&
    destination.type === "service" &&
    destination.service === serviceName
  );
}

function insertOrcelServiceRoute(routes: readonly unknown[], serviceName: string): unknown[] {
  const routesWithoutOrcelRoute = routes.filter(
    (route) => !(isRecord(route) && isOrcelServiceRoute(route, serviceName)),
  );
  const filesystemRouteIndex = routesWithoutOrcelRoute.findIndex(
    (route) => isRecord(route) && route.handle === "filesystem",
  );

  if (filesystemRouteIndex === -1) {
    return [createOrcelServiceRoute(serviceName), ...routesWithoutOrcelRoute];
  }

  return [
    ...routesWithoutOrcelRoute.slice(0, filesystemRouteIndex),
    createOrcelServiceRoute(serviceName),
    ...routesWithoutOrcelRoute.slice(filesystemRouteIndex),
  ];
}

function insertOrcelServiceRequestPathRoute(
  routes: readonly VercelRouteConfig[] | undefined,
): readonly VercelRouteConfig[] {
  const routesWithoutGeneratedRoute = (routes ?? []).filter(
    (route) => route.src !== ORCEL_SERVICE_ROUTE_SRC,
  );

  return [createOrcelServiceRequestPathRoute(), ...routesWithoutGeneratedRoute];
}

function createGeneratedServiceBuild(input: {
  readonly appRoot: string;
  readonly orcelBuildCommand?: string;
  readonly hostRoot: string;
}): { readonly buildCommand: string; readonly root: string; readonly rootDirectory: string } {
  const rootDirectory = join(input.hostRoot, ORCEL_VERCEL_SERVICES_DIRECTORY, ORCEL_SERVICE_NAME);
  const outputDirectory = join(rootDirectory, ".vercel", "output");
  const hostOutputDirectory = join(input.hostRoot, ".vercel", "output");
  const workingDirectory = toPosixRelative(rootDirectory, input.appRoot);
  const configuredOutputDirectory = toPosixRelative(input.appRoot, outputDirectory);
  const configuredHostOutputDirectory = toPosixRelative(input.appRoot, hostOutputDirectory);
  const buildCommand =
    input.orcelBuildCommand ??
    `node ${shellQuote(toPosixRelative(input.appRoot, resolveOrcelBinaryPath(input.hostRoot)))} build`;

  return {
    buildCommand: `cd ${shellQuote(workingDirectory)} && export ${ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY_ENV}=${shellQuote(configuredOutputDirectory)} && export ${ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY_ENV}=${shellQuote(configuredHostOutputDirectory)} && ${buildCommand}`,
    root: toPosixRelative(input.hostRoot, rootDirectory),
    rootDirectory,
  };
}

/**
 * Resolve the stable Vercel services configuration for a framework + orcel
 * deployment.
 *
 * When `vercel.json` (looked up from the linked Vercel project root, falling
 * back to the host root) already declares stable `services`, it must include
 * an orcel service and the module generates nothing. Otherwise this prepares a
 * generated orcel service — creating its isolated build root under
 * `.orcel/vercel-services/orcel` so the orcel build output cannot collide with the
 * host Build Output — and returns the service record plus the public service
 * route for the caller to merge into its Vercel build config. A legacy
 * `experimentalServices` field is ignored with a migration warning: Vercel no
 * longer routes it.
 */
export async function ensureOrcelVercelServicesConfig(input: {
  readonly appRoot: string;
  readonly orcelBuildCommand?: string;
  readonly frameworkName: string;
  readonly hostRoot: string;
}): Promise<EnsureOrcelVercelServicesConfigResult> {
  const vercelDirectory = await findClosestLinkedVercelDirectory(input.hostRoot);
  const projectRoot = vercelDirectory === undefined ? input.hostRoot : dirname(vercelDirectory);
  // With a Vercel Root Directory, vercel.json lives in the root directory
  // (the host root) while the .vercel link lives at the repository root, so
  // the host root declaration wins over the linked project root's.
  const hostRootVercelConfig = await readVercelJsonConfig(
    join(input.hostRoot, VERCEL_JSON_FILE_NAME),
  );
  const rootVercelConfig =
    projectRoot === input.hostRoot ||
    Object.keys(createServiceConfigRecord(hostRootVercelConfig.services)).length > 0
      ? hostRootVercelConfig
      : await readVercelJsonConfig(join(projectRoot, VERCEL_JSON_FILE_NAME));
  const rootServices = createServiceConfigRecord(rootVercelConfig.services);

  if (Object.keys(rootServices).length > 0) {
    assertRootServicesIncludeEve(rootServices, input.frameworkName);
    return { mode: "root" };
  }

  if (rootVercelConfig.experimentalServices !== undefined) {
    console.warn(
      `[orcel] ${VERCEL_JSON_FILE_NAME} defines experimentalServices, which Vercel no longer routes. The orcel ${input.frameworkName} integration now generates the stable services config automatically — remove experimentalServices from ${VERCEL_JSON_FILE_NAME}.`,
    );
  }

  const generatedServiceBuild = createGeneratedServiceBuild(input);
  await mkdir(generatedServiceBuild.rootDirectory, { recursive: true });

  return {
    mode: "generated",
    services: {
      [ORCEL_SERVICE_NAME]: {
        buildCommand: generatedServiceBuild.buildCommand,
        framework: "eve",
        outputDirectory: ".vercel/output",
        routes: [createOrcelServiceRequestPathRoute()],
        root: generatedServiceBuild.root,
      },
    },
  };
}

/**
 * Merge the generated orcel service and its public route into a Vercel Build
 * Output config.
 *
 * The service route is inserted before an existing `handle: "filesystem"`
 * route, or prepended when none exists. An orcel service already configured by
 * the user is preserved and only gains the `request.path` route; everything
 * else passes through untouched.
 */
export function mergeOrcelVercelConfig(
  existing: VercelBuildConfig | undefined,
  generated: Extract<EnsureOrcelVercelServicesConfigResult, { mode: "generated" }>,
): VercelBuildConfig {
  const existingServices = existing?.services ?? {};
  const configuredOrcelEntry = Object.entries(existingServices).find(
    ([name, service]) => name === ORCEL_SERVICE_NAME || service.framework === "eve",
  );
  const serviceName = configuredOrcelEntry?.[0] ?? ORCEL_SERVICE_NAME;
  const services = configuredOrcelEntry
    ? {
        ...existingServices,
        [serviceName]: {
          ...configuredOrcelEntry[1],
          routes: insertOrcelServiceRequestPathRoute(configuredOrcelEntry[1].routes),
        },
      }
    : { ...existingServices, ...generated.services };

  return {
    version: 3,
    ...existing,
    routes: insertOrcelServiceRoute(existing?.routes ?? [], serviceName),
    services,
  };
}
