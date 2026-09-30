import { mkdir, readFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";

import { shellQuote } from "#shared/shell-quote.js";

import {
  KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY_ENV,
  KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY_ENV,
} from "#internal/application/paths.js";
import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";
import { resolveKafBinaryPath } from "#shared/resolve-kaf-binary.js";
import { findClosestLinkedVercelDirectory } from "#shared/vercel-output-directory.js";

const VERCEL_JSON_FILE_NAME = "vercel.json";
const KAF_SERVICE_NAME = "kaf";
const KAF_SERVICE_ROUTE_SRC = `^${KAF_ROUTE_PREFIX}/(.*)$`;
const KAF_SERVICE_ROUTE_PATH = `${KAF_ROUTE_PREFIX}/$1`;
const KAF_VERCEL_SERVICES_DIRECTORY = ".kaf/vercel-services";

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
 * The top-level Vercel Build Output route that sends kaf transport requests to
 * the generated kaf service.
 */
type KafVercelServiceRoute = {
  readonly destination: {
    readonly service: string;
    readonly type: "service";
  };
  readonly src: string;
};

/**
 * A service-scoped route carrying the `request.path` transform that pins the
 * path the kaf runtime observes to the kaf transport namespace.
 */
type KafVercelServiceRequestPathRoute = {
  readonly src: string;
  readonly transforms: readonly [VercelRequestPathTransform];
};

/**
 * The generated kaf service entry written into the Vercel Build Output
 * `services` record.
 */
export type KafVercelGeneratedService = {
  readonly buildCommand: string;
  readonly framework: "kaf";
  readonly outputDirectory: ".vercel/output";
  readonly routes: readonly VercelRouteConfig[];
  readonly root: string;
};

/**
 * Minimal shape of a Vercel Build Output config that can carry generated kaf
 * services.
 */
export interface VercelBuildConfig {
  version?: number;
  routes?: unknown[];
  services?: Record<string, VercelServiceConfig>;
  [key: string]: unknown;
}

/**
 * Result of {@link ensureKafVercelServicesConfig}: `root` when `vercel.json`
 * already declares stable services (the user owns routing; nothing is
 * generated), `generated` with the service record to merge into a Vercel Build
 * Output config otherwise.
 */
export type EnsureKafVercelServicesConfigResult =
  | { readonly mode: "root" }
  | {
      readonly mode: "generated";
      readonly services: Record<string, KafVercelGeneratedService>;
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

function findKafService(
  services: Record<string, VercelServiceConfig>,
): VercelServiceConfig | undefined {
  return Object.values(services).find((service) => service.framework === "kaf");
}

function assertRootServicesIncludeEve(
  services: Record<string, VercelServiceConfig>,
  frameworkName: string,
): void {
  if (findKafService(services) === undefined) {
    throw new Error(
      `${VERCEL_JSON_FILE_NAME} already defines services, so the kaf ${frameworkName} integration cannot add a generated kaf service. Add an kaf service (framework "kaf") and a rewrite from ${KAF_ROUTE_PREFIX}/(.*) to it in ${VERCEL_JSON_FILE_NAME}, or remove services from ${VERCEL_JSON_FILE_NAME}.`,
    );
  }
}

/**
 * Build the top-level Build Output route that exposes the kaf service on the
 * kaf transport namespace (`/kaf/v1/*`).
 */
export function createKafServiceRoute(
  serviceName: string = KAF_SERVICE_NAME,
): KafVercelServiceRoute {
  return {
    destination: {
      service: serviceName,
      type: "service",
    },
    src: KAF_SERVICE_ROUTE_SRC,
  };
}

/**
 * Build the kaf service's own route that sets `request.path` so the kaf
 * runtime observes the transport path regardless of how the platform routed
 * the request into the service.
 */
export function createKafServiceRequestPathRoute(): KafVercelServiceRequestPathRoute {
  return {
    src: KAF_SERVICE_ROUTE_SRC,
    transforms: [
      {
        args: KAF_SERVICE_ROUTE_PATH,
        op: "set",
        type: "request.path",
      },
    ],
  };
}

function isKafServiceRoute(route: VercelRouteConfig, serviceName: string): boolean {
  const destination = route.destination;

  return (
    route.src === KAF_SERVICE_ROUTE_SRC &&
    isRecord(destination) &&
    destination.type === "service" &&
    destination.service === serviceName
  );
}

function insertKafServiceRoute(routes: readonly unknown[], serviceName: string): unknown[] {
  const routesWithoutKafRoute = routes.filter(
    (route) => !(isRecord(route) && isKafServiceRoute(route, serviceName)),
  );
  const filesystemRouteIndex = routesWithoutKafRoute.findIndex(
    (route) => isRecord(route) && route.handle === "filesystem",
  );

  if (filesystemRouteIndex === -1) {
    return [createKafServiceRoute(serviceName), ...routesWithoutKafRoute];
  }

  return [
    ...routesWithoutKafRoute.slice(0, filesystemRouteIndex),
    createKafServiceRoute(serviceName),
    ...routesWithoutKafRoute.slice(filesystemRouteIndex),
  ];
}

function insertKafServiceRequestPathRoute(
  routes: readonly VercelRouteConfig[] | undefined,
): readonly VercelRouteConfig[] {
  const routesWithoutGeneratedRoute = (routes ?? []).filter(
    (route) => route.src !== KAF_SERVICE_ROUTE_SRC,
  );

  return [createKafServiceRequestPathRoute(), ...routesWithoutGeneratedRoute];
}

function createGeneratedServiceBuild(input: {
  readonly appRoot: string;
  readonly kafBuildCommand?: string;
  readonly hostRoot: string;
}): { readonly buildCommand: string; readonly root: string; readonly rootDirectory: string } {
  const rootDirectory = join(input.hostRoot, KAF_VERCEL_SERVICES_DIRECTORY, KAF_SERVICE_NAME);
  const outputDirectory = join(rootDirectory, ".vercel", "output");
  const hostOutputDirectory = join(input.hostRoot, ".vercel", "output");
  const workingDirectory = toPosixRelative(rootDirectory, input.appRoot);
  const configuredOutputDirectory = toPosixRelative(input.appRoot, outputDirectory);
  const configuredHostOutputDirectory = toPosixRelative(input.appRoot, hostOutputDirectory);
  const buildCommand =
    input.kafBuildCommand ??
    `node ${shellQuote(toPosixRelative(input.appRoot, resolveKafBinaryPath(input.hostRoot)))} build`;

  return {
    buildCommand: `cd ${shellQuote(workingDirectory)} && export ${KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY_ENV}=${shellQuote(configuredOutputDirectory)} && export ${KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY_ENV}=${shellQuote(configuredHostOutputDirectory)} && ${buildCommand}`,
    root: toPosixRelative(input.hostRoot, rootDirectory),
    rootDirectory,
  };
}

/**
 * Resolve the stable Vercel services configuration for a framework + kaf
 * deployment.
 *
 * When `vercel.json` (looked up from the linked Vercel project root, falling
 * back to the host root) already declares stable `services`, it must include
 * an kaf service and the module generates nothing. Otherwise this prepares a
 * generated kaf service — creating its isolated build root under
 * `.kaf/vercel-services/kaf` so the kaf build output cannot collide with the
 * host Build Output — and returns the service record plus the public service
 * route for the caller to merge into its Vercel build config. A legacy
 * `experimentalServices` field is ignored with a migration warning: Vercel no
 * longer routes it.
 */
export async function ensureKafVercelServicesConfig(input: {
  readonly appRoot: string;
  readonly kafBuildCommand?: string;
  readonly frameworkName: string;
  readonly hostRoot: string;
}): Promise<EnsureKafVercelServicesConfigResult> {
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
      `[kaf] ${VERCEL_JSON_FILE_NAME} defines experimentalServices, which Vercel no longer routes. The kaf ${input.frameworkName} integration now generates the stable services config automatically — remove experimentalServices from ${VERCEL_JSON_FILE_NAME}.`,
    );
  }

  const generatedServiceBuild = createGeneratedServiceBuild(input);
  await mkdir(generatedServiceBuild.rootDirectory, { recursive: true });

  return {
    mode: "generated",
    services: {
      [KAF_SERVICE_NAME]: {
        buildCommand: generatedServiceBuild.buildCommand,
        framework: "kaf",
        outputDirectory: ".vercel/output",
        routes: [createKafServiceRequestPathRoute()],
        root: generatedServiceBuild.root,
      },
    },
  };
}

/**
 * Merge the generated kaf service and its public route into a Vercel Build
 * Output config.
 *
 * The service route is inserted before an existing `handle: "filesystem"`
 * route, or prepended when none exists. An kaf service already configured by
 * the user is preserved and only gains the `request.path` route; everything
 * else passes through untouched.
 */
export function mergeKafVercelConfig(
  existing: VercelBuildConfig | undefined,
  generated: Extract<EnsureKafVercelServicesConfigResult, { mode: "generated" }>,
): VercelBuildConfig {
  const existingServices = existing?.services ?? {};
  const configuredKafEntry = Object.entries(existingServices).find(
    ([name, service]) => name === KAF_SERVICE_NAME || service.framework === "kaf",
  );
  const serviceName = configuredKafEntry?.[0] ?? KAF_SERVICE_NAME;
  const services = configuredKafEntry
    ? {
        ...existingServices,
        [serviceName]: {
          ...configuredKafEntry[1],
          routes: insertKafServiceRequestPathRoute(configuredKafEntry[1].routes),
        },
      }
    : { ...existingServices, ...generated.services };

  return {
    version: 3,
    ...existing,
    routes: insertKafServiceRoute(existing?.routes ?? [], serviceName),
    services,
  };
}
