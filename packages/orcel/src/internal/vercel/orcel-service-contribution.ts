import { createHash } from "node:crypto";
import { join } from "node:path";

import {
  ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER_ENV,
  ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY_ENV,
  ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY_ENV,
} from "#internal/application/build-output-environment.js";
import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";
import { joinOrcelRoutePath } from "#shared/orcel-route-path.js";
import {
  ORCEL_PUBLIC_ROUTE_PREFIX_ENV,
  normalizePublicRoutePrefix,
} from "#shared/public-route-prefix.js";
import { quoteVercelShellArgument, toVercelRelativePath } from "#internal/vercel/build-command.js";
import {
  assertValidVercelServiceName,
  isValidVercelServiceName,
  MAX_VERCEL_SERVICE_NAME_LENGTH,
} from "#internal/vercel/vercel-service-name.js";
import type {
  GeneratedVercelServiceConfig,
  VercelRouteConfig,
} from "#internal/vercel/vercel-services-config.js";

const ORCEL_VERCEL_SERVICES_DIRECTORY = ".orcel/vercel-services";

export interface OrcelVercelAgentTarget {
  readonly appRoot: string;
  readonly buildCommand: string;
  readonly devCommand?: string;
  readonly name?: string;
  readonly publicRoutePrefix: string;
  readonly workspaceMember?: boolean;
}

export interface OrcelVercelBuildTarget {
  readonly hostOutputDirectory: string;
  readonly projectRoot: string;
}

interface OrcelVercelServiceContribution {
  readonly homeRouteSrc: string | undefined;
  readonly rootDirectory: string;
  readonly routeSrc: string;
  readonly service: GeneratedVercelServiceConfig;
  readonly serviceName: string;
}

function createServiceNameHash(value: string): string {
  return [...createHash("sha256").update(value).digest().subarray(0, 10)]
    .map((byte) => String.fromCharCode(97 + (byte % 26)))
    .join("");
}

/** Derive a stable Vercel service identifier without restricting the public agent name. */
export function createOrcelServiceName(name: string | undefined): string {
  if (name === undefined) return "orcel";
  const directName = `orcel-${name}`;
  if (isValidVercelServiceName(directName)) return directName;

  const suffix = createServiceNameHash(name);
  const readableName = name.replace(/[^a-z_-]+/g, "-").replace(/^[^a-z]+|[^a-z]+$/g, "") || "agent";
  const readableLength = MAX_VERCEL_SERVICE_NAME_LENGTH - "orcel--".length - suffix.length;
  const readable = readableName.slice(0, readableLength).replace(/[^a-z]+$/g, "") || "agent";
  const serviceName = `orcel-${readable}-${suffix}`;
  assertValidVercelServiceName(serviceName, "Generated orcel service name");
  return serviceName;
}

function escapeVercelRouteLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function createOrcelServiceRouteSrc(publicRoutePrefix: string): string {
  if (publicRoutePrefix.length === 0) return `^${ORCEL_ROUTE_PREFIX}/(.*)$`;
  const prefix = publicRoutePrefix.startsWith("/") ? publicRoutePrefix : `/${publicRoutePrefix}`;
  return `^${escapeVercelRouteLiteral(joinOrcelRoutePath(prefix, ORCEL_ROUTE_PREFIX))}/(.*)$`;
}

export function createOrcelRequestPathRoute(routeSrc: string): VercelRouteConfig {
  return {
    src: routeSrc,
    transforms: [{ args: `${ORCEL_ROUTE_PREFIX}/$1`, op: "set", type: "request.path" }],
  };
}

export function createOrcelHomeRouteSrc(publicRoutePrefix: string): string | undefined {
  if (publicRoutePrefix.length === 0) return undefined;
  const prefix = publicRoutePrefix.startsWith("/") ? publicRoutePrefix : `/${publicRoutePrefix}`;
  return `^${escapeVercelRouteLiteral(prefix)}/?$`;
}

/** Route a member's public base path to its package-owned home channel. */
function createOrcelHomePathRoute(publicRoutePrefix: string): VercelRouteConfig | undefined {
  const src = createOrcelHomeRouteSrc(publicRoutePrefix);
  return src === undefined
    ? undefined
    : { src, transforms: [{ args: "/", op: "set", type: "request.path" }] };
}

export function createOrcelPublicRoute(serviceName: string, routeSrc: string): VercelRouteConfig {
  return { destination: { service: serviceName, type: "service" }, src: routeSrc };
}

function createIsolatedService(input: {
  readonly agent: OrcelVercelAgentTarget;
  readonly hostOutputDirectory: string;
  readonly projectRoot: string;
  readonly serviceName: string;
}): {
  readonly buildCommand: string;
  readonly devCommand?: string;
  readonly root: string;
  readonly rootDirectory: string;
} {
  const rootDirectory = join(input.projectRoot, ORCEL_VERCEL_SERVICES_DIRECTORY, input.serviceName);
  const outputDirectory = join(rootDirectory, ".vercel", "output");
  const prefix = normalizePublicRoutePrefix(input.agent.publicRoutePrefix);
  const prefixExport =
    prefix === undefined
      ? ""
      : ` && export ${ORCEL_PUBLIC_ROUTE_PREFIX_ENV}=${quoteVercelShellArgument(prefix)}`;
  const workspaceMemberExport =
    input.agent.workspaceMember === true
      ? ` && export ${ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER_ENV}=1`
      : "";

  const appRoot = quoteVercelShellArgument(
    toVercelRelativePath(rootDirectory, input.agent.appRoot),
  );
  return {
    buildCommand: `cd ${appRoot} && export ${ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY_ENV}=${quoteVercelShellArgument(toVercelRelativePath(input.agent.appRoot, outputDirectory))} && export ${ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY_ENV}=${quoteVercelShellArgument(toVercelRelativePath(input.agent.appRoot, input.hostOutputDirectory))}${prefixExport}${workspaceMemberExport} && ${input.agent.buildCommand}`,
    ...(input.agent.devCommand === undefined
      ? {}
      : {
          devCommand: `cd ${appRoot}${prefixExport}${workspaceMemberExport} && ${input.agent.devCommand}`,
        }),
    root: toVercelRelativePath(input.projectRoot, rootDirectory),
    rootDirectory,
  };
}

/** Compile one orcel agent into its complete Vercel service and ingress contribution. */
export function compileOrcelVercelService(input: {
  readonly agent: OrcelVercelAgentTarget;
  readonly target: OrcelVercelBuildTarget;
}): OrcelVercelServiceContribution {
  const serviceName = createOrcelServiceName(input.agent.name);
  const routeSrc = createOrcelServiceRouteSrc(input.agent.publicRoutePrefix);
  const homeRouteSrc =
    input.agent.workspaceMember === true
      ? createOrcelHomeRouteSrc(input.agent.publicRoutePrefix)
      : undefined;
  const homeRoute =
    input.agent.workspaceMember === true
      ? createOrcelHomePathRoute(input.agent.publicRoutePrefix)
      : undefined;
  const isolated = createIsolatedService({
    agent: input.agent,
    hostOutputDirectory: input.target.hostOutputDirectory,
    projectRoot: input.target.projectRoot,
    serviceName,
  });

  return {
    homeRouteSrc,
    rootDirectory: isolated.rootDirectory,
    routeSrc,
    service: {
      buildCommand: isolated.buildCommand,
      devCommand: isolated.devCommand,
      framework: "eve",
      outputDirectory: ".vercel/output",
      root: isolated.root,
      routes: [
        ...(homeRoute === undefined ? [] : [homeRoute]),
        createOrcelRequestPathRoute(routeSrc),
      ],
      ...(input.agent.publicRoutePrefix.length > 0
        ? { routePrefix: input.agent.publicRoutePrefix }
        : {}),
    },
    serviceName,
  };
}
