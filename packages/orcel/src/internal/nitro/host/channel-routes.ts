import type { Nitro } from "nitro/types";

import type { ChannelRouteMethod } from "#public/definitions/channel.js";
import { stringifyEsmImportSpecifier } from "#internal/application/import-specifier.js";
import {
  resolvePackageDependencyPath,
  resolvePackageSourceFilePath,
} from "#internal/application/package.js";
import {
  type ApplicationChannelPreflightRoute,
  type ApplicationChannelRoute,
  type ApplicationChannelRouteRegistration,
  computeApplicationChannelRouteRegistrations,
} from "#internal/nitro/host/application-route-registry.js";
import type { NitroArtifactsConfig } from "#internal/nitro/routes/runtime-artifacts.js";
import type { PreparedApplicationHost } from "#internal/nitro/host/types.js";

const ORCEL_CHANNEL_VIRTUAL_ID_PREFIX = "#nitro/virtual/orcel-channel/";

interface ChannelRouteNitro {
  readonly options: Pick<Nitro["options"], "handlers" | "virtual">;
}

/** One active channel binding in the orcel-owned application route registry. */
type NitroChannelRouteRegistration = ApplicationChannelRouteRegistration;

/**
 * Computes the merged set of channel routes the Nitro host should mount.
 */
export function computeChannelRouteRegistrations(
  preparedHost: PreparedApplicationHost,
): readonly NitroChannelRouteRegistration[] {
  return computeApplicationChannelRouteRegistrations(preparedHost);
}

/**
 * Registers virtual Nitro handlers for the provided orcel channel routes.
 */
export function registerChannelVirtualHandlers(
  nitro: Pick<ChannelRouteNitro, "options">,
  input: {
    readonly artifactsConfig: NitroArtifactsConfig;
    readonly routes: readonly (ApplicationChannelPreflightRoute | ApplicationChannelRoute)[];
  },
): void {
  const channelRoutes = input.routes.filter(
    (route): route is ApplicationChannelRoute => route.kind === "channel",
  );
  const webSocketByPath = new Map(
    channelRoutes
      .filter((route) => route.method === "WEBSOCKET")
      .map((route) => [route.path, route] as const),
  );
  const getByPath = new Map(
    channelRoutes.filter((route) => route.method === "GET").map((route) => [route.path, route] as const),
  );
  const httpPaths = new Set(
    channelRoutes.filter((route) => route.method !== "WEBSOCKET").map((route) => route.path),
  );

  for (const route of input.routes) {
    if (route.kind === "channel-preflight") {
      addChannelCorsPreflightHandler(nitro, route);
      continue;
    }

    if (route.method === "WEBSOCKET") {
      const getRoute = getByPath.get(route.path);
      if (getRoute !== undefined) {
        addSharedGetAndWebSocketVirtualHandler(nitro, {
          artifactsConfig: input.artifactsConfig,
          getRoute,
          webSocketRoute: route,
        });
      } else {
        addChannelVirtualHandler(nitro, {
          artifactsConfig: input.artifactsConfig,
          route,
        });
      }
      continue;
    }

    if (route.method === "GET" && webSocketByPath.has(route.path)) {
      continue;
    }

    addChannelVirtualHandler(nitro, {
      artifactsConfig: input.artifactsConfig,
      route,
    });
  }

  for (const path of httpPaths) {
    if (!webSocketByPath.has(path) && !getByPath.has(path)) {
      addRejectedWebSocketUpgradeHandler(nitro, path);
    }
  }
}

function createChannelRouteKey(input: {
  readonly method: ChannelRouteMethod | "OPTIONS";
  readonly path: string;
}): string {
  return `${input.method.toUpperCase()} ${input.path}`;
}

function addChannelVirtualHandler(
  nitro: Pick<ChannelRouteNitro, "options">,
  input: {
    artifactsConfig: NitroArtifactsConfig;
    route: ApplicationChannelPreflightRoute | ApplicationChannelRoute;
  },
): void {
  if (input.route.kind === "channel-preflight") {
    addChannelCorsPreflightHandler(nitro, input.route);
    return;
  }

  const routeKey = createChannelRouteKey(input.route);
  const virtualId = `${ORCEL_CHANNEL_VIRTUAL_ID_PREFIX}${routeKey}`;
  const dispatchModulePath = stringifyEsmImportSpecifier(
    resolvePackageSourceFilePath("src/internal/nitro/routes/channel-dispatch.ts"),
  );
  const nitroModulePath = stringifyEsmImportSpecifier(resolvePackageDependencyPath("nitro"));
  const nitroH3ModulePath = stringifyEsmImportSpecifier(resolvePackageDependencyPath("nitro/h3"));

  if (input.route.method === "WEBSOCKET") {
    nitro.options.handlers.push({
      handler: virtualId,
      method: "GET",
      route: input.route.path,
    });
    nitro.options.virtual[virtualId] = [
      `import { defineWebSocketHandler } from ${nitroModulePath};`,
      `import { dispatchChannelWebSocketRequest } from ${dispatchModulePath};`,
      `const config = ${JSON.stringify(input.artifactsConfig)};`,
      `export default defineWebSocketHandler((event) => dispatchChannelWebSocketRequest(event, ${JSON.stringify(routeKey)}, config));`,
    ].join("\n");
    return;
  }

  nitro.options.handlers.push({
    handler: virtualId,
    method: input.route.method,
    route: input.route.path,
  });

  const httpHandler = renderChannelHttpHandler(input.route, routeKey);
  nitro.options.virtual[virtualId] = [
    ...(input.route.method === "GET"
      ? [`import { defineWebSocketHandler } from ${nitroModulePath};`]
      : []),
    ...(input.route.cors === undefined
      ? []
      : [
          `import { handleCors } from ${nitroH3ModulePath};`,
          `const cors = ${JSON.stringify(input.route.cors)};`,
        ]),
    `import { dispatchChannelRequest } from ${dispatchModulePath};`,
    `const config = ${JSON.stringify(input.artifactsConfig)};`,
    input.route.method === "GET"
      ? [
          `const httpHandler = ${httpHandler};`,
          `export default defineWebSocketHandler({`,
          `  upgrade() { throw new Response(null, { status: 404 }); },`,
          `}, httpHandler);`,
        ].join("\n")
      : `export default ${httpHandler};`,
  ].join("\n");
}

function renderChannelHttpHandler(route: ApplicationChannelRoute, routeKey: string): string {
  if (route.cors === undefined) {
    return `(event) => dispatchChannelRequest(event, ${JSON.stringify(routeKey)}, config)`;
  }

  return [
    `(event) => {`,
    `  const corsResponse = handleCors(event, cors);`,
    `  if (corsResponse !== false) return corsResponse;`,
    `  return dispatchChannelRequest(event, ${JSON.stringify(routeKey)}, config);`,
    `}`,
  ].join("\n");
}

function addSharedGetAndWebSocketVirtualHandler(
  nitro: Pick<ChannelRouteNitro, "options">,
  input: {
    artifactsConfig: NitroArtifactsConfig;
    getRoute: ApplicationChannelRoute;
    webSocketRoute: ApplicationChannelRoute;
  },
): void {
  const getRouteKey = createChannelRouteKey(input.getRoute);
  const webSocketRouteKey = createChannelRouteKey(input.webSocketRoute);
  const virtualId = `${ORCEL_CHANNEL_VIRTUAL_ID_PREFIX}GET+WEBSOCKET ${input.getRoute.path}`;
  const dispatchModulePath = stringifyEsmImportSpecifier(
    resolvePackageSourceFilePath("src/internal/nitro/routes/channel-dispatch.ts"),
  );
  const nitroModulePath = stringifyEsmImportSpecifier(resolvePackageDependencyPath("nitro"));
  const nitroH3ModulePath = stringifyEsmImportSpecifier(resolvePackageDependencyPath("nitro/h3"));
  const httpHandler = renderChannelHttpHandler(input.getRoute, getRouteKey);

  nitro.options.handlers.push({
    handler: virtualId,
    method: "GET",
    route: input.getRoute.path,
  });
  nitro.options.virtual[virtualId] = [
    `import { defineWebSocketHandler } from ${nitroModulePath};`,
    ...(input.getRoute.cors === undefined
      ? []
      : [
          `import { handleCors } from ${nitroH3ModulePath};`,
          `const cors = ${JSON.stringify(input.getRoute.cors)};`,
        ]),
    `import { dispatchChannelRequest, dispatchChannelWebSocketRequest } from ${dispatchModulePath};`,
    `const config = ${JSON.stringify(input.artifactsConfig)};`,
    `const httpHandler = ${httpHandler};`,
    `export default defineWebSocketHandler(`,
    `  (event) => dispatchChannelWebSocketRequest(event, ${JSON.stringify(webSocketRouteKey)}, config),`,
    `  httpHandler,`,
    `);`,
  ].join("\n");
}

function addRejectedWebSocketUpgradeHandler(
  nitro: Pick<ChannelRouteNitro, "options">,
  path: string,
): void {
  const virtualId = `${ORCEL_CHANNEL_VIRTUAL_ID_PREFIX}WEBSOCKET-REJECT ${path}`;
  const nitroModulePath = stringifyEsmImportSpecifier(resolvePackageDependencyPath("nitro"));

  nitro.options.handlers.push({
    handler: virtualId,
    method: "GET",
    route: path,
  });
  nitro.options.virtual[virtualId] = [
    `import { defineWebSocketHandler } from ${nitroModulePath};`,
    `export default defineWebSocketHandler({`,
    `  upgrade() { throw new Response(null, { status: 404 }); },`,
    `}, () => new Response(null, { status: 404 }));`,
  ].join("\n");
}

function addChannelCorsPreflightHandler(
  nitro: Pick<ChannelRouteNitro, "options">,
  route: ApplicationChannelPreflightRoute,
): void {
  const routeKey = createChannelRouteKey(route);
  const virtualId = `${ORCEL_CHANNEL_VIRTUAL_ID_PREFIX}${routeKey}`;
  const nitroH3ModulePath = stringifyEsmImportSpecifier(resolvePackageDependencyPath("nitro/h3"));

  nitro.options.handlers.push({
    handler: virtualId,
    method: "OPTIONS",
    route: route.path,
  });
  nitro.options.virtual[virtualId] = [
    `import { handleCors } from ${nitroH3ModulePath};`,
    `const cors = ${JSON.stringify(route.cors)};`,
    `export default (event) => {`,
    `  const corsResponse = handleCors(event, cors);`,
    `  if (corsResponse !== false) return corsResponse;`,
    `  return new Response(null, { status: 204 });`,
    `};`,
  ].join("\n");
}
