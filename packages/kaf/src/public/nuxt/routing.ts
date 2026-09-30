import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";

const KAF_NUXT_PRODUCTION_ORIGIN_ENV = "KAF_NUXT_PRODUCTION_ORIGIN";
const KAF_NUXT_PRODUCTION_PORT_ENV = "KAF_NUXT_PRODUCTION_PORT";
const DEFAULT_KAF_NUXT_PRODUCTION_PORT = 4274;

/**
 * Join a route prefix and a path with exactly one separating slash.
 */
export function joinRoutePrefix(prefix: string, path: string): string {
  return `${prefix.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

/**
 * Reduce an origin string to its canonical `protocol://host[:port]` form.
 */
export function normalizeOrigin(origin: string): string {
  return new URL(origin.trim()).origin;
}

/**
 * Resolve the local production port the module proxies to when an kaf service
 * runs alongside a non-Vercel Nuxt deployment. Defaults to
 * {@link DEFAULT_KAF_NUXT_PRODUCTION_PORT}.
 */
export function readLocalProductionPort(): number {
  const configuredPort = process.env[KAF_NUXT_PRODUCTION_PORT_ENV];
  if (configuredPort === undefined || configuredPort.trim().length === 0) {
    return DEFAULT_KAF_NUXT_PRODUCTION_PORT;
  }
  const port = Number.parseInt(configuredPort, 10);
  if (String(port) !== configuredPort.trim() || port < 1 || port > 65_535) {
    throw new Error(`${KAF_NUXT_PRODUCTION_PORT_ENV} must be an integer between 1 and 65535.`);
  }
  return port;
}

/**
 * Resolve the proxy destination for kaf routes in non-Vercel production: an
 * explicit origin override (`KAF_NUXT_PRODUCTION_ORIGIN`) or a local port. On
 * Vercel the module routes at the edge via a Build Output service route
 * instead of proxying.
 */
export function resolveProductionTarget(): string {
  const configuredOrigin = process.env[KAF_NUXT_PRODUCTION_ORIGIN_ENV];
  if (configuredOrigin !== undefined && configuredOrigin.trim().length > 0) {
    return joinRoutePrefix(normalizeOrigin(configuredOrigin), KAF_ROUTE_PREFIX);
  }

  const localOrigin = `http://127.0.0.1:${String(readLocalProductionPort())}`;
  return joinRoutePrefix(localOrigin, KAF_ROUTE_PREFIX);
}
