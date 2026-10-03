import { ORCEL_ROUTE_PREFIX } from "#protocol/routes.js";

const ORCEL_NAMED_AGENT_MOUNT_PATTERN = /^\/orcel\/[a-z0-9][a-z0-9_-]*$/;
const ORCEL_NAMED_AGENT_PROTOCOL_PATTERN = /^\/orcel\/[a-z0-9][a-z0-9_-]*\/v1$/;

/** Joins an internal orcel route to a public target, including compact named-agent mounts. */
export function joinOrcelRoutePath(basePath: string, routePath: string): string {
  const base = trimTrailingSlash(basePath);
  const route = routePath.startsWith("/") ? routePath : `/${routePath}`;
  if (route === ORCEL_ROUTE_PREFIX || route.startsWith(`${ORCEL_ROUTE_PREFIX}/`)) {
    if (ORCEL_NAMED_AGENT_MOUNT_PATTERN.test(base)) {
      return `${base}${route.slice("/orcel".length)}`;
    }
    if (ORCEL_NAMED_AGENT_PROTOCOL_PATTERN.test(base)) {
      return `${base}${route.slice(ORCEL_ROUTE_PREFIX.length)}`;
    }
  }
  return `${base}${route}`;
}

/** Maps a compact named-agent route back to the internal orcel protocol namespace. */
export function normalizePublicOrcelRoutePath(path: string): string {
  return path.replace(/^\/orcel\/[a-z0-9][a-z0-9_-]*\/v1(?=\/|$)/, ORCEL_ROUTE_PREFIX);
}

function trimTrailingSlash(value: string): string {
  if (value === "/") return "";
  return value.endsWith("/") ? value.slice(0, -1) : value;
}
