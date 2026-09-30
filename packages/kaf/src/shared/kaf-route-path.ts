import { KAF_ROUTE_PREFIX } from "#protocol/routes.js";

const KAF_NAMED_AGENT_MOUNT_PATTERN = /^\/kaf\/[a-z0-9][a-z0-9_-]*$/;
const KAF_NAMED_AGENT_PROTOCOL_PATTERN = /^\/kaf\/[a-z0-9][a-z0-9_-]*\/v1$/;

/** Joins an internal kaf route to a public target, including compact named-agent mounts. */
export function joinKafRoutePath(basePath: string, routePath: string): string {
  const base = trimTrailingSlash(basePath);
  const route = routePath.startsWith("/") ? routePath : `/${routePath}`;
  if (route === KAF_ROUTE_PREFIX || route.startsWith(`${KAF_ROUTE_PREFIX}/`)) {
    if (KAF_NAMED_AGENT_MOUNT_PATTERN.test(base)) {
      return `${base}${route.slice("/kaf".length)}`;
    }
    if (KAF_NAMED_AGENT_PROTOCOL_PATTERN.test(base)) {
      return `${base}${route.slice(KAF_ROUTE_PREFIX.length)}`;
    }
  }
  return `${base}${route}`;
}

/** Maps a compact named-agent route back to the internal kaf protocol namespace. */
export function normalizePublicKafRoutePath(path: string): string {
  return path.replace(/^\/kaf\/[a-z0-9][a-z0-9_-]*\/v1(?=\/|$)/, KAF_ROUTE_PREFIX);
}

function trimTrailingSlash(value: string): string {
  if (value === "/") return "";
  return value.endsWith("/") ? value.slice(0, -1) : value;
}
