export const KAF_SHARED_SERVER_FUNCTION_PATH = "kaf/__server.func";

/** Route Nitro's Vercel preset emits as the queue-triggered workflow function. */
export const KAF_WORKFLOW_FLOW_ROUTE_PATH = "/.well-known/workflow/v1/flow";

const KAF_SHARED_SERVER_ROUTE_DESTINATION = "/kaf/__server";
const KAF_VERCEL_FUNCTION_PREFIXES = ["kaf/", ".well-known/workflow/"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isKafVercelFunctionPath(path: string): boolean {
  return KAF_VERCEL_FUNCTION_PREFIXES.some((prefix) => path.startsWith(prefix));
}

export function normalizeKafVercelRoutes(
  routes: readonly unknown[],
  _servicePrefix: string | undefined,
): unknown[] {
  return routes.filter(isKafVercelRoute).map(normalizeKafVercelRoute);
}

function isKafVercelRoute(route: unknown): boolean {
  if (!isRecord(route)) {
    return true;
  }

  if ("handle" in route) {
    return true;
  }

  const src = typeof route.src === "string" ? route.src : "";
  const dest = typeof route.dest === "string" ? route.dest : "";

  return isKafVercelRoutePath(src) || isKafVercelRoutePath(dest);
}

function isKafVercelRoutePath(path: string): boolean {
  return path.includes("/kaf/v1") || path.includes("/.well-known/workflow/");
}

function isKafProtocolRoutePath(path: string): boolean {
  return path.includes("/kaf/v1");
}

function normalizeKafVercelRoute(route: unknown): unknown {
  if (!isRecord(route) || "handle" in route || typeof route.src !== "string") {
    return route;
  }

  const shouldUseSharedServerFunction =
    isKafProtocolRoutePath(route.src) ||
    (typeof route.dest === "string" && isKafProtocolRoutePath(route.dest));
  const nextRoute: Record<string, unknown> = {
    ...route,
  };

  if (shouldUseSharedServerFunction) {
    nextRoute.dest = KAF_SHARED_SERVER_ROUTE_DESTINATION;
  }

  return nextRoute;
}
