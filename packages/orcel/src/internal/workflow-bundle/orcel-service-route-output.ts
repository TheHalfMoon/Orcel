export const ORCEL_SHARED_SERVER_FUNCTION_PATH = "orcel/__server.func";

/** Route Nitro's Vercel preset emits as the queue-triggered workflow function. */
export const ORCEL_WORKFLOW_FLOW_ROUTE_PATH = "/.well-known/workflow/v1/flow";

const ORCEL_SHARED_SERVER_ROUTE_DESTINATION = "/orcel/__server";
const ORCEL_VERCEL_FUNCTION_PREFIXES = ["orcel/", ".well-known/workflow/"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isOrcelVercelFunctionPath(path: string): boolean {
  return ORCEL_VERCEL_FUNCTION_PREFIXES.some((prefix) => path.startsWith(prefix));
}

export function normalizeOrcelVercelRoutes(
  routes: readonly unknown[],
  _servicePrefix: string | undefined,
): unknown[] {
  return routes.filter(isOrcelVercelRoute).map(normalizeOrcelVercelRoute);
}

function isOrcelVercelRoute(route: unknown): boolean {
  if (!isRecord(route)) {
    return true;
  }

  if ("handle" in route) {
    return true;
  }

  const src = typeof route.src === "string" ? route.src : "";
  const dest = typeof route.dest === "string" ? route.dest : "";

  return isOrcelVercelRoutePath(src) || isOrcelVercelRoutePath(dest);
}

function isOrcelVercelRoutePath(path: string): boolean {
  return path.includes("/orcel/v1") || path.includes("/.well-known/workflow/");
}

function isOrcelProtocolRoutePath(path: string): boolean {
  return path.includes("/orcel/v1");
}

function normalizeOrcelVercelRoute(route: unknown): unknown {
  if (!isRecord(route) || "handle" in route || typeof route.src !== "string") {
    return route;
  }

  const shouldUseSharedServerFunction =
    isOrcelProtocolRoutePath(route.src) ||
    (typeof route.dest === "string" && isOrcelProtocolRoutePath(route.dest));
  const nextRoute: Record<string, unknown> = {
    ...route,
  };

  if (shouldUseSharedServerFunction) {
    nextRoute.dest = ORCEL_SHARED_SERVER_ROUTE_DESTINATION;
  }

  return nextRoute;
}
