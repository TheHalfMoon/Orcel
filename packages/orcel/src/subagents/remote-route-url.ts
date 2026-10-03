import { joinOrcelRoutePath } from "#shared/orcel-route-path.js";

/** Joins an orcel route to a remote agent base URL without dropping its path prefix. */
export function createRemoteAgentRouteUrl(baseUrl: string, routePath: string): string {
  const route = new URL(routePath, "http://orcel.local");
  const url = new URL(baseUrl);
  url.pathname = joinOrcelRoutePath(url.pathname, route.pathname);
  url.search = route.search;
  url.hash = route.hash;
  return url.toString();
}
