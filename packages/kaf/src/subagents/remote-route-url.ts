import { joinKafRoutePath } from "#shared/kaf-route-path.js";

/** Joins an kaf route to a remote agent base URL without dropping its path prefix. */
export function createRemoteAgentRouteUrl(baseUrl: string, routePath: string): string {
  const route = new URL(routePath, "http://kaf.local");
  const url = new URL(baseUrl);
  url.pathname = joinKafRoutePath(url.pathname, route.pathname);
  url.search = route.search;
  url.hash = route.hash;
  return url.toString();
}
