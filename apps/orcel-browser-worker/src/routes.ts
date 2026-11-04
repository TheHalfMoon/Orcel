// SG-000108 slice 3a: the worker's complete route stack, installed once per
// engine lifetime before any navigation. Playwright runs routes newest
// first, so the order below is part of the contract (pinned by a native
// probe that runs this function with an allow-everything policy):
//
// 1. denyServiceWorkerScripts (registered last, runs first): no request
//    carrying `Service-Worker: script` ever reaches the policy.
// 2. The policy route: every other request is described to the host and
//    continues only on an explicit allow; anything else is aborted.
// WebSockets are refused outright (SG-000075 denies them). Redirect hops,
// which routes never see, are decided through redirect-guard.ts, attached
// to every page; `guardReady` lets the caller wait for a page's guard
// before navigating it.

import type { BrowserContext, Page } from "playwright-core";
import { attachRedirectGuard, type RedirectGuard } from "./redirect-guard.js";
import { classifyRequest, requestDetail } from "./routing.js";
import { traceMark } from "./navigation-trace.js";
import { denyServiceWorkerScripts } from "./service-workers.js";
import type { RoutePolicy } from "./worker.js";

export interface RouteStack {
  /// Resolves with `page`'s redirect guard once attached (rejects if it
  /// cannot be attached).
  guardReady(page: Page): Promise<RedirectGuard>;
}

export async function installRoutes(
  context: BrowserContext,
  primary: () => Page,
  policy: RoutePolicy
): Promise<RouteStack> {
  await context.routeWebSocket(/.*/, async (socket) => {
    await socket.close({ code: 1008, reason: "denied" });
  });
  await context.route("**/*", async (route) => {
    traceMark("route_entered");
    let allow = false;
    try {
      const page = primary();
      const request = route.request();
      allow = await policy.decide({ ...classifyRequest(request, page, () => page.url()), detail: requestDetail(request) });
    } catch {
      allow = false;
    }
    traceMark(allow ? "route_allowed" : "route_denied");
    if (allow) {
      await route.continue();
      traceMark("route_continued");
    } else {
      await route.abort("blockedbyclient");
    }
  });
  await denyServiceWorkerScripts(context);

  const guards = new WeakMap<Page, Promise<RedirectGuard>>();
  const guard = (page: Page): Promise<RedirectGuard> => {
    let ready = guards.get(page);
    if (!ready) {
      ready = attachRedirectGuard(context, page, policy);
      guards.set(page, ready);
    }
    return ready;
  };
  // Every page (including popups) gets a guard; a page whose guard cannot
  // be attached is closed rather than left unguarded.
  context.on("page", (page) => {
    guard(page).catch(() => page.close().catch(() => {}));
  });
  for (const page of context.pages()) await guard(page);
  return { guardReady: guard };
}
