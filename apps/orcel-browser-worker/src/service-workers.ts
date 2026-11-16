// Service-worker and shared-worker denial (closes #301).
//
// Playwright's `serviceWorkers: "block"` only replaces
// `navigator.serviceWorker.register` with an init script, so a page can
// register a real worker through `ServiceWorkerContainer.prototype.register`,
// and with "block" the script fetch is invisible to routing. The worker
// therefore launches with `serviceWorkers: "allow"` (which makes every
// service-worker request, including the script fetch, visible to context
// routes) and installs this route before any page navigates: every request
// carrying `Service-Worker: script` is aborted, so no registration can
// complete. The future SG-000075 policy route must keep this denial.

import type { BrowserContext, Route } from "playwright-core";
import { documentFrameOf, type RefusalLedger } from "./refusals.js";

/// `refusals` records each refusal (refusals.ts); installRoutes passes its own.
export async function denyServiceWorkerScripts(context: BrowserContext, refusals?: RefusalLedger): Promise<void> {
  await context.route("**/*", async (route: Route) => {
    const headers = await route.request().allHeaders();
    // Shared workers too: their own requests are never routed (measured),
    // so their scripts are refused. The engine sets Sec-Fetch-Dest; a page
    // cannot forge it.
    const destination = headers["sec-fetch-dest"];
    if (headers["service-worker"] === "script" || destination === "serviceworker" || destination === "sharedworker") {
      refusals?.record(route.request().url(), documentFrameOf(route.request()));
      await route.abort("blockedbyclient");
      return;
    }
    await route.fallback();
  });
}
