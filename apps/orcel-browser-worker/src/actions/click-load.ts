// The approved activation's click and the load it starts (moved out of
// entry.ts so a native test can drive it directly, #438).

import type { Locator, Page } from "playwright-core";
import { NavigationError } from "../worker.js";
import { isOcclusion } from "./targets.js";

export async function clickAndLoad(page: Page, target: Locator): Promise<{ url: string; status: number }> {
  let status = 0;
  const onResponse = (response: import("playwright-core").Response) => {
    const request = response.request();
    if (request.isNavigationRequest() && request.frame() === page.mainFrame()) status = response.status();
  };
  page.on("response", onResponse);
  // A click that opens a popup instead of navigating the page is not the
  // approved activation: it fails at once (the popup is closed) rather than
  // waiting out the navigation timeout.
  let onPopup: ((popup: Page) => void) | undefined;
  const popped = new Promise<never>((_, reject) => {
    onPopup = (popup) => {
      void popup.close().catch(() => {});
      reject(new NavigationError("denied"));
    };
    page.on("popup", onPopup);
  });
  popped.catch(() => {});
  try {
    const navigated = page.waitForEvent("framenavigated", {
      predicate: (frame) => frame === page.mainFrame(),
      timeout: 30_000
    });
    try {
      // #438: noWaitAfter, like the download click. Without it Playwright
      // waits, inside this 5 s budget, for the navigation the click started
      // to commit, so a slow commit on a loaded runner threw a timeout that
      // was reported as "failed" although the click had happened and the
      // page was moving. The navigation is awaited below, on its own budget.
      await target.click({ timeout: 5_000, noWaitAfter: true });
    } catch (error) {
      navigated.catch(() => {});
      // BR-04: covered by another element: nothing was clicked.
      throw new NavigationError(isOcclusion(error) ? "occluded" : "failed");
    }
    await Promise.race([navigated, popped]);
    navigated.catch(() => {});
    await page.waitForLoadState("load", { timeout: 30_000 });
  } catch (error) {
    if (error instanceof NavigationError) throw error;
    if ((error as Error).name === "TimeoutError") throw new NavigationError("timeout");
    throw new NavigationError("failed");
  } finally {
    page.off("response", onResponse);
    if (onPopup) page.off("popup", onPopup);
  }
  // A refused navigation lands on Chromium's error page.
  if (page.url().startsWith("chrome-error:")) throw new NavigationError("denied");
  return { url: page.url(), status };
}
