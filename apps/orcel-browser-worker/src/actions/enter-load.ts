// SG-000122 slice A6: an approved Enter and the one document its submission
// may open. The host decides every request under its Enter route rule (one
// top-level document, a GET or POST on the committed origin, once; redirects
// that stay on it); this file only tells the host what the main frame did
// after the key: nothing (no navigation request within the settle window),
// or a committed new document, awaited to its load like an activation
// (click-load.ts). A popup is closed at once, and a refused navigation that
// lands on the engine's error page is reported "denied".

import type { Frame, Page, Request } from "playwright-core";
import { NavigationError } from "../worker.js";

/// How long after the key a submission's request may start. A form's
/// implicit submission is queued as the key is handled, so its request
/// starts well within this; a page script that submits later is not this
/// Enter's submission (the host's ordinary rules apply to it afterwards).
export const ENTER_SETTLE_MS = 1_500;
/// The commit and load budgets, as an activation's (under the host's
/// WORKER_ACTIVATION_TIMEOUT).
export const ENTER_LOAD_MS = 30_000;
/// After a refused request, how long the engine may take to show its error
/// page before the refusal is reported anyway.
export const ENTER_REFUSAL_GRACE_MS = 2_000;

/// The page surface an Enter watches (a Playwright `Page`, or a test stub).
export type EnterPage = Pick<Page, "on" | "off" | "mainFrame" | "url" | "waitForLoadState">;


/// Presses (through `press`, which performs the approved key and rejects
/// with NavigationError when the element is refused) and settles: resolves
/// `{ navigated: false }` when no main-frame navigation began within the
/// settle window, `{ navigated: true }` once a new main-frame document
/// committed and loaded. Rejects "denied" for a popup or the engine's error
/// page (a refused request), "timeout" when the document never committed or
/// loaded in time.
export async function enterAndSettle(
  page: EnterPage,
  press: () => Promise<void>,
  settleMs = ENTER_SETTLE_MS
): Promise<{ url: string; navigated: boolean }> {
  let markBegun: () => void = () => {};
  const begun = new Promise<"begun">((resolve) => (markBegun = () => resolve("begun")));
  let markCommitted: () => void = () => {};
  const committed = new Promise<"committed">((resolve) => (markCommitted = () => resolve("committed")));
  let markFailed: () => void = () => {};
  const failed = new Promise<"failed">((resolve) => (markFailed = () => resolve("failed")));
  let popped = false;
  // Every timer is cleared on the way out, so none outlives the Enter.
  const timers: Array<ReturnType<typeof setTimeout>> = [];
  const delay = (ms: number) => new Promise<"late">((resolve) => timers.push(setTimeout(() => resolve("late"), ms)));
  const main = page.mainFrame();
  const onRequest = (request: Request) => {
    if (request.isNavigationRequest() && request.frame() === main) markBegun();
  };
  const onRequestFailed = (request: Request) => {
    if (request.isNavigationRequest() && request.frame() === main) markFailed();
  };
  const onNavigated = (frame: Frame) => {
    if (frame === main) {
      markBegun();
      markCommitted();
    }
  };
  // Popups stay closed (SG-000108 A4): a submission into a new window is
  // not this page's document.
  const onPopup = (popup: Page) => {
    popped = true;
    void popup.close().catch(() => {});
  };
  page.on("request", onRequest);
  page.on("requestfailed", onRequestFailed);
  page.on("framenavigated", onNavigated);
  page.on("popup", onPopup);
  try {
    await press();
    if ((await Promise.race([begun, delay(settleMs)])) === "late") {
      if (popped) throw new NavigationError("denied");
      return { url: page.url(), navigated: false };
    }
    const settled = await Promise.race([committed, failed, delay(ENTER_LOAD_MS)]);
    if (settled === "late") throw new NavigationError("timeout");
    if (settled === "failed") {
      // A refused (or failed) request: the engine shows its error page,
      // which commits shortly; either way this is not the page's document.
      await Promise.race([committed, delay(ENTER_REFUSAL_GRACE_MS)]);
      throw new NavigationError("denied");
    }
    try {
      await page.waitForLoadState("load", { timeout: ENTER_LOAD_MS });
    } catch {
      throw new NavigationError("timeout");
    }
  } finally {
    for (const timer of timers) clearTimeout(timer);
    page.off("request", onRequest);
    page.off("requestfailed", onRequestFailed);
    page.off("framenavigated", onNavigated);
    page.off("popup", onPopup);
  }
  // A refused navigation lands on Chromium's error page.
  if (popped || page.url().startsWith("chrome-error:")) throw new NavigationError("denied");
  return { url: page.url(), navigated: true };
}
