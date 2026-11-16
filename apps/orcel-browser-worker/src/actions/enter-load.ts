// SG-000122 slice A6: an approved Enter and the one document its submission
// may open. The host decides every request under its Enter route rule (one
// top-level document, a GET or POST on the committed origin, once; redirects
// that stay on it); this file only tells the host what the main frame did
// after the key: nothing (no navigation request within the settle window),
// or a committed new document, awaited to its load like an activation
// (click-load.ts). A popup is closed at once, and a navigation Orcel refused
// (refusals.ts) that lands on the engine's error page is reported "denied";
// a navigation that failed without an Orcel refusal (an engine cancellation,
// a network failure) is reported "failed". The host reads either against its
// own route record (refused before anything opened, or outcome unknown),
// never as "nothing happened".

import type { Page, Request } from "playwright-core";
import { watchNavigation, type RefusalLedger } from "../refusals.js";
import { NavigationError } from "../worker.js";

/// How long after the key a submission's request may start. A form's
/// implicit submission is queued as the key is handled, so its request
/// starts well within this; a page script that submits later is not this
/// Enter's submission. The window is the worker's choice, so the host does
/// not rely on it: after an Enter that committed no document it keeps the
/// no-document rule until the next observation or approved navigation, and
/// such a late submission is refused.
export const ENTER_SETTLE_MS = 1_500;
/// The commit and load budgets, as an activation's (under the host's
/// WORKER_ACTIVATION_TIMEOUT).
export const ENTER_LOAD_MS = 30_000;
/// After a refused request, how long the engine may take to show its error
/// page before the refusal is reported anyway.
export const ENTER_REFUSAL_GRACE_MS = 2_000;
/// How long the Enter waits for the popups it closed to be gone.
export const ENTER_POPUP_CLOSE_MS = 1_000;

/// The page surface an Enter watches (a Playwright `Page`, or a test stub).
export type EnterPage = Pick<Page, "on" | "off" | "mainFrame" | "url" | "waitForLoadState">;


/// Presses (through `press`, which performs the approved key and rejects
/// with NavigationError when the element is refused) and settles: resolves
/// `{ navigated: false }` when no main-frame navigation began within the
/// settle window, `{ navigated: true }` once a new main-frame document
/// committed and loaded. Rejects "denied" for a popup opened before any
/// main-frame navigation began, or a main-frame navigation Orcel refused
/// (`refusals`), "failed" for one that failed without an Orcel refusal,
/// "timeout" when the document never committed or loaded in time.
///
/// Only a new document counts as committed: the main frame's
/// DOMContentLoaded, which a same-document navigation (pushState, a
/// fragment) never fires. A same-document navigation only moves the URL,
/// which the host compares itself. A popup the result page opens after the
/// submission's navigation began is closed (and refused by the host, which
/// records it apart); it does not make the committed submission "denied".
export async function enterAndSettle(
  page: EnterPage,
  refusals: RefusalLedger,
  press: () => Promise<void>,
  settleMs = ENTER_SETTLE_MS
): Promise<{ url: string; navigated: boolean }> {
  // Started before the key, so every refusal the key causes is "since".
  const watch = watchNavigation(page, refusals);
  let began = false;
  let markBegun: () => void = () => {};
  const begun = new Promise<"begun">((resolve) => (markBegun = () => {
    began = true;
    resolve("begun");
  }));
  let markCommitted: () => void = () => {};
  const committed = new Promise<"committed">((resolve) => (markCommitted = () => resolve("committed")));
  let markFailed: () => void = () => {};
  const failed = new Promise<"failed">((resolve) => (markFailed = () => resolve("failed")));
  // A popup before the main frame's navigation began: the key's own
  // effect, not a document of this page.
  let poppedEarly = false;
  const closing: Array<Promise<void>> = [];
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
  // A new main-frame document (also one that made no request the host saw,
  // such as about:blank: the host then finds no admitted document).
  const onDocument = () => {
    markBegun();
    markCommitted();
  };
  // Popups stay closed (SG-000108 A4): a submission into a new window is
  // not this page's document.
  const onPopup = (popup: Page) => {
    if (!began) poppedEarly = true;
    closing.push(popup.close().catch(() => {}));
  };
  page.on("request", onRequest);
  page.on("requestfailed", onRequestFailed);
  page.on("domcontentloaded", onDocument);
  page.on("popup", onPopup);
  try {
    await press();
    if ((await Promise.race([begun, delay(settleMs)])) === "late") {
      if (poppedEarly) throw new NavigationError("denied");
      return { url: page.url(), navigated: false };
    }
    const settled = await Promise.race([committed, failed, delay(ENTER_LOAD_MS)]);
    if (settled === "late") throw new NavigationError("timeout");
    if (settled === "failed") {
      // A refused (or failed) request: the engine shows its error page,
      // which commits shortly; either way this is not the page's document,
      // and only Orcel's own refusal is "denied".
      await Promise.race([committed, delay(ENTER_REFUSAL_GRACE_MS)]);
      throw new NavigationError(watch.refusedByOrcel() ? "denied" : "failed");
    }
    try {
      await page.waitForLoadState("load", { timeout: ENTER_LOAD_MS });
    } catch {
      throw new NavigationError("timeout");
    }
  } finally {
    // Every popup is closed before the Enter answers, within a short bound
    // (the host does not rely on it: it keeps the no-document rule held
    // after an Enter that refused a popup).
    if (closing.length > 0) await Promise.race([Promise.allSettled(closing), delay(ENTER_POPUP_CLOSE_MS)]);
    for (const timer of timers) clearTimeout(timer);
    watch.stop();
    page.off("request", onRequest);
    page.off("requestfailed", onRequestFailed);
    page.off("domcontentloaded", onDocument);
    page.off("popup", onPopup);
  }
  // A popup before the navigation began is Orcel's refusal (it closed it).
  // A refused navigation lands on Chromium's error page; so does one the
  // engine or the network failed.
  if (poppedEarly) throw new NavigationError("denied");
  if (page.url().startsWith("chrome-error:")) throw new NavigationError(watch.refusedByOrcel() ? "denied" : "failed");
  return { url: page.url(), navigated: true };
}
