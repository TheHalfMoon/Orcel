import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import type { Locator, Page } from "playwright-core";
import { clickAndLoad } from "./actions/click-load.js";
import { MAX_REFUSALS, RefusalLedger, watchNavigation, type WatchedPage } from "./refusals.js";
import { NavigationError } from "./worker.js";

/// A page whose main frame and events the test drives.
function page() {
  const events = new EventEmitter();
  const main = { name: "main" };
  const child = { name: "child" };
  const stub = {
    on: (event: string, listener: (...args: unknown[]) => void) => events.on(event, listener),
    off: (event: string, listener: (...args: unknown[]) => void) => events.off(event, listener),
    mainFrame: () => main
  };
  const request = (url: string, frame: object = main, navigation = true) => ({
    url: () => url,
    isNavigationRequest: () => navigation,
    frame: () => frame
  });
  return {
    stub: stub as unknown as WatchedPage,
    events,
    main,
    child,
    failed: (url: string, frame: object = main, navigation = true) => events.emit("requestfailed", request(url, frame, navigation)),
    listeners: () => events.listenerCount("requestfailed")
  };
}

const reason = (expected: string) => (error: unknown) => error instanceof NavigationError && error.reason === expected;

test("a navigation Orcel refused is Orcel's; an engine cancellation with no Orcel refusal is not", () => {
  const ledger = new RefusalLedger();

  // Orcel's route refused the main-frame request it then saw fail.
  const refused = page();
  const watch = watchNavigation(refused.stub, ledger);
  ledger.record("http://fixture.test/", null);
  refused.failed("http://fixture.test/");
  assert.equal(watch.refusedByOrcel("http://fixture.test/"), true);
  watch.stop();
  assert.equal(refused.listeners(), 0, "the watch stops listening");

  // The engine cancelled the navigation (Edge 157's HTTPS upgrade): the
  // same error, but no refusal of Orcel's matches it.
  const cancelled = page();
  const engine = watchNavigation(cancelled.stub, ledger);
  cancelled.failed("http://fixture.test/");
  assert.equal(engine.refusedByOrcel("http://fixture.test/"), false, "an earlier refusal of the same URL is not this navigation's");
  engine.stop();

  // With no failed request reported, the navigation's own URL is checked.
  const silent = page();
  const fallback = watchNavigation(silent.stub, ledger);
  assert.equal(fallback.refusedByOrcel("https://fixture.test/a"), false);
  ledger.record("https://fixture.test/a#top");
  assert.equal(fallback.refusedByOrcel("https://fixture.test/a"), true, "a fragment never decides");
  fallback.stop();
});

test("only main-frame navigation failures, or a refusal of the main frame's document, are attributed", () => {
  const ledger = new RefusalLedger();
  const view = page();
  const watch = watchNavigation(view.stub, ledger);
  // Orcel refused a subresource and a child frame; the engine failed the
  // main-frame navigation itself.
  ledger.record("https://fixture.test/pixel.gif");
  ledger.record("https://other.test/frame", view.child);
  view.failed("https://fixture.test/pixel.gif", view.main, false);
  view.failed("https://other.test/frame", view.child);
  view.failed("https://fixture.test/next");
  assert.equal(watch.refusedByOrcel(), false);
  // A redirect hop of the main frame's document that Orcel refused (the
  // guard records it with the main frame), whatever URL the engine reports.
  ledger.record("https://elsewhere.test/hop", view.main);
  assert.equal(watch.refusedByOrcel(), true);
  watch.stop();
});

test("the ledger is bounded: a dropped refusal can only turn denied into failed", () => {
  const ledger = new RefusalLedger();
  const view = page();
  const watch = watchNavigation(view.stub, ledger);
  ledger.record("https://fixture.test/refused");
  for (let i = 0; i < MAX_REFUSALS; i += 1) ledger.record(`https://fixture.test/sub/${i}`);
  assert.equal(ledger.size, MAX_REFUSALS);
  view.failed("https://fixture.test/refused");
  assert.equal(watch.refusedByOrcel(), false);
  watch.stop();
});

/// An activation's page: the click starts a main-frame navigation that ends
/// on the engine's error page after `fail` runs.
function activation(fail: (view: ReturnType<typeof page>) => void) {
  const view = page();
  let url = "https://fixture.test/";
  const stub = Object.assign(view.stub, {
    url: () => url,
    waitForEvent: async () => view.main,
    waitForLoadState: async () => {}
  });
  const target = {
    click: async () => {
      fail(view);
      url = "chrome-error://chromewebdata/";
    }
  };
  return { page: stub as unknown as Page, target: target as unknown as Locator, view };
}

test("an activation that lands on the error page is denied only for Orcel's refusal", async () => {
  const ledger = new RefusalLedger();
  const refused = activation((view) => {
    ledger.record("https://fixture.test/next", view.main);
    view.failed("https://fixture.test/next");
  });
  await assert.rejects(clickAndLoad(refused.page, refused.target, ledger), reason("denied"));
  assert.equal(refused.view.listeners(), 0);

  const cancelled = activation((view) => view.failed("https://fixture.test/next"));
  await assert.rejects(clickAndLoad(cancelled.page, cancelled.target, ledger), reason("failed"));
  assert.equal(cancelled.view.listeners(), 0);
});
