import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { admitPopup, boundedUrl, MAX_TABS, NAVIGATION_WATCH_MS, NavigationWatch, TabRegistry, type WatchedPage, type WatchedRequest, type WatchedResponse } from "./tabs.js";

class FakeTabPage {
  closed = false;
  constructor(public address: string) {}
  url(): string {
    return this.address;
  }
  isClosed(): boolean {
    return this.closed;
  }
}

test("OB-03: tabs get ids in order, one is active, and the cap holds", () => {
  const tabs = new TabRegistry<FakeTabPage>(2048);
  const pages = Array.from({ length: MAX_TABS + 1 }, (_, i) => new FakeTabPage(`https://fixture.test/${i}`));
  const first = pages[0] as FakeTabPage;
  assert.equal(tabs.add(first), 1);
  // The first tab is active until another is chosen.
  assert.equal(tabs.active, 1);
  assert.equal(tabs.activePage(), first);
  for (let i = 1; i < MAX_TABS; i++) assert.equal(tabs.add(pages[i] as FakeTabPage), i + 1);
  assert.equal(tabs.size, MAX_TABS);
  // Past the cap nothing is added.
  assert.equal(tabs.add(pages[MAX_TABS] as FakeTabPage), null);
  assert.equal(tabs.size, MAX_TABS);
  assert.equal(tabs.active, 1);
  assert.ok(tabs.activate(3));
  assert.equal(tabs.activePage(), pages[2]);
  assert.equal(tabs.activate(42), false);
  assert.equal(tabs.active, 3);
  assert.deepEqual(tabs.list().map((info) => info.tab), [1, 2, 3, 4, 5, 6, 7, 8]);
});

test("OB-03: a navigation's page takes over its tab; closing the active tab activates the newest", () => {
  const tabs = new TabRegistry<FakeTabPage>(2048);
  const a = new FakeTabPage("https://fixture.test/a");
  const b = new FakeTabPage("https://fixture.test/b");
  const c = new FakeTabPage("https://fixture.test/c");
  tabs.add(a);
  tabs.add(b);
  tabs.add(c);
  tabs.activate(2);
  const fresh = new FakeTabPage("https://fixture.test/b2");
  assert.ok(tabs.replace(2, fresh));
  assert.equal(tabs.idOf(fresh), 2);
  assert.equal(tabs.idOf(b), null);
  assert.equal(tabs.replace(9, fresh), false);
  assert.ok(tabs.remove(2));
  assert.equal(tabs.active, 3);
  assert.ok(tabs.remove(1));
  assert.equal(tabs.active, 3);
  assert.equal(tabs.remove(1), false);
  assert.ok(tabs.remove(3));
  assert.equal(tabs.active, null);
  assert.equal(tabs.activePage(), null);
  // Ids are never reused within a lifetime.
  assert.equal(tabs.add(a), 4);
});

test("OB-03: tab reports carry only bounded https or blank URLs", () => {
  const tabs = new TabRegistry<FakeTabPage>(64);
  const closed = new FakeTabPage("https://fixture.test/x");
  closed.closed = true;
  for (const page of [
    new FakeTabPage("https://fixture.test/a?q=1"),
    new FakeTabPage("about:blank"),
    new FakeTabPage("chrome-error://chromewebdata/"),
    new FakeTabPage(`https://fixture.test/${"x".repeat(80)}`),
    new FakeTabPage("https://fixture.test/\u0007"),
    closed
  ]) {
    tabs.add(page);
  }
  assert.deepEqual(
    tabs.list().map((info) => info.url),
    ["https://fixture.test/a?q=1", "about:blank", "", "", "", ""]
  );
  assert.equal(boundedUrl("http://fixture.test/", 2048), "");
  assert.equal(boundedUrl("javascript:alert(1)", 2048), "");
});

class FakeWatchedPage extends EventEmitter {
  readonly main = { name: "main" };
  mainFrame(): unknown {
    return this.main;
  }
}

function request(frame: unknown, navigation = true, url = "https://fixture.test/next"): WatchedRequest {
  return { isNavigationRequest: () => navigation, frame: () => frame, url: () => url };
}

function response(req: WatchedRequest, url: string, status = 200): WatchedResponse {
  return { request: () => req, url: () => url, status: () => status };
}

test("OB-03: a main-frame navigation is in flight from its request until it loads or fails", () => {
  const page = new FakeWatchedPage();
  let now = 1_000;
  const watch = new NavigationWatch(page as unknown as WatchedPage, () => now);
  assert.equal(watch.loading, false);
  // A subresource or a frame's navigation does not count.
  page.emit("request", request(page.main, false));
  page.emit("request", request({ name: "child" }, true));
  assert.equal(watch.loading, false);
  page.emit("request", request(page.main));
  assert.equal(watch.loading, true);
  page.emit("load");
  assert.equal(watch.loading, false);
  page.emit("request", request(page.main));
  page.emit("domcontentloaded");
  assert.equal(watch.loading, false);
  page.emit("request", request(page.main));
  page.emit("requestfailed", request(page.main));
  assert.equal(watch.loading, false);
  // One that never settles stops counting.
  page.emit("request", request(page.main));
  now += NAVIGATION_WATCH_MS - 1;
  assert.equal(watch.loading, true);
  now += 1;
  assert.equal(watch.loading, false);
});

test("OB-03: a popup is admitted only once its first document was allowed and answered over https", async () => {
  const admit = (act: (page: FakeWatchedPage) => void, timeoutMs = 1_000) => {
    const page = new FakeWatchedPage();
    const pending = admitPopup(page as unknown as WatchedPage, timeoutMs);
    act(page);
    return { pending, page };
  };
  const allowed = admit((page) => page.emit("response", response(request(page.main), "https://fixture.test/popup")));
  assert.equal(await allowed.pending, true);
  // Its listeners are gone afterwards.
  assert.equal(allowed.page.listenerCount("response") + allowed.page.listenerCount("requestfailed") + allowed.page.listenerCount("close"), 0);
  // The host refused it (blocked by the route stack): closed.
  assert.equal(await admit((page) => page.emit("requestfailed", request(page.main))).pending, false);
  // A redirect hop is not the document; the refused next hop decides.
  const redirected = admit((page) => {
    const req = request(page.main);
    page.emit("response", response(req, "https://fixture.test/hop", 302));
    page.emit("requestfailed", req);
  });
  assert.equal(await redirected.pending, false);
  // A subresource's response or a child frame's document decides nothing.
  const late = admit((page) => {
    page.emit("response", response(request(page.main, false), "https://fixture.test/style.css"));
    page.emit("response", response(request({ name: "child" }), "https://fixture.test/frame"));
    page.emit("response", response(request(page.main), "https://fixture.test/popup"));
  });
  assert.equal(await late.pending, true);
  assert.equal(await admit((page) => page.emit("close")).pending, false);
  assert.equal(await admit((page) => page.emit("response", response(request(page.main), "http://fixture.test/"))).pending, false);
  // Nothing arrives (a blank popup a script writes into): closed.
  assert.equal(await admit(() => {}, 20).pending, false);
});
