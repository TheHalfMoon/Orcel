import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import { NavigationError } from "../worker.js";
import { enterAndSettle, type EnterPage } from "./enter-load.js";

/// A page whose main frame and events the test drives.
function page(start: string) {
  const events = new EventEmitter();
  const main = { name: "main" };
  const other = { name: "child" };
  let url = start;
  let loads = 0;
  const stub = {
    on: (event: string, listener: (...args: unknown[]) => void) => events.on(event, listener),
    off: (event: string, listener: (...args: unknown[]) => void) => events.off(event, listener),
    mainFrame: () => main,
    url: () => url,
    waitForLoadState: async () => {
      loads += 1;
    }
  };
  const request = (frame: object, navigation = true) => ({ isNavigationRequest: () => navigation, frame: () => frame });
  return {
    stub: stub as unknown as EnterPage,
    events,
    main,
    other,
    loads: () => loads,
    // A main-frame submission: its request, then its commit at `to`.
    submit: (to: string) => {
      events.emit("request", request(main));
      url = to;
      events.emit("framenavigated", main);
    },
    // A request the host refused: it fails, the error page commits.
    refuse: () => {
      events.emit("request", request(main));
      events.emit("requestfailed", request(main));
      url = "chrome-error://chromewebdata/";
      events.emit("framenavigated", main);
    },
    request,
    listeners: () => ["request", "requestfailed", "framenavigated", "popup"].map((name) => events.listenerCount(name))
  };
}

const reason = (expected: string) => (error: unknown) => error instanceof NavigationError && error.reason === expected;

test("SG-000122 A6: an Enter that opens nothing settles unchanged; one that submits waits for the new document", async () => {
  const quiet = page("https://fixture.test/enter-form");
  // A subresource or a child frame's navigation is not the page's document.
  const press = async () => {
    quiet.events.emit("request", quiet.request(quiet.main, false));
    quiet.events.emit("request", quiet.request(quiet.other));
    quiet.events.emit("framenavigated", quiet.other);
  };
  assert.deepEqual(await enterAndSettle(quiet.stub, press, 20), { url: "https://fixture.test/enter-form", navigated: false });
  assert.equal(quiet.loads(), 0);
  assert.deepEqual(quiet.listeners(), [0, 0, 0, 0], "every listener is removed");

  const submitting = page("https://fixture.test/enter-form");
  const submitted = await enterAndSettle(submitting.stub, async () => submitting.submit("https://fixture.test/order"), 1_000);
  assert.deepEqual(submitted, { url: "https://fixture.test/order", navigated: true });
  assert.equal(submitting.loads(), 1, "the new document's load is awaited");
  assert.deepEqual(submitting.listeners(), [0, 0, 0, 0]);
});

test("SG-000122 A6: a refused submission, a popup and a refused element are typed refusals", async () => {
  const refused = page("https://fixture.test/enter-form");
  await assert.rejects(enterAndSettle(refused.stub, async () => refused.refuse(), 1_000), reason("denied"));
  assert.deepEqual(refused.listeners(), [0, 0, 0, 0]);

  const popping = page("https://fixture.test/enter-form");
  let closed = 0;
  const popup = { close: async () => void (closed += 1) };
  await assert.rejects(
    enterAndSettle(popping.stub, async () => void popping.events.emit("popup", popup), 20),
    reason("denied")
  );
  assert.equal(closed, 1, "a popup is closed at once");

  const element = page("https://fixture.test/enter-form");
  await assert.rejects(
    enterAndSettle(element.stub, async () => {
      throw new NavigationError("denied");
    }),
    reason("denied")
  );
  assert.deepEqual(element.listeners(), [0, 0, 0, 0]);
});
