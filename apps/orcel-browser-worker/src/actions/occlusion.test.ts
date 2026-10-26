import assert from "node:assert/strict";
import { test } from "node:test";
import { isOcclusion } from "./targets.js";

/// A Playwright-shaped error: its message is the summary plus the call log.
const failure = (name: string, log: string[]): Error =>
  Object.assign(new Error(["locator.click: Timeout 5000ms exceeded.", "Call log:", ...log].join("\n")), { name });

const RESOLVED = '  - locator resolved to <a href="/archive/2026-09-30">Annual review 2026-09-30</a>';
const BLOCKED = '      - <div style="position:fixed">Please accept our terms</div> intercepts pointer events';

test("BR-04 a click whose every attempt was intercepted is an occlusion", () => {
  assert.equal(
    isOcclusion(
      failure("TimeoutError", [
        "  - waiting for locator('aria-ref=e5')",
        RESOLVED,
        "  - attempting click action",
        "    2 × waiting for element to be visible, enabled and stable",
        "      - element is visible, enabled and stable",
        "      - scrolling into view if needed",
        "      - done scrolling",
        BLOCKED,
        "    - retrying click action",
        "      - waiting 100ms",
        BLOCKED
      ])
    ),
    true
  );
});

test("BR-04 an action performed at some point is never an occlusion", () => {
  // The cover lifted, the click was delivered, then waiting afterwards failed.
  assert.equal(
    isOcclusion(
      failure("TimeoutError", [
        RESOLVED,
        "  - attempting click action",
        BLOCKED,
        "  - retrying click action",
        "    - performing click action",
        "    - click action done",
        "    - waiting for scheduled navigations to finish"
      ])
    ),
    false
  );
});

test("BR-04 compressed (N ×) call-log lines are read like any other", () => {
  assert.equal(
    isOcclusion(failure("TimeoutError", [RESOLVED, "  - attempting click action", "    3 × retrying click action", BLOCKED])),
    true
  );
  assert.equal(
    isOcclusion(failure("TimeoutError", [RESOLVED, "  - attempting click action", "    2 × performing click action", BLOCKED])),
    false,
    "a compressed performed line still counts as performed"
  );
});

test("BR-04 only the last attempt counts, and page text before the attempts is never read", () => {
  // Intercepted once, then the last attempt timed out for another reason.
  assert.equal(
    isOcclusion(
      failure("TimeoutError", [RESOLVED, "  - attempting click action", BLOCKED, "  - retrying click action", "    - waiting for element to be visible, enabled and stable"])
    ),
    false
  );
  // The page puts the phrase in its own markup (quoted by the resolved line).
  const spoof = '  - locator resolved to <a title="x intercepts pointer events">Pay</a> intercepts pointer events';
  assert.equal(isOcclusion(failure("TimeoutError", [spoof, "  - attempting click action", "    - element is not enabled"])), false);
  assert.equal(isOcclusion(failure("TimeoutError", [spoof])), false, "no attempt at all");
});

test("BR-04 anything but a timeout is not an occlusion", () => {
  assert.equal(isOcclusion(failure("Error", [RESOLVED, "  - attempting click action", BLOCKED])), false);
  assert.equal(isOcclusion("intercepts pointer events"), false);
  assert.equal(isOcclusion(undefined), false);
});
