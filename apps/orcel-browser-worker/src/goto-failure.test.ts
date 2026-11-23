import assert from "node:assert/strict";
import { test } from "node:test";
import { gotoFailure, type FailedPage } from "./goto-failure.js";
import { traceStart } from "./navigation-trace.js";

const SECRET = "https://example.test/?q=secret";

/// What a navigation that threw `error` gives, what it wrote, and how often it attached.
async function failing(error: Error, parts: Partial<FailedPage> = {}) {
  const written: string[] = [];
  let attached = 0;
  traceStart();
  const reason = await gotoFailure(
    error,
    {
      refusedByOrcel: () => false,
      closed: () => false,
      attach: async () => {
        attached += 1;
        return { send: async () => ({ url: SECRET }), detach: async () => {} };
      },
      ...parts
    },
    (line) => written.push(line.replace(/\+\d+ms/g, ""))
  );
  return { reason, written, attached };
}

const named = (name: string, message: string) => Object.assign(new Error(message), { name });

test("#584: a navigation that timed out asks the browser process and says so on one line", async () => {
  assert.deepEqual(await failing(named("TimeoutError", `Timeout 30000ms exceeded navigating to ${SECRET}`)), {
    reason: "timeout",
    written: ["orcel-browser-worker: navigation timeline: browser_attach_answered browser_history_answered browser_version_answered page_closed_false\n"],
    attached: 1
  });
  assert.equal((await failing(named("TimeoutError", ""))).reason, "timeout");
  const closed = await failing(named("TimeoutError", "Timeout"), { closed: () => true, attach: () => Promise.reject(new Error(SECRET)) });
  assert.deepEqual(closed.written, ["orcel-browser-worker: navigation timeline: browser_attach_error browser_history_not_sent browser_version_not_sent page_closed_true\n"]);
});

test("#584: any other failure is typed as before, keeps only the engine's code, and is not probed", async () => {
  assert.deepEqual(await failing(new Error(`page.goto: net::ERR_CONNECTION_RESET at ${SECRET}`)), {
    reason: "failed",
    written: ["orcel-browser-worker: goto failed net::ERR_CONNECTION_RESET navigation timeline: \n"],
    attached: 0
  });
  const blocked = new Error(`page.goto: net::ERR_BLOCKED_BY_CLIENT at ${SECRET}`);
  assert.deepEqual(await failing(blocked, { refusedByOrcel: () => true }), { reason: "denied", written: [], attached: 0 });
  // A timeout is told by the error's class: a message can say anything.
  assert.equal((await failing(new Error("TimeoutError: Timeout 30000ms exceeded."))).reason, "failed");
  // The engine's own cancellation, not Orcel's refusal.
  assert.deepEqual(await failing(blocked), {
    reason: "failed",
    written: ["orcel-browser-worker: goto failed net::ERR_BLOCKED_BY_CLIENT navigation timeline: blocked_not_by_orcel\n"],
    attached: 0
  });
});
