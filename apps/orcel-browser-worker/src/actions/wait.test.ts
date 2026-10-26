import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_WAIT_MS, waitForText, type WaitPage } from "./wait.js";

/// A page whose text locator records its query and resolves or times out.
function page(outcome: "met" | "timeout") {
  const queries: Array<{ source: string; visible: boolean; state: string; timeout: number }> = [];
  const stub = {
    getByText: (pattern: RegExp) => ({
      filter: (options: { visible: boolean }) => ({
        first: () => ({
          waitFor: async (wait: { state: string; timeout: number }) => {
            queries.push({ source: pattern.source, visible: options.visible, state: wait.state, timeout: wait.timeout });
            if (outcome === "timeout") throw new Error("Timeout exceeded");
          }
        })
      })
    })
  };
  return { stub: stub as unknown as WaitPage, queries };
}

test("BR-02 a wait watches visible copies only and reports whether it was met, within the bound", async () => {
  const met = page("met");
  assert.equal(await waitForText(met.stub, "Changes  saved", true, 2_000), true);
  // A visible copy attached: appeared. (A hidden first match is filtered
  // out, so it can neither satisfy "appear" nor mask a visible copy.)
  assert.deepEqual(met.queries, [{ source: String.raw`Changes\s+saved`, visible: true, state: "attached", timeout: 2_000 }]);
  const late = page("timeout");
  assert.equal(await waitForText(late.stub, "Loading", false, 60_000), false);
  assert.deepEqual(late.queries, [{ source: "Loading", visible: true, state: "detached", timeout: MAX_WAIT_MS }]);
});
