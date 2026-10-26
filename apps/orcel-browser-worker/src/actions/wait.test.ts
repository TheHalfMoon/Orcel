import assert from "node:assert/strict";
import { test } from "node:test";
import { MAX_WAIT_MS, waitForText, type WaitPage } from "./wait.js";

/// A page whose text locator records its query and resolves or times out.
function page(outcome: "met" | "timeout") {
  const queries: Array<{ source: string; state: string; timeout: number }> = [];
  const stub = {
    getByText: (pattern: RegExp) => ({
      first: () => ({
        waitFor: async (options: { state: string; timeout: number }) => {
          queries.push({ source: pattern.source, state: options.state, timeout: options.timeout });
          if (outcome === "timeout") throw new Error("Timeout exceeded");
        }
      })
    })
  };
  return { stub: stub as unknown as WaitPage, queries };
}

test("BR-02 a wait reports whether the text appeared or disappeared, within the bound", async () => {
  const met = page("met");
  assert.equal(await waitForText(met.stub, "Changes  saved", true, 2_000), true);
  assert.deepEqual(met.queries, [{ source: "Changes\\s+saved", state: "visible", timeout: 2_000 }]);
  const late = page("timeout");
  assert.equal(await waitForText(late.stub, "Loading", false, 60_000), false);
  assert.deepEqual(late.queries, [{ source: "Loading", state: "hidden", timeout: MAX_WAIT_MS }]);
});
