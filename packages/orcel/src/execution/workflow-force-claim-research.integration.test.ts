import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  forceClaimResearchSuccessor,
  forceClaimResearchVictim,
} from "#internal/testing/workflow-force-claim-research.js";
import { waitForHook } from "#internal/testing/workflow-test-helpers.js";
import { resumeHook, start } from "#internal/workflow/runtime.js";

async function releaseIfLive(run: { status: Promise<string>; cancel: () => Promise<unknown> }) {
  const status = await run.status;
  if (status === "pending" || status === "running") await run.cancel();
}

describe("pinned Workflow SDK experimental force-claim local probe (#32)", () => {
  it("redirects a stable token to a forced claimant and settles the prior owner", async () => {
    const token = "force-claim-research:" + randomUUID();
    const victim = await start(forceClaimResearchVictim, [{ token }]);
    let claimant: Awaited<ReturnType<typeof start>> | undefined;
    try {
      await waitForHook(victim, { token });
      claimant = await start(forceClaimResearchSuccessor, [{ token }]);
      await waitForHook(claimant, { token });
      await resumeHook(token, "delivered-to-claimant");
      await expect(claimant.returnValue).resolves.toBe("delivered-to-claimant");
      await expect(victim.returnValue).rejects.toThrow("was force-claimed by another workflow");
    } finally {
      if (claimant) await releaseIfLive(claimant);
      await releaseIfLive(victim);
    }
  });
});
