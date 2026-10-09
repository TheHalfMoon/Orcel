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
  it("declines takeover of a running pre-v8 victim without taking its token", async () => {
    const token = "force-claim-legacy-victim:" + randomUUID();
    const victim = await start(forceClaimResearchVictim, [{ token }], { specVersion: 7 });
    let claimant: Awaited<ReturnType<typeof start>> | undefined;
    try {
      await waitForHook(victim, { token });
      claimant = await start(forceClaimResearchSuccessor, [{ token }]);
      // A running protocol-7 owner must not be displaced by a forced claimant.
      await expect(claimant.returnValue).rejects.toMatchObject({
        name: "WorkflowRunFailedError",
        runId: claimant.runId,
        cause: {
          name: "HookConflictError",
          token,
          conflictingRunId: victim.runId,
        },
      });
      await resumeHook(token, "still-owned-by-legacy-victim");
      await expect(victim.returnValue).resolves.toBe("still-owned-by-legacy-victim");
    } finally {
      if (claimant) await releaseIfLive(claimant);
      await releaseIfLive(victim);
    }
  });

  it("routes a repeated force-claim to the latest live owner", async () => {
    const token = "force-claim-chain:" + randomUUID();
    const original = await start(forceClaimResearchVictim, [{ token }]);
    let first: Awaited<ReturnType<typeof start>> | undefined;
    let second: Awaited<ReturnType<typeof start>> | undefined;
    try {
      await waitForHook(original, { token });
      first = await start(forceClaimResearchSuccessor, [{ token }]);
      await waitForHook(first, { token });
      second = await start(forceClaimResearchSuccessor, [{ token }]);
      await waitForHook(second, { token });

      await resumeHook(token, "latest-owner");
      await expect(second.returnValue).resolves.toBe("latest-owner");
      await expect(first.returnValue).rejects.toThrow("was force-claimed by another workflow");
      await expect(original.returnValue).rejects.toThrow("was force-claimed by another workflow");
    } finally {
      if (second) await releaseIfLive(second);
      if (first) await releaseIfLive(first);
      await releaseIfLive(original);
    }
  });
});
