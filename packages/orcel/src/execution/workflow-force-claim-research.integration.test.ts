import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  forceClaimResearchSuccessor,
  forceClaimResearchVictim,
} from "#internal/testing/workflow-force-claim-research.js";
import { waitForHook } from "#internal/testing/workflow-test-helpers.js";
import { getHookByToken, resumeHook, start } from "#internal/workflow/runtime.js";

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

  it("converges concurrent force claims to one owner in a single Local World", async () => {
    const token = "force-claim-concurrent:" + randomUUID();
    const victim = await start(forceClaimResearchVictim, [{ token }]);
    let contenders: Awaited<ReturnType<typeof start>>[] = [];
    try {
      await waitForHook(victim, { token });
      contenders = await Promise.all([
        start(forceClaimResearchSuccessor, [{ token }]),
        start(forceClaimResearchSuccessor, [{ token }]),
      ]);

      // Let both claim attempts reach a terminal ownership decision. Their order
      // is deliberately not assumed; single-process scheduling is not FIFO.
      await vi.waitFor(
        async () => {
          const statuses = await Promise.all(contenders.map((run) => run.status));
          expect(statuses.filter((status) => status === "failed")).toHaveLength(1);
          expect(statuses.filter((status) => status === "running")).toHaveLength(1);
        },
        { interval: 100, timeout: 15_000 },
      );

      const statuses = await Promise.all(contenders.map((run) => run.status));
      const winner = contenders[statuses.indexOf("running")]!;
      const loser = contenders[statuses.indexOf("failed")]!;
      expect((await getHookByToken(token)).runId).toBe(winner.runId);
      await resumeHook(token, "single-concurrent-winner");
      await expect(winner.returnValue).resolves.toBe("single-concurrent-winner");
      await expect(loser.returnValue).rejects.toThrow("was force-claimed by another workflow");
      await expect(victim.returnValue).rejects.toThrow("was force-claimed by another workflow");
    } finally {
      for (const run of contenders) await releaseIfLive(run);
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
