import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";

import { parentChildHookWorkflow } from "#internal/testing/workflow-child-hook-microreproducer.js";
import { getRun, start } from "#internal/workflow/runtime.js";

async function releaseIfLive(run: { status: Promise<string>; cancel: () => Promise<unknown> }) {
  const status = await run.status;
  if (status === "pending" || status === "running") await run.cancel();
}

describe("local Workflow parent/child hook microreproducer (#29)", () => {
  it("preserves parent ownership and two sequential child-to-parent acknowledgments", async () => {
    const firstToken = "child-microrepro:first:" + randomUUID();
    const secondToken = "child-microrepro:second:" + randomUUID();
    const parent = await start(parentChildHookWorkflow, [{ firstToken, secondToken }]);
    try {
      const result = await parent.returnValue;
      expect(result).toEqual({
        parentRunId: parent.runId,
        childRunId: expect.any(String),
        payloads: ["alpha", "beta"],
      });
      expect(result.childRunId).not.toBe(parent.runId);

      const child = await getRun(result.childRunId);
      await expect(child.returnValue).resolves.toEqual(["alpha", "beta"]);
    } finally {
      await releaseIfLive(parent);
    }
  });
});
