import { randomUUID } from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

import { describe, expect, it } from "vitest";

import {
  doubleResumeWorkflow,
  singleResumeWorkflow,
} from "#internal/testing/workflow-hook-microreproducer.js";
import { waitForHook } from "#internal/testing/workflow-test-helpers.js";
import { resumeHook, start } from "#internal/workflow/runtime.js";

interface RunRecord {
  readonly runKind: "single-resume" | "double-resume";
  readonly sdkVersion: string;
  readonly localWorldVersion: string;
  readonly firstHookReadyMs: number;
  readonly firstResumeAckMs: number;
  readonly secondHookReadyMs: number | null;
  readonly secondResumeAckMs: number | null;
  readonly returnValueWaitMs: number;
  readonly interpretation: string;
}

const localManifest = JSON.parse(
  await readFile(new URL("../../package.json", import.meta.url), "utf8"),
) as {
  devDependencies: Record<string, string>;
};

async function emit(record: RunRecord): Promise<void> {
  const line = JSON.stringify(record);
  console.info("WORKFLOW_HOOK_MICROREPRO=" + line);
  const output = process.env.WORKFLOW_HOOK_MICROREPRO_EVIDENCE_PATH;
  if (output) await appendFile(output, line + "\n", "utf8");
}

async function releaseIfLive(run: { status: Promise<string>; cancel: () => Promise<unknown> }) {
  const status = await run.status;
  if (status === "pending" || status === "running") await run.cancel();
}

describe("local Workflow-only hook resume microreproducer (#27)", () => {
  it("acknowledges one public hook and settles the exact payload", async () => {
    const token = "microrepro:single:" + randomUUID();
    const beginning = performance.now();
    const run = await start(singleResumeWorkflow, [{ token }]);
    try {
      await waitForHook(run, { token });
      const readyAt = performance.now();
      await resumeHook(token, "one");
      const acknowledgedAt = performance.now();
      await expect(run.returnValue).resolves.toBe("one");
      const settledAt = performance.now();

      await emit({
        runKind: "single-resume",
        sdkVersion: localManifest.devDependencies["@workflow/core"]!,
        localWorldVersion: localManifest.devDependencies["@workflow/world-local"]!,
        firstHookReadyMs: readyAt - beginning,
        firstResumeAckMs: acknowledgedAt - readyAt,
        secondHookReadyMs: null,
        secondResumeAckMs: null,
        returnValueWaitMs: settledAt - acknowledgedAt,
        interpretation:
          "Local monotonic observer timing only; hook discovery includes polling; no hosted or causal performance inference.",
      });
    } finally {
      await releaseIfLive(run);
    }
  });

  it("acknowledges two sequential public hooks without losing order or payloads", async () => {
    const firstToken = "microrepro:first:" + randomUUID();
    const secondToken = "microrepro:second:" + randomUUID();
    const beginning = performance.now();
    const run = await start(doubleResumeWorkflow, [{ firstToken, secondToken }]);
    try {
      await waitForHook(run, { token: firstToken });
      const firstReadyAt = performance.now();
      await resumeHook(firstToken, "alpha");
      const firstAckAt = performance.now();
      await waitForHook(run, { token: secondToken });
      const secondReadyAt = performance.now();
      await resumeHook(secondToken, "beta");
      const secondAckAt = performance.now();
      await expect(run.returnValue).resolves.toEqual(["alpha", "beta"]);
      const settledAt = performance.now();

      await emit({
        runKind: "double-resume",
        sdkVersion: localManifest.devDependencies["@workflow/core"]!,
        localWorldVersion: localManifest.devDependencies["@workflow/world-local"]!,
        firstHookReadyMs: firstReadyAt - beginning,
        firstResumeAckMs: firstAckAt - firstReadyAt,
        secondHookReadyMs: secondReadyAt - firstAckAt,
        secondResumeAckMs: secondAckAt - secondReadyAt,
        returnValueWaitMs: settledAt - secondAckAt,
        interpretation:
          "Local monotonic observer timing only; second-hook discovery includes polling; no child run or hosted latency attribution.",
      });
    } finally {
      await releaseIfLive(run);
    }
  });
});
