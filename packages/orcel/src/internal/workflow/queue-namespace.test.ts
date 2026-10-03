import { describe, expect, it, vi } from "vitest";

import {
  deriveOrcelWorkflowQueueNamespace,
  deriveOrcelWorkflowQueuePrefix,
  deriveOrcelWorkflowQueueTopic,
  installOrcelWorkflowQueueNamespace,
  WORKFLOW_QUEUE_NAMESPACE_ENV,
} from "#internal/workflow/queue-namespace.js";

describe("workflow queue namespace", () => {
  it("derives a valid, collision-free namespace from the agent name", () => {
    expect(deriveOrcelWorkflowQueueNamespace("weather-agent")).toBe("orcel776561746865722d6167656e74");
    expect(deriveOrcelWorkflowQueueNamespace("weatheragent")).not.toBe(
      deriveOrcelWorkflowQueueNamespace("weather-agent"),
    );
    expect(deriveOrcelWorkflowQueueNamespace("weather-agent")).toMatch(/^[a-z][a-z0-9]*$/);
  });

  it("derives the workflow queue prefix and topic from the same namespace", () => {
    expect(deriveOrcelWorkflowQueuePrefix("weather-agent")).toBe(
      "__orcel776561746865722d6167656e74_wkf_workflow_",
    );
    expect(deriveOrcelWorkflowQueueTopic("weather-agent")).toBe(
      "__orcel776561746865722d6167656e74_wkf_workflow_*",
    );
  });

  it("installs the derived namespace for Workflow runtime operations", () => {
    vi.stubEnv(WORKFLOW_QUEUE_NAMESPACE_ENV, "previous");

    try {
      expect(installOrcelWorkflowQueueNamespace("weather-agent")).toBe(
        "orcel776561746865722d6167656e74",
      );
      expect(process.env[WORKFLOW_QUEUE_NAMESPACE_ENV]).toBe("orcel776561746865722d6167656e74");
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
