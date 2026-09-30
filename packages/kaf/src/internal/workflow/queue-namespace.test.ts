import { describe, expect, it, vi } from "vitest";

import {
  deriveKafWorkflowQueueNamespace,
  deriveKafWorkflowQueuePrefix,
  deriveKafWorkflowQueueTopic,
  installKafWorkflowQueueNamespace,
  WORKFLOW_QUEUE_NAMESPACE_ENV,
} from "#internal/workflow/queue-namespace.js";

describe("workflow queue namespace", () => {
  it("derives a valid, collision-free namespace from the agent name", () => {
    expect(deriveKafWorkflowQueueNamespace("weather-agent")).toBe("kaf776561746865722d6167656e74");
    expect(deriveKafWorkflowQueueNamespace("weatheragent")).not.toBe(
      deriveKafWorkflowQueueNamespace("weather-agent"),
    );
    expect(deriveKafWorkflowQueueNamespace("weather-agent")).toMatch(/^[a-z][a-z0-9]*$/);
  });

  it("derives the workflow queue prefix and topic from the same namespace", () => {
    expect(deriveKafWorkflowQueuePrefix("weather-agent")).toBe(
      "__eve776561746865722d6167656e74_wkf_workflow_",
    );
    expect(deriveKafWorkflowQueueTopic("weather-agent")).toBe(
      "__eve776561746865722d6167656e74_wkf_workflow_*",
    );
  });

  it("installs the derived namespace for Workflow runtime operations", () => {
    vi.stubEnv(WORKFLOW_QUEUE_NAMESPACE_ENV, "previous");

    try {
      expect(installKafWorkflowQueueNamespace("weather-agent")).toBe(
        "kaf776561746865722d6167656e74",
      );
      expect(process.env[WORKFLOW_QUEUE_NAMESPACE_ENV]).toBe("kaf776561746865722d6167656e74");
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
