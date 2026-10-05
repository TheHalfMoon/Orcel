import { describe, expect, it } from "vitest";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import { ORCEL_FRAMEWORK_SLUG } from "#internal/package-name.js";
import {
  createOrcelVercelOptions,
  ORCEL_WORKFLOW_FLOW_ROUTE_PATH,
} from "#internal/nitro/host/vercel-build-output-config.js";
import { deriveOrcelWorkflowQueueTopic } from "#internal/workflow/queue-namespace.js";

describe("createOrcelVercelOptions", () => {
  it("returns undefined when the Vercel build output is disabled", () => {
    expect(createOrcelVercelOptions({ agentName: "test-agent", enabled: false })).toBeUndefined();
  });

  it("emits both framework slug and version so the proxy keeps the framework object", () => {
    expect(createOrcelVercelOptions({ agentName: "test-agent", enabled: true })?.config).toEqual({
      version: 3,
      framework: {
        slug: ORCEL_FRAMEWORK_SLUG,
        version: resolveInstalledPackageInfo().version,
      },
    });
  });

  it("declares the queue-triggered workflow flow function through functionRules", () => {
    const options = createOrcelVercelOptions({ agentName: "test-agent", enabled: true });

    expect(options?.functionRules).toEqual({
      [ORCEL_WORKFLOW_FLOW_ROUTE_PATH]: {
        maxDuration: "max",
        experimentalTriggers: [
          {
            type: "queue/v2beta",
            topic: deriveOrcelWorkflowQueueTopic("test-agent"),
            consumer: "default",
            retryAfterSeconds: 5,
            initialDelaySeconds: 0,
          },
        ],
        environment: {
          WORKFLOW_PRECONDITION_GUARD: "1",
        },
      },
    });
  });

  it("omits the public route prefix from the flow environment when none is set", () => {
    for (const publicRoutePrefix of [undefined, ""]) {
      const options = createOrcelVercelOptions({
        agentName: "test-agent",
        enabled: true,
        publicRoutePrefix,
      });
      expect(options?.functionRules[ORCEL_WORKFLOW_FLOW_ROUTE_PATH].environment).not.toHaveProperty(
        "ORCEL_PUBLIC_ROUTE_PREFIX",
      );
    }
  });

  it("bakes the normalized public route prefix into the flow function environment", () => {
    const options = createOrcelVercelOptions({
      agentName: "test-agent",
      enabled: true,
      publicRoutePrefix: "orcel/support/",
    });

    expect(options?.functionRules[ORCEL_WORKFLOW_FLOW_ROUTE_PATH].environment).toEqual({
      WORKFLOW_PRECONDITION_GUARD: "1",
      ORCEL_PUBLIC_ROUTE_PREFIX: "/orcel/support",
    });
  });

  it("marks workspace-member flow functions without marking standalone agents", () => {
    const standalone = createOrcelVercelOptions({
      agentName: "test-agent",
      enabled: true,
      publicRoutePrefix: "/support",
    });
    const workspaceMember = createOrcelVercelOptions({
      agentName: "test-agent",
      enabled: true,
      publicRoutePrefix: "/support",
      workspaceMember: true,
    });

    expect(standalone?.functionRules[ORCEL_WORKFLOW_FLOW_ROUTE_PATH].environment).not.toHaveProperty(
      "ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER",
    );
    expect(workspaceMember?.functionRules[ORCEL_WORKFLOW_FLOW_ROUTE_PATH].environment).toMatchObject({
      ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER: "1",
    });
  });
});
