import { describe, expect, it } from "vitest";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import { KAF_PACKAGE_NAME } from "#internal/package-name.js";
import {
  createKafVercelOptions,
  KAF_WORKFLOW_FLOW_ROUTE_PATH,
} from "#internal/nitro/host/vercel-build-output-config.js";
import { deriveKafWorkflowQueueTopic } from "#internal/workflow/queue-namespace.js";

describe("createKafVercelOptions", () => {
  it("returns undefined when the Vercel build output is disabled", () => {
    expect(createKafVercelOptions({ agentName: "test-agent", enabled: false })).toBeUndefined();
  });

  it("emits both framework slug and version so the proxy keeps the framework object", () => {
    expect(createKafVercelOptions({ agentName: "test-agent", enabled: true })?.config).toEqual({
      version: 3,
      framework: {
        slug: KAF_PACKAGE_NAME,
        version: resolveInstalledPackageInfo().version,
      },
    });
  });

  it("declares the queue-triggered workflow flow function through functionRules", () => {
    const options = createKafVercelOptions({ agentName: "test-agent", enabled: true });

    expect(options?.functionRules).toEqual({
      [KAF_WORKFLOW_FLOW_ROUTE_PATH]: {
        maxDuration: "max",
        experimentalTriggers: [
          {
            type: "queue/v2beta",
            topic: deriveKafWorkflowQueueTopic("test-agent"),
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
      const options = createKafVercelOptions({
        agentName: "test-agent",
        enabled: true,
        publicRoutePrefix,
      });
      expect(options?.functionRules[KAF_WORKFLOW_FLOW_ROUTE_PATH].environment).not.toHaveProperty(
        "KAF_PUBLIC_ROUTE_PREFIX",
      );
    }
  });

  it("bakes the normalized public route prefix into the flow function environment", () => {
    const options = createKafVercelOptions({
      agentName: "test-agent",
      enabled: true,
      publicRoutePrefix: "kaf/support/",
    });

    expect(options?.functionRules[KAF_WORKFLOW_FLOW_ROUTE_PATH].environment).toEqual({
      WORKFLOW_PRECONDITION_GUARD: "1",
      KAF_PUBLIC_ROUTE_PREFIX: "/kaf/support",
    });
  });

  it("marks workspace-member flow functions without marking standalone agents", () => {
    const standalone = createKafVercelOptions({
      agentName: "test-agent",
      enabled: true,
      publicRoutePrefix: "/support",
    });
    const workspaceMember = createKafVercelOptions({
      agentName: "test-agent",
      enabled: true,
      publicRoutePrefix: "/support",
      workspaceMember: true,
    });

    expect(standalone?.functionRules[KAF_WORKFLOW_FLOW_ROUTE_PATH].environment).not.toHaveProperty(
      "KAF_INTERNAL_AGENT_WORKSPACE_MEMBER",
    );
    expect(workspaceMember?.functionRules[KAF_WORKFLOW_FLOW_ROUTE_PATH].environment).toMatchObject({
      KAF_INTERNAL_AGENT_WORKSPACE_MEMBER: "1",
    });
  });
});
