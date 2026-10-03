import { describe, expect, it } from "vitest";

import {
  compileOrcelVercelService,
  createOrcelServiceName,
} from "#internal/vercel/orcel-service-contribution.js";
import { resolveOrcelServicePrefixByRoot } from "#internal/vercel/vercel-service-config-operations.js";
import { isValidVercelServiceName } from "#internal/vercel/vercel-service-name.js";

describe("resolveOrcelServicePrefixByRoot", () => {
  it("resolves stable and legacy services by application root", () => {
    expect(
      resolveOrcelServicePrefixByRoot({
        appRoots: ["/project/agents/support"],
        config: {
          services: {
            orcel: { framework: "eve", root: "agents/support", routePrefix: "/support" },
          },
        },
        configRoot: "/project",
      }),
    ).toBe("/support");
    expect(
      resolveOrcelServicePrefixByRoot({
        appRoots: ["/project/agent"],
        config: {
          experimentalServices: {
            orcel: { entrypoint: "agent", framework: "eve", mount: { path: "/agent" } },
          },
        },
        configRoot: "/project",
      }),
    ).toBe("/agent");
  });

  it("ignores malformed legacy service collections", () => {
    expect(
      resolveOrcelServicePrefixByRoot({
        appRoots: ["/project/agent"],
        config: {
          experimentalServices: null,
          services: {
            orcel: { framework: "eve", root: "agent", routePrefix: "/agent" },
            web: { framework: "nextjs" },
          },
        },
        configRoot: "/project",
      }),
    ).toBe("/agent");
  });
});

describe("compileOrcelVercelService", () => {
  it("runs generated workspace agents headlessly under their public routes", () => {
    expect(
      compileOrcelVercelService({
        agent: {
          appRoot: "/project/agents/support",
          buildCommand: "orcel build",
          devCommand: "orcel dev --no-ui",
          name: "support",
          publicRoutePrefix: "/support",
          workspaceMember: true,
        },
        target: { hostOutputDirectory: "/project/.vercel/output", projectRoot: "/project" },
      }).service.devCommand,
    ).toBe(
      "cd '../../../agents/support' && export ORCEL_PUBLIC_ROUTE_PREFIX='/support' && export ORCEL_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && orcel dev --no-ui",
    );
  });
});

describe("createOrcelServiceName", () => {
  it("preserves public agent names that are valid service suffixes", () => {
    expect(createOrcelServiceName("customer-care")).toBe("orcel-customer-care");
  });

  it("encodes digit-bearing public names into stable valid service names", () => {
    const serviceName = createOrcelServiceName("support2");
    expect(serviceName).toBe(createOrcelServiceName("support2"));
    expect(serviceName).not.toBe(createOrcelServiceName("support3"));
    expect(serviceName).toMatch(/^orcel-support-[a-z]+$/);
    expect(isValidVercelServiceName(serviceName)).toBe(true);
  });

  it("truncates long names while retaining a distinguishing suffix", () => {
    const serviceName = createOrcelServiceName(`support-${"a".repeat(80)}`);
    expect(serviceName.length).toBeLessThanOrEqual(64);
    expect(isValidVercelServiceName(serviceName)).toBe(true);
  });
});
