import { describe, expect, it } from "vitest";

import {
  compileKafVercelService,
  createKafServiceName,
} from "#internal/vercel/kaf-service-contribution.js";
import { resolveKafServicePrefixByRoot } from "#internal/vercel/vercel-service-config-operations.js";
import { isValidVercelServiceName } from "#internal/vercel/vercel-service-name.js";

describe("resolveKafServicePrefixByRoot", () => {
  it("resolves stable and legacy services by application root", () => {
    expect(
      resolveKafServicePrefixByRoot({
        appRoots: ["/project/agents/support"],
        config: {
          services: {
            kaf: { framework: "kaf", root: "agents/support", routePrefix: "/support" },
          },
        },
        configRoot: "/project",
      }),
    ).toBe("/support");
    expect(
      resolveKafServicePrefixByRoot({
        appRoots: ["/project/agent"],
        config: {
          experimentalServices: {
            kaf: { entrypoint: "agent", framework: "kaf", mount: { path: "/agent" } },
          },
        },
        configRoot: "/project",
      }),
    ).toBe("/agent");
  });

  it("ignores malformed legacy service collections", () => {
    expect(
      resolveKafServicePrefixByRoot({
        appRoots: ["/project/agent"],
        config: {
          experimentalServices: null,
          services: {
            kaf: { framework: "kaf", root: "agent", routePrefix: "/agent" },
            web: { framework: "nextjs" },
          },
        },
        configRoot: "/project",
      }),
    ).toBe("/agent");
  });
});

describe("compileKafVercelService", () => {
  it("runs generated workspace agents headlessly under their public routes", () => {
    expect(
      compileKafVercelService({
        agent: {
          appRoot: "/project/agents/support",
          buildCommand: "kaf build",
          devCommand: "kaf dev --no-ui",
          name: "support",
          publicRoutePrefix: "/support",
          workspaceMember: true,
        },
        target: { hostOutputDirectory: "/project/.vercel/output", projectRoot: "/project" },
      }).service.devCommand,
    ).toBe(
      "cd '../../../agents/support' && export KAF_PUBLIC_ROUTE_PREFIX='/support' && export KAF_INTERNAL_AGENT_WORKSPACE_MEMBER=1 && kaf dev --no-ui",
    );
  });
});

describe("createKafServiceName", () => {
  it("preserves public agent names that are valid service suffixes", () => {
    expect(createKafServiceName("customer-care")).toBe("kaf-customer-care");
  });

  it("encodes digit-bearing public names into stable valid service names", () => {
    const serviceName = createKafServiceName("support2");
    expect(serviceName).toBe(createKafServiceName("support2"));
    expect(serviceName).not.toBe(createKafServiceName("support3"));
    expect(serviceName).toMatch(/^kaf-support-[a-z]+$/);
    expect(isValidVercelServiceName(serviceName)).toBe(true);
  });

  it("truncates long names while retaining a distinguishing suffix", () => {
    const serviceName = createKafServiceName(`support-${"a".repeat(80)}`);
    expect(serviceName.length).toBeLessThanOrEqual(64);
    expect(isValidVercelServiceName(serviceName)).toBe(true);
  });
});
