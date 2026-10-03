import { describe, expect, it } from "vitest";

import {
  createOrcelServiceRequestPathRoute,
  createOrcelServiceRoute,
  mergeOrcelVercelConfig,
  type EnsureOrcelVercelServicesConfigResult,
} from "./vercel-services.js";

const GENERATED: Extract<EnsureOrcelVercelServicesConfigResult, { mode: "generated" }> = {
  mode: "generated",
  services: {
    orcel: {
      buildCommand: "orcel build",
      framework: "eve",
      outputDirectory: ".vercel/output",
      routes: [createOrcelServiceRequestPathRoute()],
      root: ".orcel/vercel-services/orcel",
    },
  },
};

describe("createOrcelServiceRoute", () => {
  it("routes the orcel transport namespace to the orcel service", () => {
    expect(createOrcelServiceRoute()).toEqual({
      destination: {
        service: "orcel",
        type: "service",
      },
      src: "^/orcel/v1/(.*)$",
    });
  });

  it("targets a custom service name", () => {
    expect(createOrcelServiceRoute("agent").destination.service).toBe("agent");
  });
});

describe("createOrcelServiceRequestPathRoute", () => {
  it("pins the request path to the orcel transport namespace", () => {
    expect(createOrcelServiceRequestPathRoute()).toEqual({
      src: "^/orcel/v1/(.*)$",
      transforms: [
        {
          args: "/orcel/v1/$1",
          op: "set",
          type: "request.path",
        },
      ],
    });
  });
});

describe("mergeOrcelVercelConfig", () => {
  it("builds a fresh config when nothing exists", () => {
    expect(mergeOrcelVercelConfig(undefined, GENERATED)).toEqual({
      version: 3,
      routes: [createOrcelServiceRoute()],
      services: GENERATED.services,
    });
  });

  it("prepends the service route before user routes", () => {
    const userRoute = { src: "^/custom/(.*)$", dest: "/other/$1" };

    expect(mergeOrcelVercelConfig({ routes: [userRoute] }, GENERATED).routes).toEqual([
      createOrcelServiceRoute(),
      userRoute,
    ]);
  });

  it("inserts the service route before a user filesystem handle", () => {
    const before = { src: "^/a$", dest: "/b" };
    const after = { src: "^/c$", dest: "/d" };

    expect(
      mergeOrcelVercelConfig({ routes: [before, { handle: "filesystem" }, after] }, GENERATED).routes,
    ).toEqual([before, createOrcelServiceRoute(), { handle: "filesystem" }, after]);
  });

  it("preserves a user-configured orcel service and routes to it", () => {
    const merged = mergeOrcelVercelConfig(
      {
        services: {
          agent: {
            framework: "eve",
            buildCommand: "pnpm build:agent",
            root: "agent",
          },
          other: { framework: "hono" },
        },
      },
      GENERATED,
    );

    expect(merged.services).toEqual({
      agent: {
        framework: "eve",
        buildCommand: "pnpm build:agent",
        root: "agent",
        routes: [createOrcelServiceRequestPathRoute()],
      },
      other: { framework: "hono" },
    });
    expect(merged.routes).toEqual([createOrcelServiceRoute("agent")]);
  });

  it("stays idempotent when merged twice", () => {
    const once = mergeOrcelVercelConfig(undefined, GENERATED);

    expect(mergeOrcelVercelConfig(once, GENERATED)).toEqual(once);
  });

  it("preserves unknown keys and an explicit version", () => {
    const merged = mergeOrcelVercelConfig({ version: 2, cleanUrls: true }, GENERATED);

    expect(merged.version).toBe(2);
    expect(merged.cleanUrls).toBe(true);
  });
});
