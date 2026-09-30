import { describe, expect, it } from "vitest";

import {
  createKafServiceRequestPathRoute,
  createKafServiceRoute,
  mergeKafVercelConfig,
  type EnsureKafVercelServicesConfigResult,
} from "./vercel-services.js";

const GENERATED: Extract<EnsureKafVercelServicesConfigResult, { mode: "generated" }> = {
  mode: "generated",
  services: {
    kaf: {
      buildCommand: "kaf build",
      framework: "kaf",
      outputDirectory: ".vercel/output",
      routes: [createKafServiceRequestPathRoute()],
      root: ".kaf/vercel-services/kaf",
    },
  },
};

describe("createKafServiceRoute", () => {
  it("routes the kaf transport namespace to the kaf service", () => {
    expect(createKafServiceRoute()).toEqual({
      destination: {
        service: "kaf",
        type: "service",
      },
      src: "^/kaf/v1/(.*)$",
    });
  });

  it("targets a custom service name", () => {
    expect(createKafServiceRoute("agent").destination.service).toBe("agent");
  });
});

describe("createKafServiceRequestPathRoute", () => {
  it("pins the request path to the kaf transport namespace", () => {
    expect(createKafServiceRequestPathRoute()).toEqual({
      src: "^/kaf/v1/(.*)$",
      transforms: [
        {
          args: "/kaf/v1/$1",
          op: "set",
          type: "request.path",
        },
      ],
    });
  });
});

describe("mergeKafVercelConfig", () => {
  it("builds a fresh config when nothing exists", () => {
    expect(mergeKafVercelConfig(undefined, GENERATED)).toEqual({
      version: 3,
      routes: [createKafServiceRoute()],
      services: GENERATED.services,
    });
  });

  it("prepends the service route before user routes", () => {
    const userRoute = { src: "^/custom/(.*)$", dest: "/other/$1" };

    expect(mergeKafVercelConfig({ routes: [userRoute] }, GENERATED).routes).toEqual([
      createKafServiceRoute(),
      userRoute,
    ]);
  });

  it("inserts the service route before a user filesystem handle", () => {
    const before = { src: "^/a$", dest: "/b" };
    const after = { src: "^/c$", dest: "/d" };

    expect(
      mergeKafVercelConfig({ routes: [before, { handle: "filesystem" }, after] }, GENERATED).routes,
    ).toEqual([before, createKafServiceRoute(), { handle: "filesystem" }, after]);
  });

  it("preserves a user-configured kaf service and routes to it", () => {
    const merged = mergeKafVercelConfig(
      {
        services: {
          agent: {
            framework: "kaf",
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
        framework: "kaf",
        buildCommand: "pnpm build:agent",
        root: "agent",
        routes: [createKafServiceRequestPathRoute()],
      },
      other: { framework: "hono" },
    });
    expect(merged.routes).toEqual([createKafServiceRoute("agent")]);
  });

  it("stays idempotent when merged twice", () => {
    const once = mergeKafVercelConfig(undefined, GENERATED);

    expect(mergeKafVercelConfig(once, GENERATED)).toEqual(once);
  });

  it("preserves unknown keys and an explicit version", () => {
    const merged = mergeKafVercelConfig({ version: 2, cleanUrls: true }, GENERATED);

    expect(merged.version).toBe(2);
    expect(merged.cleanUrls).toBe(true);
  });
});
