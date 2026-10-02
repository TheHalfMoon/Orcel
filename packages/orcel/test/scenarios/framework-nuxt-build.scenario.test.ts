import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createNuxtOrcelServiceDescriptor } from "../../src/internal/testing/scenario-apps/nuxt-orcel-service.js";
import { useScenarioApp } from "../../src/internal/testing/scenario-app.js";
import { runPnpmCommand } from "../../src/internal/testing/run-pnpm-command.js";

const scenarioApp = useScenarioApp();

const NUXT_ORCEL_SERVICE_DESCRIPTOR = createNuxtOrcelServiceDescriptor({
  installDependencies: true,
});

async function readVercelOutputConfig(outputRoot: string): Promise<{
  readonly routes: readonly unknown[];
  readonly services: Record<string, unknown>;
}> {
  const config: unknown = JSON.parse(await readFile(join(outputRoot, "config.json"), "utf8"));

  if (
    typeof config !== "object" ||
    config === null ||
    !("routes" in config) ||
    !Array.isArray(config.routes)
  ) {
    throw new Error("Expected Vercel Build Output config.json to contain a routes array.");
  }

  const services =
    "services" in config && typeof config.services === "object" && config.services !== null
      ? (config.services as Record<string, unknown>)
      : {};

  return { routes: config.routes, services };
}

function isOrcelServiceRoute(route: unknown): boolean {
  return (
    typeof route === "object" &&
    route !== null &&
    "src" in route &&
    route.src === "^/orcel/v1/(.*)$" &&
    "destination" in route
  );
}

function isFilesystemHandle(route: unknown): boolean {
  return (
    typeof route === "object" &&
    route !== null &&
    "handle" in route &&
    route.handle === "filesystem"
  );
}

describe("framework-nuxt build", () => {
  it("emits the orcel service and route into the Vercel Build Output", async () => {
    const app = await scenarioApp(NUXT_ORCEL_SERVICE_DESCRIPTOR);

    // Build the Nuxt app directly with the env a real Vercel build container
    // always provides. `VERCEL` triggers both Nitro's Vercel preset (via
    // std-env provider detection) and the orcel module's service generation;
    // `NITRO_PRESET` pins the preset so the assertion does not depend on
    // detection heuristics. `vercel build` is intentionally not used here: run
    // unauthenticated it strips these system env vars, so Nitro would fall back
    // to the node-server preset and emit no Build Output. Vercel's own
    // assembly of the generated service is covered by the Next.js scenario.
    await runPnpmCommand({
      args: ["exec", "nuxt", "build"],
      cwd: app.appRoot,
      env: {
        ...process.env,
        NITRO_PRESET: "vercel",
        VERCEL: "1",
        VERCEL_ENV: "production",
      },
    });

    const { routes, services } = await readVercelOutputConfig(
      join(app.appRoot, ".vercel", "output"),
    );
    const orcelRouteIndex = routes.findIndex(isOrcelServiceRoute);
    const filesystemIndex = routes.findIndex(isFilesystemHandle);

    expect(routes[orcelRouteIndex]).toEqual(
      expect.objectContaining({
        destination: { service: "orcel", type: "service" },
        src: "^/orcel/v1/(.*)$",
      }),
    );
    if (filesystemIndex !== -1) {
      expect(orcelRouteIndex).toBeLessThan(filesystemIndex);
    }
    expect(services.orcel).toEqual(
      expect.objectContaining({
        framework: "orcel",
        root: ".orcel/vercel-services/orcel",
      }),
    );
  }, 300_000);
});
