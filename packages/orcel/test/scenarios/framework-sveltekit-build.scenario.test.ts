import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createSvelteKitOrcelServiceDescriptor } from "../../src/internal/testing/scenario-apps/sveltekit-orcel-service.js";
import { useScenarioApp } from "../../src/internal/testing/scenario-app.js";
import { runPnpmCommand } from "../../src/internal/testing/run-pnpm-command.js";

const scenarioApp = useScenarioApp();

const SVELTEKIT_ORCEL_SERVICE_DESCRIPTOR = createSvelteKitOrcelServiceDescriptor({
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

describe("framework-sveltekit build", () => {
  it("emits the orcel service and route into the Vercel Build Output", async () => {
    const app = await scenarioApp(SVELTEKIT_ORCEL_SERVICE_DESCRIPTOR);

    await runPnpmCommand({
      args: ["exec", "vite", "build"],
      cwd: app.appRoot,
      env: {
        ...process.env,
        VERCEL: "1",
        VERCEL_ENV: "production",
      },
    });

    const { routes, services } = await readVercelOutputConfig(
      join(app.appRoot, ".vercel", "output"),
    );
    const orcelRouteIndex = routes.findIndex(
      (route) =>
        typeof route === "object" &&
        route !== null &&
        "src" in route &&
        route.src === "^/orcel/v1/(.*)$" &&
        "destination" in route,
    );
    const filesystemIndex = routes.findIndex(
      (route) =>
        typeof route === "object" &&
        route !== null &&
        "handle" in route &&
        route.handle === "filesystem",
    );

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
