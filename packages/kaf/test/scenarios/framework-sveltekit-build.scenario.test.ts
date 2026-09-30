import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createSvelteKitKafServiceDescriptor } from "../../src/internal/testing/scenario-apps/sveltekit-kaf-service.js";
import { useScenarioApp } from "../../src/internal/testing/scenario-app.js";
import { runPnpmCommand } from "../../src/internal/testing/run-pnpm-command.js";

const scenarioApp = useScenarioApp();

const SVELTEKIT_KAF_SERVICE_DESCRIPTOR = createSvelteKitKafServiceDescriptor({
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
  it("emits the kaf service and route into the Vercel Build Output", async () => {
    const app = await scenarioApp(SVELTEKIT_KAF_SERVICE_DESCRIPTOR);

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
    const kafRouteIndex = routes.findIndex(
      (route) =>
        typeof route === "object" &&
        route !== null &&
        "src" in route &&
        route.src === "^/kaf/v1/(.*)$" &&
        "destination" in route,
    );
    const filesystemIndex = routes.findIndex(
      (route) =>
        typeof route === "object" &&
        route !== null &&
        "handle" in route &&
        route.handle === "filesystem",
    );

    expect(routes[kafRouteIndex]).toEqual(
      expect.objectContaining({
        destination: { service: "kaf", type: "service" },
        src: "^/kaf/v1/(.*)$",
      }),
    );
    if (filesystemIndex !== -1) {
      expect(kafRouteIndex).toBeLessThan(filesystemIndex);
    }
    expect(services.kaf).toEqual(
      expect.objectContaining({
        framework: "kaf",
        root: ".kaf/vercel-services/kaf",
      }),
    );
  }, 300_000);
});
