import { access, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { ScenarioAppDescriptor } from "../../src/internal/testing/scenario-app.js";
import { createNextKafProxyDescriptor } from "../../src/internal/testing/scenario-apps/next-kaf-proxy.js";
import { useScenarioApp } from "../../src/internal/testing/scenario-app.js";
import { runPnpmCommand } from "../../src/internal/testing/run-pnpm-command.js";

const VERCEL_GENERATED_SERVICES_VERSION = "56.4.0";
const VERCEL_PNPM_10_PROJECT_CREATED_AT = Date.UTC(2026, 6, 13);
const scenarioApp = useScenarioApp();

const NEXT_KAF_PROXY_DESCRIPTOR = createNextKafProxyDescriptor({
  installDependencies: true,
  vercelVersion: VERCEL_GENERATED_SERVICES_VERSION,
});
const NEXT_KAF_MIDDLEWARE_DESCRIPTOR = {
  ...NEXT_KAF_PROXY_DESCRIPTOR,
  files: {
    ...NEXT_KAF_PROXY_DESCRIPTOR.files,
    "next.config.mjs": `import { withEve } from "kaf/next";\n\nexport default withEve({}, { kafBuildCommand: "pnpm exec kaf build --skip-sandbox-prewarm" });\n`,
    ".vercel/project.json": `${JSON.stringify(
      {
        orgId: "team_kaf_scenario",
        projectId: "prj_kaf_scenario",
        projectName: "next-kaf-middleware",
        settings: {
          buildCommand: "pnpm exec next build",
          createdAt: VERCEL_PNPM_10_PROJECT_CREATED_AT,
          framework: "nextjs",
          nodeVersion: "24.x",
          outputDirectory: null,
          rootDirectory: null,
        },
      },
      null,
      2,
    )}\n`,
  },
  name: "next-kaf-middleware",
} satisfies ScenarioAppDescriptor;
const NEXT_KAF_NAMED_SCHEDULES_DESCRIPTOR = {
  ...NEXT_KAF_PROXY_DESCRIPTOR,
  files: {
    ...NEXT_KAF_PROXY_DESCRIPTOR.files,
    ".vercel/project.json": `${JSON.stringify(
      {
        orgId: "team_kaf_scenario",
        projectId: "prj_kaf_named_schedules_scenario",
        projectName: "next-kaf-named-schedules",
        settings: {
          buildCommand: "pnpm exec next build",
          createdAt: VERCEL_PNPM_10_PROJECT_CREATED_AT,
          framework: "nextjs",
          nodeVersion: "24.x",
          outputDirectory: null,
          rootDirectory: null,
        },
      },
      null,
      2,
    )}\n`,
    "agents/billing/agent.mjs": `import { defineAgent } from "kaf";

export default defineAgent({ model: "openai/gpt-5.4" });
`,
    "agents/billing/instructions.md": "You are the billing test agent.\n",
    "agents/billing/schedules/sweep.md": `---
cron: "*/10 * * * *"
---

Sweep overdue invoices.
`,
    "agents/support/agent.mjs": `import { defineAgent } from "kaf";

export default defineAgent({ model: "openai/gpt-5.4" });
`,
    "agents/support/instructions.md": "You are the support test agent.\n",
    "agents/support/schedules/triage.md": `---
cron: "*/5 * * * *"
---

Triage the support queue.
`,
    "next.config.mjs": `import { withEve } from "kaf/next";

export default withEve({}, {
  kafBuildCommand: "pnpm exec kaf build --skip-sandbox-prewarm",
  agents: {
    billing: "./agents/billing",
    support: "./agents/support",
  },
});
`,
    "src/app/api/user-cleanup/route.js": `export function GET() {
  return Response.json({ ok: true });
}
`,
    "vercel.json": `${JSON.stringify(
      {
        crons: [{ path: "/api/user-cleanup", schedule: "0 0 * * *" }],
      },
      null,
      2,
    )}\n`,
  },
  name: "next-kaf-named-schedules",
} satisfies ScenarioAppDescriptor;

async function readVercelOutputConfig(outputRoot: string): Promise<Record<string, unknown>> {
  const config: unknown = JSON.parse(await readFile(join(outputRoot, "config.json"), "utf8"));

  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new Error("Expected Vercel Build Output config.json to contain an object.");
  }

  return config as Record<string, unknown>;
}

async function readVercelOutputRoutes(outputRoot: string): Promise<readonly unknown[]> {
  const config = await readVercelOutputConfig(outputRoot);
  if (!Array.isArray(config.routes)) {
    throw new Error("Expected Vercel Build Output config.json to contain a routes array.");
  }
  return config.routes;
}

async function runVercelBuild(appRoot: string): Promise<void> {
  await runPnpmCommand({
    args: ["exec", "./node_modules/.bin/vercel", "build", "--yes"],
    cwd: appRoot,
    env: {
      ...process.env,
      NPM_CONFIG_AUDIT: "false",
      NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
    },
  });
}

describe("framework-next build", () => {
  it("preserves Next middleware when Vercel assembles the generated kaf service", async () => {
    const app = await scenarioApp(NEXT_KAF_MIDDLEWARE_DESCRIPTOR);

    await runVercelBuild(app.appRoot);

    const outputRoot = join(app.appRoot, ".vercel", "output");
    const routes = await readVercelOutputRoutes(outputRoot);

    expect(routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ middlewarePath: "/_middleware" }),
        expect.objectContaining({
          destination: { service: "kaf", type: "service" },
          src: "^/kaf/v1/(.*)$",
        }),
      ]),
    );
    await expect(
      access(join(outputRoot, "functions", "_middleware.func", ".vc-config.json")),
    ).resolves.toBeUndefined();
    await expect(
      access(join(outputRoot, "services", "kaf", "functions", "__server.func", ".vc-config.json")),
    ).resolves.toBeUndefined();
    await expect(
      access(
        join(outputRoot, "services", "kaf", "functions", "_middleware.func", ".vc-config.json"),
      ),
    ).resolves.toBeUndefined();
  }, 240_000);

  it("publishes named kaf schedules into the assembled host output", async () => {
    const app = await scenarioApp(NEXT_KAF_NAMED_SCHEDULES_DESCRIPTOR);

    await runVercelBuild(app.appRoot);

    const outputRoot = join(app.appRoot, ".vercel", "output");
    const config = await readVercelOutputConfig(outputRoot);
    expect(config.crons).toHaveLength(3);
    expect(config.crons).toEqual(
      expect.arrayContaining([
        { path: "/api/user-cleanup", schedule: "0 0 * * *" },
        {
          path: expect.stringMatching(/^\/kaf\/billing\/v1\/cron\/[A-Za-z0-9_-]+$/),
          schedule: "*/10 * * * *",
        },
        {
          path: expect.stringMatching(/^\/kaf\/support\/v1\/cron\/[A-Za-z0-9_-]+$/),
          schedule: "*/5 * * * *",
        },
      ]),
    );
  }, 240_000);
});
