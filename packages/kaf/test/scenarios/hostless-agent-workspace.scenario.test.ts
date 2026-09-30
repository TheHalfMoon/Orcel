import { access, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { useScenarioApp } from "../../src/internal/testing/scenario-app.js";
import { runPnpmCommand } from "../../src/internal/testing/run-pnpm-command.js";

const VERCEL_VERSION = "59.5.0";
const scenarioApp = useScenarioApp();

describe("hostless agent workspace", () => {
  it("assembles every direct child as a peer Vercel service", async () => {
    const app = await scenarioApp({
      files: {
        "agents/research/agent/agent.mjs": `import { defineAgent } from "kaf";\nexport default defineAgent({ model: "openai/gpt-5.4" });\n`,
        "agents/research/agent/instructions.md": "You are the research agent.\n",
        "agents/support/agent/agent.mjs": `import { defineAgent } from "kaf";\nexport default defineAgent({ model: "openai/gpt-5.4" });\n`,
        "agents/support/agent/instructions.md": "You are the support agent.\n",
        ".vercel/project.json": `${JSON.stringify(
          {
            orgId: "team_kaf_scenario",
            projectId: "prj_kaf_collection_scenario",
            projectName: "hostless-agent-workspace",
            settings: {
              buildCommand: "pnpm exec kaf build --skip-sandbox-prewarm",
              framework: null,
              outputDirectory: null,
              rootDirectory: null,
            },
          },
          null,
          2,
        )}\n`,
        "pnpm-workspace.yaml": "minimumReleaseAge: 0\n",
      },
      dependencies: { vercel: VERCEL_VERSION },
      installDependencies: true,
      name: "hostless-agent-workspace",
    });
    await runPnpmCommand({
      args: ["exec", "vercel", "build", "--yes"],
      cwd: app.appRoot,
    });

    const outputRoot = join(app.appRoot, ".vercel", "output");
    const config = JSON.parse(await readFile(join(outputRoot, "config.json"), "utf8"));
    expect(config.routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          destination: { service: "kaf-support", type: "service" },
          src: "^/kaf/support/v1/(.*)$",
        }),
        expect.objectContaining({
          destination: { service: "kaf-research", type: "service" },
          src: "^/kaf/research/v1/(.*)$",
        }),
      ]),
    );
    await expect(
      access(join(outputRoot, "services", "kaf-support", "functions", "__server.func")),
    ).resolves.toBeUndefined();
    await expect(
      access(join(outputRoot, "services", "kaf-research", "functions", "__server.func")),
    ).resolves.toBeUndefined();
  }, 240_000);
});
