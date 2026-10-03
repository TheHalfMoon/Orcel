import { mkdir, rm, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import {
  VERCEL_ORCEL_AGENT_SUMMARY_OUTPUT_PATH,
  VERCEL_ORCEL_MULTI_AGENT_SUMMARY_KIND,
  VERCEL_ORCEL_MULTI_AGENT_SUMMARY_VERSION,
  type VercelOrcelMultiAgentSummary,
} from "#internal/vercel-agent-summary.js";
import type { AgentWorkspace } from "#internal/project-context.js";
import { assembleOrcelVercelServices } from "#internal/vercel/assemble-orcel-services.js";
import { buildMultiAgentLandingPage } from "#internal/vercel/build-multi-agent-landing-page.js";
import { quoteVercelShellArgument, toVercelRelativePath } from "#internal/vercel/build-command.js";
import { readVercelJsonFile } from "#internal/vercel/vercel-services-config.js";
import { resolveOrcelBinaryPath } from "#shared/resolve-orcel-binary.js";

const VERCEL_BUILD_OUTPUT_VERSION = 3;

function createMultiAgentSummary(workspace: AgentWorkspace): VercelOrcelMultiAgentSummary {
  return {
    agents: workspace.members.map((member) => ({
      name: member.name,
      routePrefix: `/orcel/${member.name}`,
      summaryPath: relative(
        workspace.root,
        join(member.appRoot, VERCEL_ORCEL_AGENT_SUMMARY_OUTPUT_PATH),
      ).replaceAll("\\", "/"),
    })),
    generatorVersion: resolveInstalledPackageInfo().version,
    kind: VERCEL_ORCEL_MULTI_AGENT_SUMMARY_KIND,
    schemaVersion: VERCEL_ORCEL_MULTI_AGENT_SUMMARY_VERSION,
  };
}

/** Emit the inferred Vercel Services project for a strict hostless workspace. */
export async function buildAgentWorkspace(
  workspace: AgentWorkspace,
  options: { readonly skipSandboxPrewarm?: boolean } = {},
): Promise<string> {
  const config = await readVercelJsonFile(join(workspace.root, "vercel.json"));
  if (
    config.services !== undefined ||
    config.experimentalServices !== undefined ||
    config.experimentalServicesV2 !== undefined
  ) {
    throw new Error(
      "This project defines its Vercel service graph in vercel.json. Compose generated workspace agents from a programmatic vercel.ts with `withEve` from `orcel/vercel`, manually define every service and run `vercel build`, or run `orcel build` from an individual agent directory.",
    );
  }

  const agents = workspace.members.map((member) => ({
    agent: {
      appRoot: member.appRoot,
      buildCommand: `node ${quoteVercelShellArgument(
        toVercelRelativePath(member.appRoot, resolveOrcelBinaryPath(member.appRoot)),
      )} build${options.skipSandboxPrewarm === true ? " --skip-sandbox-prewarm" : ""}`,
      devCommand: `node ${quoteVercelShellArgument(
        toVercelRelativePath(member.appRoot, resolveOrcelBinaryPath(member.appRoot)),
      )} dev --no-ui`,
      name: member.name,
      publicRoutePrefix: `/orcel/${member.name}`,
      workspaceMember: true,
    },
    target: {
      hostOutputDirectory: join(workspace.root, ".vercel", "output"),
      projectRoot: workspace.root,
    },
  }));
  const assembled = assembleOrcelVercelServices({ agents });

  const outputDirectory = join(workspace.root, ".vercel", "output");
  await rm(outputDirectory, { force: true, recursive: true });
  await mkdir(outputDirectory, { recursive: true });
  await Promise.all(
    assembled.rootDirectories.map((rootDirectory) => mkdir(rootDirectory, { recursive: true })),
  );
  await mkdir(join(workspace.root, ".orcel"), { recursive: true });
  await writeFile(
    join(workspace.root, VERCEL_ORCEL_AGENT_SUMMARY_OUTPUT_PATH),
    `${JSON.stringify(createMultiAgentSummary(workspace), null, 2)}\n`,
  );
  const staticDirectory = join(outputDirectory, "static");
  await mkdir(staticDirectory, { recursive: true });
  await writeFile(join(staticDirectory, "index.html"), buildMultiAgentLandingPage(workspace));
  await writeFile(
    join(outputDirectory, "config.json"),
    `${JSON.stringify(
      {
        version: VERCEL_BUILD_OUTPUT_VERSION,
        routes: [...assembled.routes, { handle: "filesystem" }],
        services: assembled.services,
      },
      null,
      2,
    )}\n`,
  );
  return outputDirectory;
}
