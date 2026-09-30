import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type {
  CompiledAgentManifest,
  CompiledChannelDefinition,
  CompiledConnectionDefinition,
  CompiledInstructionsDefinition,
  CompiledScheduleDefinition,
  CompiledSkillDefinition,
  CompiledSubagentNode,
  CompiledToolDefinition,
} from "#compiler/manifest.js";
import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import {
  type VercelKafAgentSummary,
  type VercelKafChannelEntry,
  type VercelKafConnectionEntry,
  type VercelKafInstructionsEntry,
  type VercelKafScheduleEntry,
  type VercelKafSkillEntry,
  type VercelKafSubagentEntry,
  type VercelKafToolEntry,
  VERCEL_KAF_AGENT_SUMMARY_KIND,
  VERCEL_KAF_AGENT_SUMMARY_VERSION,
  normalizeChannelKindForDisplay,
} from "#internal/vercel-agent-summary.js";

/**
 * Builds the public {@link VercelKafAgentSummary} from a compiled agent
 * manifest. The result is the stable contract Vercel ingests from the
 * deployment build output — see {@link emitVercelAgentSummary} for the
 * write-out side.
 */
export function buildVercelAgentSummary(input: {
  manifest: CompiledAgentManifest;
  generatorVersion?: string;
}): VercelKafAgentSummary {
  const { manifest } = input;

  return {
    kind: VERCEL_KAF_AGENT_SUMMARY_KIND,
    schemaVersion: VERCEL_KAF_AGENT_SUMMARY_VERSION,
    generatorVersion: input.generatorVersion ?? resolveInstalledPackageInfo().version,
    agent:
      manifest.config.dynamicModel === undefined
        ? {
            name: manifest.config.name,
            description: manifest.config.description,
            modelId: manifest.config.model.id,
          }
        : {
            name: manifest.config.name,
            description: manifest.config.description,
            modelRouting: { kind: "dynamic" },
          },
    instructions: manifest.instructions.map(toInstructionsEntry),
    schedules: manifest.schedules.map(toScheduleEntry),
    tools: manifest.tools.map(toToolEntry),
    skills: manifest.skills.map(toSkillEntry),
    connections: manifest.connections.map(toConnectionEntry),
    channels: manifest.channelRoutes.effective.map(toChannelEntry),
    sandbox:
      manifest.sandbox === null
        ? null
        : {
            logicalPath: manifest.sandbox.logicalPath,
          },
    subagents: manifest.subagents.map(toSubagentEntry),
    diagnostics: {
      errors: manifest.diagnosticsSummary.errors,
      warnings: manifest.diagnosticsSummary.warnings,
    },
  };
}

/**
 * Writes the agent summary file. Returns the absolute path of the
 * written file.
 *
 * On Vercel deployments, the build container's
 * `upload-kaf-agent-summary.ts` helper picks up this file from
 * `rootPath` (which equals `appRoot` for the project being built) and
 * uploads it to `<projectId>/<deploymentId>/kaf_agent_summary.json` as
 * a top-level deployment artifact — the same tier as
 * `deploy_metadata.json` and `turbo_summary.json`. The dashboard reads
 * it through the dedicated
 * `/v6/deployments/:id/files/kaf-agent-summary` endpoint.
 *
 * For self-hosted setups (no Vercel build container in the loop), the
 * file simply sits on disk at the same path. Operators wire it up to
 * whatever surface they want.
 */
export async function emitVercelAgentSummary(input: {
  manifest: CompiledAgentManifest;
  generatorVersion?: string;
  outputPath: string;
}): Promise<string> {
  const summary = buildVercelAgentSummary({
    generatorVersion: input.generatorVersion,
    manifest: input.manifest,
  });
  await mkdir(dirname(input.outputPath), { recursive: true });
  await writeFile(input.outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  return input.outputPath;
}

function toInstructionsEntry(
  instructions: CompiledInstructionsDefinition,
): VercelKafInstructionsEntry {
  return {
    content: instructions.content,
    logicalPath: instructions.logicalPath,
    role: instructions.role,
    sourceKind: instructions.sourceKind,
  };
}

function toScheduleEntry(schedule: CompiledScheduleDefinition): VercelKafScheduleEntry {
  return {
    name: schedule.name,
    cron: schedule.cron,
    logicalPath: schedule.logicalPath,
  };
}

function toToolEntry(tool: CompiledToolDefinition): VercelKafToolEntry {
  return {
    name: tool.name,
    description: tool.description,
    logicalPath: tool.logicalPath,
  };
}

function toSkillEntry(skill: CompiledSkillDefinition): VercelKafSkillEntry {
  return {
    name: skill.name,
    description: skill.description,
    logicalPath: skill.logicalPath,
    sourceKind: skill.sourceKind,
  };
}

function toConnectionEntry(connection: CompiledConnectionDefinition): VercelKafConnectionEntry {
  const entry: VercelKafConnectionEntry = {
    name: connection.connectionName,
    description: connection.description,
    url: connection.url,
    logicalPath: connection.logicalPath,
    type: connection.protocol,
  };

  if (connection.vercelConnect !== undefined) {
    return {
      ...entry,
      vercelConnect: { connector: connection.vercelConnect.connector },
    };
  }

  return entry;
}

function toChannelEntry(channel: CompiledChannelDefinition): VercelKafChannelEntry {
  const entry: VercelKafChannelEntry = {
    name: channel.name,
    method: channel.method,
    urlPath: channel.urlPath,
    type: normalizeChannelKindForDisplay(channel.adapterKind),
    logicalPath: channel.logicalPath,
  };

  if (channel.adapterKind !== undefined) {
    return { ...entry, adapterKind: channel.adapterKind };
  }

  return entry;
}

function toSubagentEntry(subagent: CompiledSubagentNode): VercelKafSubagentEntry {
  return {
    name: subagent.name,
    description: subagent.description,
    logicalPath: subagent.logicalPath,
  };
}
