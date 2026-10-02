import {
  inspectVerifiedRemoteAgent,
  type Prompter,
  type VerifiedRemoteAgentInspection,
} from "orcel/setup";
import { parseOrcelTargetInfo, readOrcelTargetInfo, type OrcelTargetInfo } from "./orcel-target.js";
import type { InstallTarget } from "./install-flow.js";

interface RemoteTargetAuthDependencies {
  inspectVerifiedRemoteAgent(input: {
    serverUrl: string;
    workspaceRoot: string;
    prompter?: Prompter;
  }): Promise<VerifiedRemoteAgentInspection>;
  readOrcelTargetInfo: typeof readOrcelTargetInfo;
}

const defaultDependencies: RemoteTargetAuthDependencies = {
  inspectVerifiedRemoteAgent,
  readOrcelTargetInfo,
};

export async function readInstallTargetInfo(options: {
  cwd: string;
  orcelBin: string;
  prompter?: Prompter;
  target: InstallTarget;
  dependencies?: Partial<RemoteTargetAuthDependencies>;
}): Promise<{ info: OrcelTargetInfo; vercelScope?: string }> {
  const dependencies = { ...defaultDependencies, ...options.dependencies };
  if (options.target.kind === "local") {
    return {
      info: await dependencies.readOrcelTargetInfo({
        cwd: options.target.directory,
        orcelBin: options.orcelBin,
      }),
    };
  }

  const inspectionOptions: Parameters<typeof dependencies.inspectVerifiedRemoteAgent>[0] = {
    serverUrl: options.target.url,
    workspaceRoot: options.cwd,
  };
  if (options.prompter !== undefined) inspectionOptions.prompter = options.prompter;
  const inspection = await dependencies.inspectVerifiedRemoteAgent(inspectionOptions);
  const result: { info: OrcelTargetInfo; vercelScope?: string } = {
    info: parseOrcelTargetInfo(inspection.info),
  };
  if (inspection.vercelScope !== undefined) result.vercelScope = inspection.vercelScope;
  return result;
}
