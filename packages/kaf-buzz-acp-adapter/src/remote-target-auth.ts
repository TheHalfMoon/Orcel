import {
  inspectVerifiedRemoteAgent,
  type Prompter,
  type VerifiedRemoteAgentInspection,
} from "kaf/setup";
import { parseKafTargetInfo, readKafTargetInfo, type KafTargetInfo } from "./kaf-target.js";
import type { InstallTarget } from "./install-flow.js";

interface RemoteTargetAuthDependencies {
  inspectVerifiedRemoteAgent(input: {
    serverUrl: string;
    workspaceRoot: string;
    prompter?: Prompter;
  }): Promise<VerifiedRemoteAgentInspection>;
  readKafTargetInfo: typeof readKafTargetInfo;
}

const defaultDependencies: RemoteTargetAuthDependencies = {
  inspectVerifiedRemoteAgent,
  readKafTargetInfo,
};

export async function readInstallTargetInfo(options: {
  cwd: string;
  kafBin: string;
  prompter?: Prompter;
  target: InstallTarget;
  dependencies?: Partial<RemoteTargetAuthDependencies>;
}): Promise<{ info: KafTargetInfo; vercelScope?: string }> {
  const dependencies = { ...defaultDependencies, ...options.dependencies };
  if (options.target.kind === "local") {
    return {
      info: await dependencies.readKafTargetInfo({
        cwd: options.target.directory,
        kafBin: options.kafBin,
      }),
    };
  }

  const inspectionOptions: Parameters<typeof dependencies.inspectVerifiedRemoteAgent>[0] = {
    serverUrl: options.target.url,
    workspaceRoot: options.cwd,
  };
  if (options.prompter !== undefined) inspectionOptions.prompter = options.prompter;
  const inspection = await dependencies.inspectVerifiedRemoteAgent(inspectionOptions);
  const result: { info: KafTargetInfo; vercelScope?: string } = {
    info: parseKafTargetInfo(inspection.info),
  };
  if (inspection.vercelScope !== undefined) result.vercelScope = inspection.vercelScope;
  return result;
}
