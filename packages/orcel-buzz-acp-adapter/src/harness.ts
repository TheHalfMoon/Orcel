import { mkdir, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { SHARED_PRINCIPAL_OPT_IN } from "./environment.js";

export interface HarnessDefinition {
  id: string;
  label: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  installInstructionsUrl: string;
  installHint: string;
}

export function buildHarnessDefinition(options: {
  buzzCli: string;
  cliPath: string;
  modelId: string;
  nodePath: string;
  target?: string;
  appDirectory?: string;
  vercelScope?: string;
  allowSharedPrincipal?: boolean;
}): HarnessDefinition {
  const env: Record<string, string> = {
    BUZZ_CLI: options.buzzCli,
    ORCEL_MODEL_ID: options.modelId,
  };
  if (options.appDirectory) env.ORCEL_APP_DIR = options.appDirectory;
  if (options.vercelScope) env.ORCEL_VERCEL_SCOPE = options.vercelScope;
  if (options.allowSharedPrincipal) env[SHARED_PRINCIPAL_OPT_IN] = "1";
  return {
    id: "orcel-buzz-acp-adapter",
    label: "orcel",
    command: options.nodePath,
    args: [options.cliPath, ...(options.target ? [options.target] : [])],
    env,
    installInstructionsUrl:
      "https://github.com/TheHalfMoon/orcel/tree/main/packages/orcel-buzz-acp-adapter#readme",
    installHint: "Install @orcel/buzz-acp-adapter globally, then run orcel-buzz-acp-adapter install.",
  };
}

export function defaultHarnessDirectory(
  environment: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): string {
  if (environment.BUZZ_CUSTOM_HARNESS_DIR) return environment.BUZZ_CUSTOM_HARNESS_DIR;
  if (platform === "darwin") {
    return join(
      homedir(),
      "Library",
      "Application Support",
      "xyz.block.buzz.app",
      "custom_harnesses",
    );
  }
  throw new Error("Set BUZZ_CUSTOM_HARNESS_DIR to the Buzz custom_harnesses directory");
}

export async function installHarness(
  directory: string,
  definition: HarnessDefinition,
): Promise<string> {
  await mkdir(directory, { recursive: true });
  const path = join(directory, `${definition.id}.json`);
  await writeFile(path, `${JSON.stringify(definition, null, 2)}\n`, { mode: 0o600 });
  return path;
}

export async function uninstallHarness(directory: string): Promise<string> {
  const path = join(directory, "orcel-buzz-acp-adapter.json");
  await rm(path, { force: true });
  return path;
}
