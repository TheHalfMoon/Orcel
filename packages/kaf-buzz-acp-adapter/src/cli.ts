#!/usr/bin/env node

import { existsSync } from "node:fs";
import { access } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPrompter, WizardCancelledError } from "kaf/setup";
import { SHARED_PRINCIPAL_OPT_IN } from "./environment.js";
import { readKafTargetInfo, resolveBundledKafBin } from "./kaf-target.js";
import {
  buildHarnessDefinition,
  defaultHarnessDirectory,
  installHarness,
  uninstallHarness,
} from "./harness.js";
import {
  chooseInstallTarget,
  classifyRemoteTarget,
  classifyTarget,
  confirmInstall,
  type InstallPrompter,
  type InstallTarget,
} from "./install-flow.js";
import { runProxy } from "./proxy.js";
import { readInstallTargetInfo } from "./remote-target-auth.js";

interface CliOptions {
  command: "run" | "install" | "uninstall" | "doctor" | "help";
  target?: string;
  targetKind?: "local" | "remote";
  kafBin: string;
  buzzCli: string;
  harnessDirectory?: string;
  modelId?: string;
  allowSharedPrincipal: boolean;
  yes: boolean;
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  if (options.command === "help") {
    printHelp();
    return;
  }

  const cwd = process.env.KAF_APP_DIR || process.cwd();
  const explicitTarget = resolveExplicitTarget(options, cwd);
  if (options.command === "install") {
    await runInstall(options, cwd, explicitTarget);
    return;
  }

  if (options.command === "uninstall") {
    const directory =
      options.harnessDirectory ?? defaultHarnessDirectory(process.env, process.platform);
    const path = await uninstallHarness(directory);
    console.log(`Removed the kaf Buzz harness at ${path}`);
    return;
  }

  if (options.command === "doctor") {
    await access(options.kafBin);
    const info = await readKafTargetInfo(
      explicitTarget
        ? kafTargetOptions(explicitTarget, options.kafBin)
        : { kafBin: options.kafBin, cwd },
    );
    console.log(`kaf target: ${info.name}`);
    console.log(`authored model: ${info.modelId}`);
    console.log(`kaf executable: ${options.kafBin}`);
    console.log(`Buzz CLI: ${options.buzzCli}`);
    return;
  }

  let modelId = options.modelId ?? process.env.KAF_MODEL_ID;
  if (!modelId) {
    try {
      modelId = (
        await readKafTargetInfo(
          explicitTarget
            ? kafTargetOptions(explicitTarget, options.kafBin)
            : { kafBin: options.kafBin, cwd },
        )
      ).modelId;
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.error(`[kaf-buzz-acp-adapter] could not discover the authored model: ${detail}`);
    }
  }

  const environment = options.allowSharedPrincipal
    ? { ...process.env, [SHARED_PRINCIPAL_OPT_IN]: "1" }
    : process.env;
  const proxyOptions: Parameters<typeof runProxy>[0] = {
    buzzCli: options.buzzCli,
    cwd: explicitTarget?.kind === "local" ? explicitTarget.directory : cwd,
    environment,
    kafBin: options.kafBin,
    input: process.stdin,
    output: process.stdout,
    publicationStateDirectory:
      process.env.BUZZ_PUBLISH_STATE_DIR ??
      join(homedir(), ".buzz", "kaf-buzz-acp-adapter", "publications"),
    publishTimeoutMs: Number(process.env.BUZZ_PUBLISH_TIMEOUT_MS || 20_000),
  };
  if (modelId) proxyOptions.modelId = modelId;
  if (explicitTarget?.kind === "remote") proxyOptions.target = explicitTarget.url;
  await runProxy(proxyOptions);
}

async function runInstall(
  options: CliOptions,
  cwd: string,
  explicitTarget: InstallTarget | undefined,
): Promise<void> {
  const interactive = process.stdin.isTTY === true && process.stdout.isTTY === true;
  const prompter = interactive ? createPrompter() : undefined;
  prompter?.intro("kaf + Buzz", "Connect an kaf agent to Buzz.");

  const chooseOptions: Parameters<typeof chooseInstallTarget>[0] = { cwd, interactive };
  if (explicitTarget) chooseOptions.explicitTarget = explicitTarget;
  if (prompter) chooseOptions.prompter = prompter as InstallPrompter;
  const target = await chooseInstallTarget(chooseOptions);
  const { info, vercelScope } = await readInstallTargetInfo({
    cwd,
    kafBin: options.kafBin,
    prompter,
    target,
  });
  const directory =
    options.harnessDirectory ?? defaultHarnessDirectory(process.env, process.platform);
  prompter?.log.success(`Found ${info.name}`);
  prompter?.log.info(`Authored model: ${info.modelId}`);
  prompter?.log.info(`Target: ${target.kind === "remote" ? target.url : target.directory}`);
  prompter?.log.info(`Buzz CLI: ${options.buzzCli}`);
  prompter?.log.info(
    options.allowSharedPrincipal
      ? "Author gate: shared kaf authentication explicitly enabled"
      : "Author gate: Buzz Respond to must remain Owner only",
  );
  prompter?.log.info(`Harness: ${join(directory, "kaf-buzz-acp-adapter.json")}`);

  const confirmOptions: Parameters<typeof confirmInstall>[0] = {
    interactive,
    yes: options.yes,
  };
  if (prompter) confirmOptions.prompter = prompter as InstallPrompter;
  if (!(await confirmInstall(confirmOptions))) {
    prompter?.outro("No changes made.");
    return;
  }

  const harnessOptions: Parameters<typeof buildHarnessDefinition>[0] = {
    buzzCli: options.buzzCli,
    cliPath: fileURLToPath(import.meta.url),
    modelId: options.modelId ?? info.modelId,
    nodePath: process.execPath,
  };
  if (vercelScope) harnessOptions.vercelScope = vercelScope;
  if (options.allowSharedPrincipal) harnessOptions.allowSharedPrincipal = true;
  if (target.kind === "remote") harnessOptions.target = target.url;
  else harnessOptions.appDirectory = target.directory;
  const path = await installHarness(directory, buildHarnessDefinition(harnessOptions));

  const authorGateNotice = options.allowSharedPrincipal
    ? "Shared-principal mode is enabled: every sender accepted by Buzz will use the same kaf authentication and connections."
    : "Keep the Buzz agent's Respond to setting on Owner only.";
  if (prompter) {
    prompter.log.success(`Installed the Buzz harness at ${path}`);
    prompter.log.info(authorGateNotice);
    prompter.outro("Reopen Buzz, then select kaf as the agent harness.");
  } else {
    console.log(`Installed the kaf Buzz harness at ${path}`);
    console.log(authorGateNotice);
    console.log("Reopen Buzz, then select kaf as the agent harness.");
  }
}

function kafTargetOptions(
  target: InstallTarget,
  kafBin: string,
): Parameters<typeof readKafTargetInfo>[0] {
  if (target.kind === "remote") return { kafBin, target: target.url, cwd: process.cwd() };
  return { kafBin, cwd: target.directory };
}

function resolveExplicitTarget(options: CliOptions, cwd: string): InstallTarget | undefined {
  if (!options.target) return undefined;
  if (options.targetKind === "local") {
    return { kind: "local", directory: resolve(cwd, options.target) };
  }
  if (options.targetKind === "remote") return classifyRemoteTarget(options.target);
  return classifyTarget(options.target, cwd);
}

function parseArguments(arguments_: string[]): CliOptions {
  let command: CliOptions["command"] = "run";
  let target: string | undefined;
  let targetKind: CliOptions["targetKind"];
  let kafBin = process.env.KAF_BIN || resolveBundledKafBin();
  let buzzCli = process.env.BUZZ_CLI || defaultBuzzCli();
  let harnessDirectory: string | undefined;
  let modelId: string | undefined;
  let allowSharedPrincipal = false;
  let yes = false;

  const argumentsCopy = [...arguments_];
  if (["install", "uninstall", "doctor"].includes(argumentsCopy[0] ?? "")) {
    command = argumentsCopy.shift() as CliOptions["command"];
  } else if (["help", "--help", "-h"].includes(argumentsCopy[0] ?? "")) {
    return { command: "help", kafBin, buzzCli, allowSharedPrincipal, yes };
  }

  while (argumentsCopy.length > 0) {
    const argument = argumentsCopy.shift()!;
    if (argument === "--kaf-bin") kafBin = requiredValue(argument, argumentsCopy.shift());
    else if (argument === "--buzz-cli") buzzCli = requiredValue(argument, argumentsCopy.shift());
    else if (argument === "--harness-dir") {
      harnessDirectory = requiredValue(argument, argumentsCopy.shift());
    } else if (argument === "--model") modelId = requiredValue(argument, argumentsCopy.shift());
    else if (argument === "--local" || argument === "--url") {
      if (target !== undefined) throw new Error("Specify only one target");
      target = requiredValue(argument, argumentsCopy.shift());
      targetKind = argument === "--local" ? "local" : "remote";
    } else if (argument === "--allow-shared-principal") allowSharedPrincipal = true;
    else if (argument === "--yes" || argument === "-y") yes = true;
    else if (argument.startsWith("-")) throw new Error(`Unknown option: ${argument}`);
    else if (target === undefined) target = argument;
    else throw new Error(`Unexpected argument: ${argument}`);
  }

  const options: CliOptions = { command, kafBin, buzzCli, allowSharedPrincipal, yes };
  if (target) options.target = target;
  if (targetKind) options.targetKind = targetKind;
  if (harnessDirectory) options.harnessDirectory = harnessDirectory;
  if (modelId) options.modelId = modelId;
  return options;
}

function defaultBuzzCli(): string {
  const macOsBundledCli = "/Applications/Buzz.app/Contents/MacOS/buzz";
  return process.platform === "darwin" && existsSync(macOsBundledCli) ? macOsBundledCli : "buzz";
}

function requiredValue(option: string, value: string | undefined): string {
  if (!value) throw new Error(`${option} requires a value`);
  return value;
}

function printHelp(): void {
  console.log(`Usage:
  kaf-buzz-acp-adapter [target]
  kaf-buzz-acp-adapter install [target]
  kaf-buzz-acp-adapter uninstall
  kaf-buzz-acp-adapter doctor [target]

Targets may be a local kaf application directory or an HTTP(S) deployment URL.
Running install without a target starts the interactive setup flow.

Options:
  --local <directory>    local kaf application directory
  --url <url>            deployed kaf application URL
  --allow-shared-principal
                         allow accepted Buzz senders to share kaf authentication
  -y, --yes              confirm a non-interactive install
  --kaf-bin <path>       kaf executable to launch
  --buzz-cli <path>      Buzz CLI executable
  --harness-dir <path>   Buzz custom_harnesses directory
  --model <id>           authored kaf model override`);
}

main().catch((error: unknown) => {
  if (error instanceof WizardCancelledError) {
    process.exitCode = 1;
    return;
  }
  const detail = error instanceof Error ? error.message : String(error);
  console.error(`[kaf-buzz-acp-adapter] ${detail}`);
  process.exitCode = 1;
});
