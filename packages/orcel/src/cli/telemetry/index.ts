import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import os from "node:os";

import {
  createOrcelTelemetryIdentity,
  isEphemeralOrcelTelemetryEnvironment,
  resolveOrcelTelemetryProjectId,
} from "#cli/telemetry/identity.js";
import {
  markOrcelTelemetryNotified,
  readOrcelTelemetryPreference,
  readOrCreateOrcelTelemetryIdentity,
} from "#cli/telemetry/preference.js";

type OrcelCliTelemetryEvent = {
  readonly id: string;
  readonly event_time: number;
  readonly key: string;
  readonly value: string;
};

export type OrcelCliSetupFlow = "init" | "extension_init" | "onboarding";
export type OrcelCliSetupStep =
  | "resolve_target"
  | "scaffold"
  | "install_dependencies"
  | "initialize_git"
  | "handoff"
  | "connection_ready"
  | "first_response"
  | "model_provider"
  | "model_settings"
  | "registry_channels"
  | "registry_integrations"
  | "registry_review"
  | "registry_install";
export type OrcelCliSetupTerminalResult = "completed" | "cancelled" | "error";

/** A bounded, non-sensitive reason for a failed setup terminal event. */
export type OrcelCliSetupFailureCode =
  | "target_resolution"
  | "target_conflict"
  | "target_invalid"
  | "target_filesystem"
  | "workspace_input"
  | "scaffolding"
  | "package_manager_not_found"
  | "package_manager_start_failed"
  | "workspace_probe_failed"
  | "workspace_probe_unrecognized"
  | "dependency_installation"
  | "git_initialization"
  | "handoff"
  | "onboarding";

export type OrcelCliSetupStepEvent = {
  flow: OrcelCliSetupFlow;
  step: OrcelCliSetupStep;
  registrySelectedCount?: number;
};

export type OrcelCliSetupTerminalEvent = {
  flow: OrcelCliSetupFlow;
  step: OrcelCliSetupStep;
  result: OrcelCliSetupTerminalResult;
  failureCode?: OrcelCliSetupFailureCode;
};

export type OrcelCliTelemetry = {
  trackCommand(command: string): void;
  trackDevContext(context: { target: "local" | "remote"; ui: "tui" | "headless" }): void;
  trackSetupStep(input: OrcelCliSetupStepEvent): void;
  trackSetupTerminal(input: OrcelCliSetupTerminalEvent): void;
  trackOutcome(outcome: "success" | "usage_error" | "error"): void;
  notify(logger: { error(message: string): void }): Promise<void>;
  flush(): Promise<void>;
};

async function isEnabled(): Promise<boolean> {
  return (
    process.env.NODE_ENV !== "test" &&
    !process.env.ORCEL_TELEMETRY_DISABLED &&
    (await readOrcelTelemetryPreference()).enabled
  );
}

function event(key: string, value: string): OrcelCliTelemetryEvent {
  return { id: randomUUID(), event_time: Date.now(), key, value };
}

function setupFailureCode(step: OrcelCliSetupStep): OrcelCliSetupFailureCode {
  switch (step) {
    case "resolve_target":
      return "target_resolution";
    case "scaffold":
      return "scaffolding";
    case "install_dependencies":
    case "registry_install":
      return "dependency_installation";
    case "initialize_git":
      return "git_initialization";
    case "handoff":
      return "handoff";
    case "connection_ready":
    case "first_response":
    case "model_provider":
    case "model_settings":
    case "registry_channels":
    case "registry_integrations":
    case "registry_review":
      return "onboarding";
  }
}

const CLI_TELEMETRY_COMMANDS = new Map<string, string>([
  ["acp", "acp"],
  ["add", "add"],
  ["build", "build"],
  ["deploy", "deploy"],
  ["dev", "dev"],
  ["eval", "eval"],
  ["extension", "extension"],
  ["extension:build", "extension:build"],
  ["extension:init", "extension:init"],
  ["info", "info"],
  ["init", "init"],
  ["integration", "integration"],
  ["integration:connect", "integration:connect"],
  ["integration:setup", "integration:setup"],
  ["remote", "remote"],
  ["remote:connect", "remote:connect"],
  ["remote:info", "remote:info"],
  ["remote:invoke", "remote:invoke"],
  ["link", "link"],
  ["logs", "logs:show"],
  ["logs:list", "logs:list"],
  ["logs:show", "logs:show"],
  ["registry", "registry"],
  ["registry:add", "registry:add"],
  ["registry:list", "registry:list"],
  ["registry:search", "registry:search"],
  ["registry:view", "registry:view"],
  ["set", "set"],
  ["set:model", "set:model"],
  ["start", "start"],
  ["telemetry", "telemetry"],
  ["telemetry:disable", "telemetry:disable"],
  ["telemetry:enable", "telemetry:enable"],
  ["telemetry:status", "telemetry:status"],
  ["traces", "traces"],
  ["traces:list", "traces:list"],
  ["traces:show", "traces:show"],
]);

/** Explicit privacy allowlist for command values emitted by CLI telemetry. */
export const cliTelemetryCommandPaths = new Set(CLI_TELEMETRY_COMMANDS.keys());

/** Internal command paths that must never emit telemetry. */
export const internalCliCommandPaths = new Set(["telemetry:flush"]);

/** Returns only an allowlisted command path; it never includes user input. */
export function canonicalCommand(argv: readonly string[]): string {
  const firstArgument = argv[0];
  if (firstArgument === "--help" || firstArgument === "-h") return "help";
  if (firstArgument === "--version" || firstArgument === "-V") return "version";

  const commandIndex = argv.findIndex((argument) => !argument.startsWith("-"));
  const command = argv[commandIndex];
  if (command === undefined || /^https?:\/\//.test(command)) return "dev";

  const nested = argv.slice(commandIndex + 1).find((argument) => !argument.startsWith("-"));
  if (nested !== undefined) {
    const normalizedNested = nested === "ls" ? "list" : nested;
    const nestedCommand = CLI_TELEMETRY_COMMANDS.get(`${command}:${normalizedNested}`);
    if (nestedCommand !== undefined) return nestedCommand;
  }
  if (command === "logs" || command === "traces") return `${command}:show`;
  return CLI_TELEMETRY_COMMANDS.get(command) ?? "unknown";
}

export function createOrcelCliTelemetry(version: string): OrcelCliTelemetry {
  const events: OrcelCliTelemetryEvent[] = [
    event("version", version),
    event("platform", os.platform()),
    event("arch", os.arch()),
    event("stdin_is_tty", process.stdin.isTTY ? "true" : "false"),
  ];
  const sessionId = randomUUID();
  const setupEvents: OrcelCliTelemetryEvent[] = [];
  let activeSetup: { flow: OrcelCliSetupFlow; step: OrcelCliSetupStep } | undefined;
  let setupTerminalRecorded = false;

  return {
    trackCommand(command) {
      events.push(event("command", command));
    },
    trackDevContext(context) {
      events.push(event("target", context.target), event("ui", context.ui));
    },
    trackSetupStep(input) {
      activeSetup = { flow: input.flow, step: input.step };
      setupEvents.push(event("setup_flow", input.flow), event("setup_step", input.step));
      if (input.registrySelectedCount !== undefined) {
        setupEvents.push(event("registry_selected_count", String(input.registrySelectedCount)));
      }
    },
    trackSetupTerminal(input) {
      setupTerminalRecorded = true;
      setupEvents.push(
        event("setup_flow", input.flow),
        event("setup_terminal_step", input.step),
        event("setup_terminal_result", input.result),
      );
      if (input.result === "error") {
        setupEvents.push(
          event("setup_failure_code", input.failureCode ?? setupFailureCode(input.step)),
        );
      }
    },
    trackOutcome(outcome) {
      if (activeSetup !== undefined && !setupTerminalRecorded) {
        this.trackSetupTerminal({
          ...activeSetup,
          result: outcome === "success" ? "completed" : "error",
        });
      }
      events.push(event("outcome", outcome));
    },
    async notify(logger) {
      const preference = await readOrcelTelemetryPreference();
      if (
        process.env.NODE_ENV === "test" ||
        process.env.ORCEL_TELEMETRY_DISABLED ||
        !preference.enabled ||
        preference.notified ||
        !process.stderr.isTTY
      ) {
        return;
      }
      logger.error(
        "Attention: orcel collects CLI telemetry to improve the command-line interface.\n" +
          "Disable it with `orcel telemetry disable`, or for one command set ORCEL_TELEMETRY_DISABLED=1.\n" +
          "Learn more: https://github.com/TheHalfMoon/orcel/docs/reference/telemetry",
      );
      try {
        await markOrcelTelemetryNotified();
      } catch {
        // Failing to persist the notice must not affect the command.
      }
    },
    async flush() {
      if (!(await isEnabled()) || events.length === 0) return;
      try {
        const ephemeralIdentity = isEphemeralOrcelTelemetryEnvironment();
        const identity = ephemeralIdentity
          ? createOrcelTelemetryIdentity()
          : await readOrCreateOrcelTelemetryIdentity();
        events.push(
          event("identity_kind", ephemeralIdentity ? "ephemeral" : "persistent"),
          event("installation_id", identity.installationId),
          event("project_id", await resolveOrcelTelemetryProjectId({ identity })),
        );
        events.push(...setupEvents);
      } catch {
        return;
      }
      if (process.env.ORCEL_TELEMETRY_DEBUG) {
        process.stderr.write(`[orcel telemetry] ${JSON.stringify(events)}\n`);
        return;
      }
      try {
        const child = spawn(
          process.execPath,
          [process.argv[1] ?? "", "telemetry", "flush", JSON.stringify({ events, sessionId })],
          {
            detached: true,
            env: { ...process.env, ORCEL_TELEMETRY_DISABLED: "1" },
            stdio: "ignore",
            windowsHide: true,
          },
        );
        child.on("error", () => {});
        child.unref();
      } catch {
        // Telemetry must never affect command output or exit status.
      }
    },
  };
}
