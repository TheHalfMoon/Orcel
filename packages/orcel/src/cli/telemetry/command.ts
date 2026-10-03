import type { Command } from "#compiled/commander/index.js";
import { flushOrcelCliTelemetry } from "#cli/telemetry/flush.js";
import { readOrcelTelemetryPreference, setOrcelTelemetryEnabled } from "#cli/telemetry/preference.js";

type TelemetryLogger = {
  log(message: string): void;
};

export function registerOrcelTelemetryCommands(program: Command, logger: TelemetryLogger): void {
  const telemetry = program
    .command("telemetry")
    .description("Enable or disable CLI telemetry collection.");
  telemetry
    .command("status")
    .description("Show whether telemetry collection is enabled.")
    .action(async () => {
      await showOrcelTelemetryStatus(logger);
    });
  telemetry
    .command("enable")
    .description("Enable telemetry collection.")
    .action(async () => {
      await enableOrcelTelemetry(logger);
    });
  telemetry
    .command("disable")
    .description("Disable telemetry collection.")
    .action(async () => {
      await disableOrcelTelemetry(logger);
    });
  telemetry.command("flush <payload>", { hidden: true }).action(async (payload: string) => {
    await flushOrcelCliTelemetry(payload);
  });
}

export async function showOrcelTelemetryStatus(logger: TelemetryLogger): Promise<void> {
  const { enabled } = await readOrcelTelemetryPreference();
  logger.log(`Telemetry status: ${enabled ? "Enabled" : "Disabled"}`);
}

export async function enableOrcelTelemetry(logger: TelemetryLogger): Promise<void> {
  await setOrcelTelemetryEnabled(true);
  logger.log("Telemetry collection enabled.");
}

export async function disableOrcelTelemetry(logger: TelemetryLogger): Promise<void> {
  await setOrcelTelemetryEnabled(false);
  logger.log("Telemetry collection disabled. No data will be collected from this machine.");
}
