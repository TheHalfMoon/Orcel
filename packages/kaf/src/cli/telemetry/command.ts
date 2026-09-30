import type { Command } from "#compiled/commander/index.js";
import { flushKafCliTelemetry } from "#cli/telemetry/flush.js";
import { readKafTelemetryPreference, setKafTelemetryEnabled } from "#cli/telemetry/preference.js";

type TelemetryLogger = {
  log(message: string): void;
};

export function registerKafTelemetryCommands(program: Command, logger: TelemetryLogger): void {
  const telemetry = program
    .command("telemetry")
    .description("Enable or disable CLI telemetry collection.");
  telemetry
    .command("status")
    .description("Show whether telemetry collection is enabled.")
    .action(async () => {
      await showKafTelemetryStatus(logger);
    });
  telemetry
    .command("enable")
    .description("Enable telemetry collection.")
    .action(async () => {
      await enableKafTelemetry(logger);
    });
  telemetry
    .command("disable")
    .description("Disable telemetry collection.")
    .action(async () => {
      await disableKafTelemetry(logger);
    });
  telemetry.command("flush <payload>", { hidden: true }).action(async (payload: string) => {
    await flushKafCliTelemetry(payload);
  });
}

export async function showKafTelemetryStatus(logger: TelemetryLogger): Promise<void> {
  const { enabled } = await readKafTelemetryPreference();
  logger.log(`Telemetry status: ${enabled ? "Enabled" : "Disabled"}`);
}

export async function enableKafTelemetry(logger: TelemetryLogger): Promise<void> {
  await setKafTelemetryEnabled(true);
  logger.log("Telemetry collection enabled.");
}

export async function disableKafTelemetry(logger: TelemetryLogger): Promise<void> {
  await setKafTelemetryEnabled(false);
  logger.log("Telemetry collection disabled. No data will be collected from this machine.");
}
