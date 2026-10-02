import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";

import {
  createOrcelTelemetryIdentity,
  type OrcelCliTelemetryIdentity,
} from "#cli/telemetry/identity.js";
import { dirname, isAbsolute, join } from "node:path";

import { z } from "#compiled/zod/index.js";

const ORCEL_TELEMETRY_NOTICE_VERSION = 1;

type OrcelTelemetryPreference = {
  readonly enabled: boolean;
  readonly notified: boolean;
};

function configuredDirectory(value: string | undefined, fallback: string): string {
  return value && isAbsolute(value) ? value : fallback;
}

function orcelConfigPath(): string {
  const home = homedir();
  if (process.platform === "win32") {
    return join(
      configuredDirectory(process.env.APPDATA, join(home, "AppData", "Roaming")),
      "orcel",
      "config.json",
    );
  }
  if (process.platform === "darwin") {
    return join(home, "Library", "Preferences", "orcel", "config.json");
  }
  return join(
    configuredDirectory(process.env.XDG_CONFIG_HOME, join(home, ".config")),
    "orcel",
    "config.json",
  );
}

const OrcelConfigSchema = z.looseObject({
  telemetry: z
    .looseObject({
      enabled: z.boolean().default(true),
      installationId: z.string().optional(),
      noticeVersion: z.number().int().positive().optional(),
      notifiedAt: z.string().optional(),
      projectSalt: z.string().optional(),
    })
    .optional(),
});

function parsePreference(value: unknown): OrcelTelemetryPreference {
  const telemetry = OrcelConfigSchema.safeParse(value).data?.telemetry;
  return {
    enabled: telemetry?.enabled ?? true,
    notified: telemetry?.noticeVersion === ORCEL_TELEMETRY_NOTICE_VERSION,
  };
}

export async function readOrcelTelemetryPreference(): Promise<OrcelTelemetryPreference> {
  try {
    return parsePreference(JSON.parse(await readFile(orcelConfigPath(), "utf8")) as unknown);
  } catch {
    return { enabled: true, notified: false };
  }
}

export async function readOrCreateOrcelTelemetryIdentity(): Promise<OrcelCliTelemetryIdentity> {
  let telemetry: z.infer<typeof OrcelConfigSchema>["telemetry"];
  try {
    telemetry = OrcelConfigSchema.safeParse(
      JSON.parse(await readFile(orcelConfigPath(), "utf8")) as unknown,
    ).data?.telemetry;
  } catch {
    // An absent or malformed config starts with a fresh telemetry identity.
  }

  const identity =
    telemetry?.installationId && telemetry.projectSalt
      ? { installationId: telemetry.installationId, projectSalt: telemetry.projectSalt }
      : createOrcelTelemetryIdentity();
  if (
    telemetry?.installationId !== identity.installationId ||
    telemetry?.projectSalt !== identity.projectSalt
  ) {
    await updateOrcelTelemetryPreference(identity);
  }
  return identity;
}

async function updateOrcelTelemetryPreference(
  update: Record<string, boolean | number | string>,
): Promise<void> {
  const path = orcelConfigPath();
  let existing: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
    if (typeof parsed === "object" && parsed !== null) existing = parsed as Record<string, unknown>;
  } catch {
    // An absent or malformed config starts with the telemetry preference.
  }

  const telemetry =
    typeof existing.telemetry === "object" && existing.telemetry !== null ? existing.telemetry : {};
  const next = { ...existing, telemetry: { ...telemetry, ...update } };
  const temporaryPath = `${path}.${process.pid}.${Date.now()}.tmp`;
  await mkdir(dirname(path), { recursive: true });
  try {
    await writeFile(temporaryPath, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, path);
  } catch (error) {
    await rm(temporaryPath, { force: true });
    throw error;
  }
}

export async function setOrcelTelemetryEnabled(enabled: boolean): Promise<void> {
  await updateOrcelTelemetryPreference({ enabled });
}

export async function markOrcelTelemetryNotified(): Promise<void> {
  await updateOrcelTelemetryPreference({
    noticeVersion: ORCEL_TELEMETRY_NOTICE_VERSION,
    notifiedAt: new Date().toISOString(),
  });
}
