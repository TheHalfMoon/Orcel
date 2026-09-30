import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:fs/promises", () => ({
  mkdir: vi.fn(),
  readFile: vi.fn(),
  rename: vi.fn(),
  rm: vi.fn(),
  writeFile: vi.fn(),
}));

import {
  markKafTelemetryNotified,
  readKafTelemetryPreference,
  readOrCreateKafTelemetryIdentity,
  setKafTelemetryEnabled,
} from "#cli/telemetry/preference.js";

const originalPlatform = process.platform;

afterEach(() => {
  Object.defineProperty(process, "platform", { value: originalPlatform });
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

describe("kaf telemetry preference", () => {
  it("defaults to enabled before a preference exists", async () => {
    vi.mocked(readFile).mockRejectedValue(new Error("missing"));

    await expect(readKafTelemetryPreference()).resolves.toEqual({ enabled: true, notified: false });
  });

  it("reads a persisted opt-out and current notice version", async () => {
    vi.mocked(readFile).mockResolvedValue(
      '{"telemetry":{"enabled":false,"noticeVersion":1,"notifiedAt":"now"}}',
    );

    await expect(readKafTelemetryPreference()).resolves.toEqual({ enabled: false, notified: true });
  });

  it("shows the versioned notice when only an older notice timestamp exists", async () => {
    vi.mocked(readFile).mockResolvedValue('{"telemetry":{"notifiedAt":"now"}}');

    await expect(readKafTelemetryPreference()).resolves.toEqual({ enabled: true, notified: false });
  });

  it("creates and persists a telemetry identity", async () => {
    vi.mocked(readFile).mockRejectedValue(new Error("missing"));

    const identity = await readOrCreateKafTelemetryIdentity();

    expect(identity.installationId).toMatch(/^[0-9a-f-]{36}$/);
    expect(identity.projectSalt).toMatch(/^[0-9a-f-]{36}$/);
    expect(writeFile).toHaveBeenCalledWith(
      expect.any(String),
      expect.stringContaining(identity.installationId),
      { mode: 0o600 },
    );
    expect(writeFile).toHaveBeenCalledWith(
      expect.any(String),
      expect.stringContaining(identity.projectSalt),
      { mode: 0o600 },
    );
  });

  it("ignores a relative XDG config home", async () => {
    Object.defineProperty(process, "platform", { value: "linux" });
    vi.stubEnv("XDG_CONFIG_HOME", "relative-config");
    vi.mocked(readFile).mockRejectedValue(new Error("missing"));

    await setKafTelemetryEnabled(false);

    expect(mkdir).toHaveBeenCalledWith(join(homedir(), ".config", "kaf"), { recursive: true });
  });

  it("merges telemetry changes into the kaf config atomically", async () => {
    Object.defineProperty(process, "platform", { value: "linux" });
    const directory = join("/kaf-config", "kaf");
    const temporaryPrefix = `${join(directory, "config.json")}.`;
    vi.stubEnv("XDG_CONFIG_HOME", "/kaf-config");
    vi.mocked(readFile)
      .mockResolvedValueOnce('{"other":"preserved","telemetry":{"future":"preserved"}}')
      .mockResolvedValueOnce(
        '{"other":"preserved","telemetry":{"future":"preserved","enabled":false}}',
      );

    await setKafTelemetryEnabled(false);
    await markKafTelemetryNotified();

    expect(mkdir).toHaveBeenCalledWith(directory, { recursive: true });
    expect(writeFile).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining(temporaryPrefix),
      expect.stringContaining('"other": "preserved"'),
      { mode: 0o600 },
    );
    expect(writeFile).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining(temporaryPrefix),
      expect.stringContaining('"future": "preserved"'),
      { mode: 0o600 },
    );
    expect(writeFile).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining(temporaryPrefix),
      expect.stringContaining('"enabled": false'),
      { mode: 0o600 },
    );
    expect(writeFile).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining(temporaryPrefix),
      expect.stringContaining('"noticeVersion": 1'),
      { mode: 0o600 },
    );
    expect(writeFile).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining(temporaryPrefix),
      expect.stringContaining('"notifiedAt"'),
      { mode: 0o600 },
    );
    expect(rename).toHaveBeenCalledTimes(2);
    expect(rename).toHaveBeenCalledWith(
      expect.stringContaining(temporaryPrefix),
      join(directory, "config.json"),
    );
  });

  it.each([
    ["darwin", join(homedir(), "Library", "Preferences", "kaf")],
    ["win32", join(homedir(), "AppData", "Roaming", "kaf")],
    ["linux", join(homedir(), ".config", "kaf")],
  ])("uses the native config directory on %s", async (platform, directory) => {
    Object.defineProperty(process, "platform", { value: platform });
    vi.stubEnv("XDG_CONFIG_HOME", "");
    vi.stubEnv("APPDATA", "");
    vi.mocked(readFile).mockRejectedValue(new Error("missing"));

    await setKafTelemetryEnabled(false);

    expect(mkdir).toHaveBeenCalledWith(directory, { recursive: true });
    expect(rename).toHaveBeenCalledWith(expect.any(String), join(directory, "config.json"));
  });
});
