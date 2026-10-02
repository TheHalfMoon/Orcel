import { afterEach, describe, expect, it, vi } from "vitest";

import {
  disableOrcelTelemetry,
  enableOrcelTelemetry,
  showOrcelTelemetryStatus,
} from "#cli/telemetry/command.js";
import { readOrcelTelemetryPreference, setOrcelTelemetryEnabled } from "#cli/telemetry/preference.js";

vi.mock("#cli/telemetry/preference.js", () => ({
  readOrcelTelemetryPreference: vi.fn(async () => ({ enabled: true, notified: false })),
  setOrcelTelemetryEnabled: vi.fn(),
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("orcel telemetry", () => {
  it("reports the durable preference", async () => {
    vi.mocked(readOrcelTelemetryPreference).mockResolvedValue({ enabled: false, notified: true });
    const logger = { log: vi.fn() };

    await showOrcelTelemetryStatus(logger);

    expect(logger.log).toHaveBeenCalledWith("Telemetry status: Disabled");
  });

  it("updates the durable preference", async () => {
    const logger = { log: vi.fn() };

    await enableOrcelTelemetry(logger);
    await disableOrcelTelemetry(logger);

    expect(setOrcelTelemetryEnabled).toHaveBeenNthCalledWith(1, true);
    expect(setOrcelTelemetryEnabled).toHaveBeenNthCalledWith(2, false);
  });
});
