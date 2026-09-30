import { afterEach, describe, expect, it, vi } from "vitest";

import {
  disableKafTelemetry,
  enableKafTelemetry,
  showKafTelemetryStatus,
} from "#cli/telemetry/command.js";
import { readKafTelemetryPreference, setKafTelemetryEnabled } from "#cli/telemetry/preference.js";

vi.mock("#cli/telemetry/preference.js", () => ({
  readKafTelemetryPreference: vi.fn(async () => ({ enabled: true, notified: false })),
  setKafTelemetryEnabled: vi.fn(),
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("kaf telemetry", () => {
  it("reports the durable preference", async () => {
    vi.mocked(readKafTelemetryPreference).mockResolvedValue({ enabled: false, notified: true });
    const logger = { log: vi.fn() };

    await showKafTelemetryStatus(logger);

    expect(logger.log).toHaveBeenCalledWith("Telemetry status: Disabled");
  });

  it("updates the durable preference", async () => {
    const logger = { log: vi.fn() };

    await enableKafTelemetry(logger);
    await disableKafTelemetry(logger);

    expect(setKafTelemetryEnabled).toHaveBeenNthCalledWith(1, true);
    expect(setKafTelemetryEnabled).toHaveBeenNthCalledWith(2, false);
  });
});
