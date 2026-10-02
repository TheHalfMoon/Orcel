import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  spawn: vi.fn(),
}));

import { canonicalCommand, createOrcelCliTelemetry } from "#cli/telemetry/index.js";
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

vi.mock("#cli/telemetry/identity.js", () => ({
  createOrcelTelemetryIdentity: vi.fn(() => ({
    installationId: "ephemeral_installation_123",
    projectSalt: "ephemeral_project_salt_123",
  })),
  isEphemeralOrcelTelemetryEnvironment: vi.fn(() => false),
  resolveOrcelTelemetryProjectId: vi.fn(async () => "project_123"),
}));

vi.mock("#cli/telemetry/preference.js", () => ({
  markOrcelTelemetryNotified: vi.fn(),
  readOrcelTelemetryPreference: vi.fn(async () => ({ enabled: true, notified: false })),
  readOrCreateOrcelTelemetryIdentity: vi.fn(async () => ({
    installationId: "installation_123",
    projectSalt: "project_salt_123",
  })),
}));

afterEach(() => {
  vi.unstubAllEnvs();
  vi.clearAllMocks();
  vi.mocked(readOrcelTelemetryPreference)
    .mockReset()
    .mockResolvedValue({ enabled: true, notified: false });
  vi.mocked(readOrCreateOrcelTelemetryIdentity)
    .mockReset()
    .mockResolvedValue({ installationId: "installation_123", projectSalt: "project_salt_123" });
  vi.mocked(createOrcelTelemetryIdentity).mockReset().mockReturnValue({
    installationId: "ephemeral_installation_123",
    projectSalt: "ephemeral_project_salt_123",
  });
  vi.mocked(isEphemeralOrcelTelemetryEnvironment).mockReset().mockReturnValue(false);
});

describe("canonicalCommand", () => {
  it("records default and nested command paths without user-supplied values", () => {
    expect(canonicalCommand([])).toBe("dev");
    expect(canonicalCommand(["dev", "https://agent.example"])).toBe("dev");
    expect(canonicalCommand(["registry", "search", "private-query"])).toBe("registry:search");
    expect(canonicalCommand(["logs"])).toBe("logs:show");
    expect(canonicalCommand(["traces"])).toBe("traces:show");
  });

  it("records root help and version separately from the default command", () => {
    expect(canonicalCommand(["--help"])).toBe("help");
    expect(canonicalCommand(["-h"])).toBe("help");
    expect(canonicalCommand(["--version"])).toBe("version");
    expect(canonicalCommand(["-V"])).toBe("version");
  });

  it("records supported top-level commands and buckets unknown commands", () => {
    expect(canonicalCommand(["set", "--model", "private/model"])).toBe("set");
    expect(canonicalCommand(["not-a-command", "private-argument"])).toBe("unknown");
  });
});

describe("createOrcelCliTelemetry", () => {
  it("does not spawn a flush process when the environment override disables telemetry", async () => {
    vi.stubEnv("ORCEL_TELEMETRY_DISABLED", "1");
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("info");

    await telemetry.flush();

    expect(spawn).not.toHaveBeenCalled();
    expect(readOrcelTelemetryPreference).not.toHaveBeenCalled();
    expect(readOrCreateOrcelTelemetryIdentity).not.toHaveBeenCalled();
  });

  it("does not spawn a flush process when the durable preference disables telemetry", async () => {
    vi.mocked(readOrcelTelemetryPreference).mockResolvedValue({ enabled: false, notified: true });
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("info");

    await telemetry.flush();

    expect(spawn).not.toHaveBeenCalled();
    expect(readOrCreateOrcelTelemetryIdentity).not.toHaveBeenCalled();
  });

  it("prints and persists the first-run notice on an interactive terminal", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const stderr = Object.getOwnPropertyDescriptor(process.stderr, "isTTY");
    Object.defineProperty(process.stderr, "isTTY", { configurable: true, value: true });
    const logger = { error: vi.fn() };
    try {
      await createOrcelCliTelemetry("1.0.0").notify(logger);
    } finally {
      if (stderr === undefined) Reflect.deleteProperty(process.stderr, "isTTY");
      else Object.defineProperty(process.stderr, "isTTY", stderr);
    }

    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining("orcel telemetry disable"));
    expect(markOrcelTelemetryNotified).toHaveBeenCalled();
  });

  it("records resolved dev context without inspecting command arguments", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DEBUG", "1");
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("dev");
    telemetry.trackDevContext({ target: "remote", ui: "headless" });

    await telemetry.flush();

    const events = JSON.parse(
      String(write.mock.calls[0]?.[0]).replace("[orcel telemetry] ", ""),
    ) as Array<{
      key: string;
      value: string;
    }>;
    expect(events).toContainEqual(expect.objectContaining({ key: "target", value: "remote" }));
    expect(events).toContainEqual(expect.objectContaining({ key: "ui", value: "headless" }));
    expect(events).toContainEqual(
      expect.objectContaining({ key: "identity_kind", value: "persistent" }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: "installation_id", value: "installation_123" }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: "project_id", value: "project_123" }),
    );
    expect(resolveOrcelTelemetryProjectId).toHaveBeenCalledWith({
      identity: { installationId: "installation_123", projectSalt: "project_salt_123" },
    });
  });

  it("records timestamped connection readiness and first response without content", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DEBUG", "1");
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("dev");
    telemetry.trackSetupStep({ flow: "onboarding", step: "connection_ready" });
    telemetry.trackSetupTerminal({
      flow: "onboarding",
      step: "model_provider",
      result: "completed",
    });
    telemetry.trackSetupStep({ flow: "onboarding", step: "first_response" });
    await telemetry.flush();
    const events = JSON.parse(String(write.mock.calls[0]?.[0]).replace("[orcel telemetry] ", ""));
    for (const value of ["connection_ready", "first_response"])
      expect(events).toContainEqual(
        expect.objectContaining({ key: "setup_step", value, event_time: expect.any(Number) }),
      );
  });

  it("records the furthest init stage without error details", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DEBUG", "1");
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("init");
    telemetry.trackSetupStep({ flow: "init", step: "resolve_target" });
    telemetry.trackSetupStep({ flow: "init", step: "install_dependencies" });

    await telemetry.flush();

    const events = JSON.parse(
      String(write.mock.calls[0]?.[0]).replace("[orcel telemetry] ", ""),
    ) as Array<{ key: string; value: string }>;
    expect(events).toContainEqual(
      expect.objectContaining({ key: "setup_step", value: "install_dependencies" }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: "setup_step", value: "resolve_target" }),
    );
  });

  it("records the final onboarding stage without user selections", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DEBUG", "1");
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("dev");
    telemetry.trackSetupStep({ flow: "onboarding", step: "model_provider" });
    telemetry.trackSetupTerminal({ flow: "onboarding", step: "registry_install", result: "error" });

    await telemetry.flush();

    const events = JSON.parse(
      String(write.mock.calls[0]?.[0]).replace("[orcel telemetry] ", ""),
    ) as Array<{ key: string; value: string }>;
    expect(events).toContainEqual(
      expect.objectContaining({ key: "setup_terminal_step", value: "registry_install" }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: "setup_step", value: "model_provider" }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: "setup_failure_code", value: "dependency_installation" }),
    );
  });

  it("records an explicit bounded setup failure category", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DEBUG", "1");
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("init");
    telemetry.trackSetupStep({ flow: "init", step: "resolve_target" });
    telemetry.trackSetupTerminal({
      flow: "init",
      step: "resolve_target",
      result: "error",
      failureCode: "target_resolution",
    });

    await telemetry.flush();

    const events = JSON.parse(
      String(write.mock.calls[0]?.[0]).replace("[orcel telemetry] ", ""),
    ) as Array<{ key: string; value: string }>;
    expect(events).toContainEqual(
      expect.objectContaining({ key: "setup_failure_code", value: "target_resolution" }),
    );
  });

  it("skips telemetry when identity initialization fails", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.mocked(readOrCreateOrcelTelemetryIdentity).mockRejectedValue(new Error("read-only config"));
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("info");

    await expect(telemetry.flush()).resolves.toBeUndefined();

    expect(spawn).not.toHaveBeenCalled();
  });

  it("uses an in-memory identity in an ephemeral environment", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DEBUG", "1");
    vi.mocked(isEphemeralOrcelTelemetryEnvironment).mockReturnValue(true);
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("info");

    await telemetry.flush();

    expect(readOrCreateOrcelTelemetryIdentity).not.toHaveBeenCalled();
    expect(createOrcelTelemetryIdentity).toHaveBeenCalledOnce();
    const events = JSON.parse(
      String(write.mock.calls[0]?.[0]).replace("[orcel telemetry] ", ""),
    ) as Array<{ key: string; value: string }>;
    expect(events).toContainEqual(
      expect.objectContaining({ key: "identity_kind", value: "ephemeral" }),
    );
    expect(events).toContainEqual(
      expect.objectContaining({ key: "installation_id", value: "ephemeral_installation_123" }),
    );
  });

  it("flushes an allowlisted outcome through a telemetry-disabled child process", async () => {
    const child = Object.assign(new EventEmitter(), { unref: vi.fn() });
    vi.mocked(spawn).mockReturnValue(child as never);
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("ORCEL_TELEMETRY_DISABLED", "");
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("info");
    telemetry.trackOutcome("usage_error");

    await telemetry.flush();

    expect(spawn).toHaveBeenCalledWith(
      process.execPath,
      expect.arrayContaining([process.argv[1], "telemetry", "flush"]),
      expect.objectContaining({
        detached: true,
        env: expect.objectContaining({ ORCEL_TELEMETRY_DISABLED: "1" }),
      }),
    );
    expect(child.unref).toHaveBeenCalled();
    const payload = JSON.parse(vi.mocked(spawn).mock.calls[0]![1][3]!) as {
      events: Array<{ key: string; value: string }>;
    };
    expect(payload.events).toContainEqual(
      expect.objectContaining({ key: "outcome", value: "usage_error" }),
    );
    expect(payload.events).not.toContainEqual(expect.objectContaining({ key: "error_code" }));
    expect(payload.events).not.toContainEqual(expect.objectContaining({ key: "error_status" }));
  });

  it("ignores asynchronous child-process errors", async () => {
    const child = Object.assign(new EventEmitter(), { unref: vi.fn() });
    vi.mocked(spawn).mockReturnValue(child as never);
    vi.stubEnv("NODE_ENV", "production");
    const telemetry = createOrcelCliTelemetry("1.0.0");
    telemetry.trackCommand("info");

    await telemetry.flush();

    expect(() => child.emit("error", new Error("spawn failed"))).not.toThrow();
    expect(child.unref).toHaveBeenCalled();
  });
});
