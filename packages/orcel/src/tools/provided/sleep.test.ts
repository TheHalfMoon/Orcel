import { afterEach, describe, expect, it, vi } from "vitest";

import { sleep as workflowSleep } from "#compiled/@workflow/core/index.js";
import { sleep } from "#tools/provided/sleep.js";
import { isWorkflowToolDefinition } from "#tools/workflow-definition.js";

vi.mock("#compiled/@workflow/core/index.js", () => ({
  sleep: vi.fn(),
}));

describe("sleep", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("defines a model-facing tool", () => {
    const definition = sleep();

    expect(isWorkflowToolDefinition(definition)).toBe(true);
    expect(definition.description).toContain("before continuing");
    expect(definition.execute).toBeTypeOf("function");
  });

  it("returns interrupted when the signal was already aborted before execution", async () => {
    vi.mocked(workflowSleep).mockImplementation(() => new Promise<void>(() => {}));
    const definition = sleep();
    const output = definition.execute({ seconds: 600 }, {
      abortSignal: AbortSignal.abort(),
    } as never);

    // An already-aborted call must not start a durable ten-minute timer.
    expect(workflowSleep).not.toHaveBeenCalled();
    await expect(output).resolves.toEqual({ interrupted: true });
  });

  it("returns interrupted when aborted while the durable sleep is pending", async () => {
    vi.mocked(workflowSleep).mockImplementation(() => new Promise<void>(() => {}));
    const controller = new AbortController();
    const added = vi.spyOn(controller.signal, "addEventListener");
    const removed = vi.spyOn(controller.signal, "removeEventListener");
    const output = sleep().execute({ seconds: 600 }, { abortSignal: controller.signal } as never);

    expect(workflowSleep).toHaveBeenCalledExactlyOnceWith(600_000);
    controller.abort();
    await expect(output).resolves.toEqual({ interrupted: true });
    expect(removed).toHaveBeenCalledExactlyOnceWith("abort", added.mock.calls[0]![1]);
  });

  it("removes the abort listener after a normally completed durable sleep", async () => {
    let wake: (() => void) | undefined;
    vi.mocked(workflowSleep).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          wake = resolve;
        }),
    );
    const controller = new AbortController();
    const added = vi.spyOn(controller.signal, "addEventListener");
    const removed = vi.spyOn(controller.signal, "removeEventListener");

    const output = sleep().execute({ seconds: 2 }, { abortSignal: controller.signal } as never);
    expect(workflowSleep).toHaveBeenCalledExactlyOnceWith(2_000);
    expect(added).toHaveBeenCalledTimes(1);
    expect(added).toHaveBeenCalledWith("abort", expect.any(Function), { once: true });
    wake?.();
    await expect(output).resolves.toEqual({ waitedSeconds: 2 });
    expect(removed).toHaveBeenCalledExactlyOnceWith("abort", added.mock.calls[0]![1]);
  });

  it("waits for the requested number of seconds in its workflow body", async () => {
    let wake: (() => void) | undefined;
    vi.mocked(workflowSleep).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          wake = resolve;
        }),
    );
    const definition = sleep();
    const abortSignal = new AbortController().signal;
    const output = definition.execute({ seconds: 2.5001 }, { abortSignal } as never);

    await vi.waitFor(() => {
      expect(workflowSleep).toHaveBeenCalledExactlyOnceWith(2_501);
    });

    wake?.();

    await expect(output).resolves.toEqual({ waitedSeconds: 2.5001 });
  });
});
