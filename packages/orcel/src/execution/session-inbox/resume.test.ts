import {
  sessionHandoffMarkerToken,
  sessionInboxHookToken,
} from "#execution/session-inbox/address.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HookNotFoundError } from "#compiled/@workflow/errors/index.js";
import { sessionCommandHookToken } from "#execution/session-inbox/address.js";
import { resolveSessionInbox, resumeSessionInbox } from "#execution/session-inbox/resume.js";

const resumeHookMock = vi.fn();
const getHookByTokenMock = vi.fn();

vi.mock("#internal/workflow/runtime.js", () => ({
  resumeHook: (...args: unknown[]) => resumeHookMock(...args),
  getHookByToken: (...args: unknown[]) => getHookByTokenMock(...args),
}));

afterEach(() => {
  resumeHookMock.mockReset();
  getHookByTokenMock.mockReset();
  vi.restoreAllMocks();
});

describe("session inbox resume", () => {
  it("resumes the current owner while preserving public session identity", async () => {
    const token = sessionCommandHookToken("session-1");
    const hook = sessionHook("owner-2", token, { sessionId: "session-1" });
    resumeHookMock.mockResolvedValue(hook);

    const receipt = await resumeSessionInbox(token, { kind: "clear" });
    expect(receipt.ownerRunId).toBe("owner-2");
    await expect(receipt.sessionId).resolves.toBe("session-1");
    expect(resumeHookMock).toHaveBeenCalledWith(sessionInboxHookToken(token), { kind: "clear" });
  });

  it("resolves a saved public address through the stable token", async () => {
    const token = sessionCommandHookToken("session-1");
    const hook = sessionHook("owner-2", token, { sessionId: "session-1" });
    resumeHookMock.mockResolvedValue(hook);

    await resumeSessionInbox({ sessionId: "session-1" }, { kind: "compact" });
    expect(resumeHookMock).toHaveBeenCalledWith(sessionInboxHookToken(token), { kind: "compact" });
  });
  it("does not hydrate metadata until an accepted alias caller asks for identity", async () => {
    const metadata = vi.fn(() => Promise.resolve({ sessionId: "anchor" }));
    const acceptance = Promise.withResolvers<{
      readonly runId: string;
      readonly metadata: Promise<unknown>;
    }>();
    resumeHookMock.mockReturnValue(acceptance.promise);
    const delivery = resumeSessionInbox("channel:alias", { kind: "clear" });
    expect(metadata).not.toHaveBeenCalled();
    acceptance.resolve({
      runId: "successor",
      get metadata() {
        return metadata();
      },
    });
    const receipt = await delivery;
    expect(metadata).not.toHaveBeenCalled();
    await expect(receipt.sessionId).resolves.toBe("anchor");
    await expect(receipt.sessionId).resolves.toBe("anchor");
    expect(metadata).toHaveBeenCalledOnce();
    expect(resumeHookMock).toHaveBeenCalledOnce();
  });

  it("never reads metadata for a known session address", async () => {
    resumeHookMock.mockResolvedValue({
      runId: "successor",
      get metadata() {
        throw new Error("Metadata must not be read");
      },
    });
    const receipt = await resumeSessionInbox({ sessionId: "anchor" }, { kind: "clear" });
    await expect(receipt.sessionId).resolves.toBe("anchor");
  });

  it("resolves the original session through an in-progress handoff gap", async () => {
    const token = "channel:handoff-alias";
    const physical = sessionInboxHookToken(token);
    const marker = sessionHandoffMarkerToken(token);
    let ownerLookups = 0;
    getHookByTokenMock.mockImplementation(async (target: string) => {
      if (target === marker) return { runId: "old-owner" };
      if (target !== physical) throw new HookNotFoundError("Unexpected legacy lookup");
      ownerLookups += 1;
      if (ownerLookups === 1) throw new HookNotFoundError("Owner is releasing the hook");
      return sessionHook("successor", physical, { sessionId: "original-session" });
    });

    await expect(resolveSessionInbox(token)).resolves.toEqual({
      sessionId: "original-session",
    });
    expect(ownerLookups).toBe(2);
    expect(getHookByTokenMock).toHaveBeenCalledWith(marker);
    expect(getHookByTokenMock).not.toHaveBeenCalledWith(token);
  });

  it("fails closed when a handoff marker outlives the retry window", async () => {
    const token = "channel:stalled-handoff";
    const marker = sessionHandoffMarkerToken(token);
    const physical = sessionInboxHookToken(token);
    const clock = vi.spyOn(Date, "now").mockReturnValueOnce(1_000).mockReturnValue(6_001);
    getHookByTokenMock.mockImplementation(async (target: string) => {
      if (target === marker) return { runId: "old-owner" };
      if (target === physical) throw new HookNotFoundError("No live hook yet");
      throw new HookNotFoundError("Unexpected legacy lookup");
    });

    await expect(resolveSessionInbox(token)).rejects.toMatchObject({
      name: "SessionHandoffPendingError",
    });
    expect(clock).toHaveBeenCalled();
    expect(getHookByTokenMock).toHaveBeenCalledWith(marker);
    expect(getHookByTokenMock).not.toHaveBeenCalledWith(token);
  });

  it("does not retry a missing hook into legacy while an expired handoff marker exists", async () => {
    const token = "channel:stalled-delivery";
    const marker = sessionHandoffMarkerToken(token);
    const physical = sessionInboxHookToken(token);
    vi.spyOn(Date, "now").mockReturnValueOnce(1_000).mockReturnValue(6_001);
    resumeHookMock.mockRejectedValue(new HookNotFoundError("Unclaimed during handoff"));
    getHookByTokenMock.mockImplementation(async (target: string) => {
      if (target === marker) return { runId: "prior-owner" };
      if (target === physical) throw new HookNotFoundError("No new owner yet");
      throw new HookNotFoundError("Unexpected legacy lookup");
    });

    await expect(resumeSessionInbox(token, { kind: "clear" })).rejects.toMatchObject({
      name: "SessionHandoffPendingError",
    });
    expect(resumeHookMock).toHaveBeenCalledOnce();
    expect(getHookByTokenMock).toHaveBeenCalledWith(marker);
    expect(getHookByTokenMock).not.toHaveBeenCalledWith(token);
  });

  it("does not substitute the executor for missing session identity", async () => {
    resumeHookMock.mockResolvedValue({ runId: "successor", metadata: Promise.resolve(undefined) });
    const receipt = await resumeSessionInbox("alias", { kind: "clear" });
    await expect(receipt.sessionId).rejects.toThrow("command accepted");
    expect(resumeHookMock).toHaveBeenCalledOnce();
  });
});

function sessionHook(runId: string, token: string, metadata: Record<string, unknown>) {
  return { metadata: Promise.resolve(metadata), runId, token };
}
