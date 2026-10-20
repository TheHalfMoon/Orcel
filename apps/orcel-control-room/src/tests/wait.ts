// Test support: waits for a client state or condition with a deadline.

import type { ControlRoomClient, ControlRoomState } from "../agentkit/client/index.js";

export function waitForState(
  client: ControlRoomClient,
  predicate: (state: ControlRoomState) => boolean,
  label: string,
  timeoutMs = 20_000,
): Promise<ControlRoomState> {
  return new Promise((resolve, reject) => {
    if (predicate(client.getState())) {
      resolve(client.getState());
      return;
    }
    const timer = setTimeout(() => {
      off();
      reject(new Error(`timed out waiting for ${label}; state: ${JSON.stringify({ ...client.getState(), events: client.getState().events.length, status: undefined, capabilities: undefined, lastSnapshot: undefined })}`));
    }, timeoutMs);
    const off = client.onState((state) => {
      if (!predicate(state)) return;
      clearTimeout(timer);
      off();
      resolve(state);
    });
  });
}
