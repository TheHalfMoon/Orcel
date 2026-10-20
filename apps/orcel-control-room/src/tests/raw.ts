// Test support: sends one raw line to the app API and collects the parsed
// frames, so tests can send what the client itself refuses to send.

import { parseServerFrame } from "../agentkit/protocol/validation.js";
import type { ServerFrame } from "../agentkit/protocol/index.js";
import type { AppApiConnector } from "../agentkit/transport/orceld-transport.js";

export async function exchange(
  connector: AppApiConnector,
  line: string,
  done: (frames: ServerFrame[]) => boolean = (frames) => frames.length >= 1,
  timeoutMs = 20_000,
  options: { peerMayReset?: boolean } = {},
): Promise<{ frames: ServerFrame[]; ended: boolean }> {
  const connection = await connector.connect();
  const frames: ServerFrame[] = [];
  let ended = false;
  const timer = setTimeout(() => connection.close(), timeoutMs);
  try {
    // Only for a frame orceld refuses unread (`peerMayReset`): it answers
    // and closes before reading the rest, so the write may fail while its
    // answer is still readable. Everywhere else a reset is a failure.
    await connection.send(line).catch((error: unknown) => {
      if (!(options.peerMayReset && closedByPeer(error))) throw error;
    });
    try {
      for await (const text of connection.lines()) {
        frames.push(parseServerFrame(text));
        if (done(frames)) return { frames, ended };
      }
    } catch (error) {
      // A Unix socket closed with unread input resets the connection after
      // the frames already sent: for a refused frame that is the close.
      if (!(options.peerMayReset && closedByPeer(error))) throw error;
    }
    ended = true;
    return { frames, ended };
  } finally {
    clearTimeout(timer);
    connection.close();
  }
}

function closedByPeer(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === "ECONNRESET" || code === "EPIPE";
}
