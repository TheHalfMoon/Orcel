// Test support only (#398 item 4). The production connector refuses every
// Windows pipe because Node cannot verify the pipe server's account
// (orceld-transport.ts header). The live tests start orceld themselves, so
// on Windows they connect through this one, which skips that verification.
// It lives in src/tests/, which tsconfig.build.json (the production build)
// does not compile, so no shipped code can reach it.

import net from "node:net";

import {
  connectEndpoint,
  SocketConnection,
  type AppApiConnector,
  type FrameConnection,
} from "../agentkit/transport/orceld-transport.js";

const CONNECT_TIMEOUT_MS = 5_000;

/** Opens `pipe` without verifying its server. Tests only. */
function connectUnverifiedPipe(pipe: string): Promise<FrameConnection> {
  return new Promise<FrameConnection>((resolve, reject) => {
    const socket = net.createConnection({ path: pipe });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connecting to ${pipe} timed out`));
    }, CONNECT_TIMEOUT_MS);
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.removeAllListeners("error");
      resolve(new SocketConnection(socket));
    });
  });
}

/**
 * The connector for tests: the production checks on Unix, and on Windows
 * the unverified pipe connect for a daemon the test itself started.
 */
export function unverifiedTestConnector(endpoint: string): AppApiConnector {
  return {
    endpoint,
    connect: () =>
      process.platform === "win32" ? connectUnverifiedPipe(endpoint) : connectEndpoint(endpoint),
  };
}
