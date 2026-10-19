// Orcel code. CR-02 step 2: the transport the AgentKit-derived client uses to
// reach orceld's app API (CR-01). AgentKit's own transport is HTTP
// (packages/agentkit/src/adapters, not taken); this one is the local IPC
// endpoint of ORCEL_APP_API_1.md section 1. It only connects: it never
// listens, never starts a server and never spawns orceld.
//
// Endpoint authentication follows CR-01's rules:
// - Unix: the socket lives in the private state root. Before connecting the
//   client checks, without following links, that `run/` is a directory this
//   uid owns with no group or other permission and that the socket is a
//   socket this uid owns. Another user's socket, a symbolic link or a
//   non-socket is refused before any byte is sent.
// - Windows: the pipe `\\.\pipe\orcel-<user SID>-app` carries a DACL for the
//   user only, so another account's open is refused by the OS. Node's
//   libuv opens pipes without SECURITY_SQOS_PRESENT, so this connector
//   cannot meet ORCEL_APP_API_1.md section 7's identification-only open or
//   confirm the server's account; the CR-03 Tauri bridge (Rust) must, and
//   until then this connector is for headless and test use. The client
//   sends nothing but read-only requests either way.

import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import net from "node:net";
import path from "node:path";

import { LineDecoder } from "./framing.js";

/** One connection to the app API: lines out, lines in. */
export interface FrameConnection {
  send(line: string): Promise<void>;
  /** Server lines in order. Ends when the server closes; throws on errors. */
  lines(): AsyncIterable<string>;
  close(): void;
}

/** Opens connections to one app API endpoint. */
export interface AppApiConnector {
  readonly endpoint: string;
  connect(): Promise<FrameConnection>;
}

/** The endpoint is not private to this user, or cannot be named. */
export class EndpointRefusedError extends Error {
  public constructor(
    public readonly endpoint: string,
    reason: string,
  ) {
    super(`refusing app API endpoint ${endpoint}: ${reason}`);
    this.name = "EndpointRefusedError";
  }
}

type Env = Record<string, string | undefined>;

/** `ORCEL_APP_API_INSTANCE`: 1-32 of a-z, 0-9 and -, as orceld reads it. */
export function instanceSuffix(value: string | undefined): string {
  if (value === undefined) return "";
  if (!/^[a-z0-9-]{1,32}$/u.test(value)) {
    throw new EndpointRefusedError(
      "(unnamed)",
      "ORCEL_APP_API_INSTANCE must be 1-32 characters of a-z, 0-9 and -",
    );
  }
  return `-${value}`;
}

function usableUnixAbsolute(value: string | undefined): string | undefined {
  if (!value || !value.startsWith("/")) return undefined;
  const parts = value.split("/");
  return parts.some((part) => part === "." || part === "..") ? undefined : value;
}

/**
 * The Unix state root as `orcel_platform::paths::state_root` derives it.
 * Paths are joined with POSIX separators so the rule is testable anywhere.
 */
export function unixStateRoot(platform: NodeJS.Platform, env: Env): string {
  const home = usableUnixAbsolute(env.HOME);
  if (platform === "darwin") {
    if (!home) throw new EndpointRefusedError("(unnamed)", "HOME is not an absolute path");
    return path.posix.join(home, "Library", "Application Support", "Orcel");
  }
  const stateHome = usableUnixAbsolute(env.XDG_STATE_HOME);
  if (stateHome) return path.posix.join(stateHome, "orcel");
  if (!home) {
    throw new EndpointRefusedError(
      "(unnamed)",
      "XDG_STATE_HOME or HOME is not an absolute path",
    );
  }
  return path.posix.join(home, ".local", "state", "orcel");
}

export function unixSocketPath(platform: NodeJS.Platform, env: Env): string {
  return path.posix.join(
    unixStateRoot(platform, env),
    "run",
    `app-api${instanceSuffix(env.ORCEL_APP_API_INSTANCE)}.sock`,
  );
}

export function windowsPipeName(sid: string, env: Env): string {
  if (!/^S-1-[0-9-]+$/u.test(sid)) {
    throw new EndpointRefusedError("(unnamed)", `"${sid}" is not a user SID`);
  }
  return `\\\\.\\pipe\\orcel-${sid}-app${instanceSuffix(env.ORCEL_APP_API_INSTANCE)}`;
}

/** The current user's SID, from the system's whoami (never a PATH lookup). */
export function currentUserSid(env: Env = process.env): Promise<string> {
  const systemRoot = env.SystemRoot ?? env.SYSTEMROOT ?? "C:\\Windows";
  const whoami = path.win32.join(systemRoot, "System32", "whoami.exe");
  return new Promise((resolve, reject) => {
    execFile(
      whoami,
      ["/user", "/fo", "csv", "/nh"],
      { windowsHide: true, timeout: 10_000 },
      (error, stdout) => {
        if (error) {
          reject(new EndpointRefusedError("(unnamed)", `whoami failed: ${error.message}`));
          return;
        }
        const sid = /"(S-1-[0-9-]+)"/u.exec(stdout)?.[1];
        if (sid) resolve(sid);
        else reject(new EndpointRefusedError("(unnamed)", "whoami printed no SID"));
      },
    );
  });
}

/** The default endpoint orceld serves for this user on this OS. */
export async function defaultEndpoint(env: Env = process.env): Promise<string> {
  if (process.platform === "win32") {
    return windowsPipeName(await currentUserSid(env), env);
  }
  return unixSocketPath(process.platform, env);
}

/**
 * Unix: refuses an endpoint another user could have placed. The private
 * directory is what keeps other users out; this checks it is really ours.
 */
export async function assertPrivateUnixEndpoint(socketPath: string): Promise<void> {
  const uid = process.getuid?.();
  if (uid === undefined) return;
  const directory = path.posix.dirname(socketPath);
  const dir = await lstat(directory).catch((error: NodeJS.ErrnoException) => {
    throw new EndpointRefusedError(socketPath, `${directory}: ${error.code ?? error.message}`);
  });
  if (dir.isSymbolicLink() || !dir.isDirectory()) {
    throw new EndpointRefusedError(socketPath, `${directory} is not a directory`);
  }
  if (dir.uid !== uid) {
    throw new EndpointRefusedError(socketPath, `${directory} is owned by uid ${dir.uid}`);
  }
  if ((dir.mode & 0o077) !== 0) {
    throw new EndpointRefusedError(
      socketPath,
      `${directory} grants group or other access (mode ${(dir.mode & 0o777).toString(8)})`,
    );
  }
  const socket = await lstat(socketPath).catch((error: NodeJS.ErrnoException) => {
    throw new EndpointRefusedError(socketPath, error.code ?? error.message);
  });
  if (!socket.isSocket()) {
    throw new EndpointRefusedError(socketPath, "is not a socket");
  }
  if (socket.uid !== uid) {
    throw new EndpointRefusedError(socketPath, `is owned by uid ${socket.uid}`);
  }
}

class SocketConnection implements FrameConnection {
  private readonly decoder = new LineDecoder();
  private readonly queue: string[] = [];
  private failure: unknown;
  private ended = false;
  private wake: (() => void) | undefined;

  public constructor(private readonly socket: net.Socket) {
    socket.on("data", (chunk: Buffer) => {
      try {
        this.queue.push(...this.decoder.push(chunk));
      } catch (error) {
        this.fail(error);
        socket.destroy();
      }
      this.notify();
    });
    socket.on("end", () => {
      this.ended = true;
      this.notify();
    });
    socket.on("close", () => {
      this.ended = true;
      this.notify();
    });
    socket.on("error", (error) => {
      this.fail(error);
      this.notify();
    });
  }

  private fail(error: unknown): void {
    if (this.failure === undefined) this.failure = error;
  }

  private notify(): void {
    const wake = this.wake;
    this.wake = undefined;
    wake?.();
  }

  public send(line: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.socket.destroyed || !this.socket.writable) {
        reject(new Error("the app API connection is closed"));
        return;
      }
      this.socket.write(line, "utf8", (error) => (error ? reject(error) : resolve()));
    });
  }

  public async *lines(): AsyncIterable<string> {
    for (;;) {
      const line = this.queue.shift();
      if (line !== undefined) {
        yield line;
        continue;
      }
      if (this.failure !== undefined) throw this.failure;
      if (this.ended) return;
      await new Promise<void>((resolve) => {
        this.wake = resolve;
      });
    }
  }

  public close(): void {
    this.ended = true;
    this.socket.destroy();
    this.notify();
  }
}

export interface OrceldTransportOptions {
  /** A pipe name or socket path; defaults to this user's orceld endpoint. */
  endpoint?: string;
  /** Milliseconds to wait for the connection to open. */
  connectTimeoutMs?: number;
}

/** Connects to `endpoint` once its privacy checks pass. */
export function connectEndpoint(
  endpoint: string,
  connectTimeoutMs = 5_000,
): Promise<FrameConnection> {
  return (async () => {
    if (process.platform !== "win32") await assertPrivateUnixEndpoint(endpoint);
    return new Promise<FrameConnection>((resolve, reject) => {
      const socket = net.createConnection({ path: endpoint });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error(`connecting to ${endpoint} timed out`));
      }, connectTimeoutMs);
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
  })();
}

/** `orceldTransport`: the connector the Control Room client uses. */
export async function orceldTransport(
  options: OrceldTransportOptions = {},
): Promise<AppApiConnector> {
  const endpoint = options.endpoint ?? (await defaultEndpoint());
  return {
    endpoint,
    connect: () => connectEndpoint(endpoint, options.connectTimeoutMs),
  };
}
