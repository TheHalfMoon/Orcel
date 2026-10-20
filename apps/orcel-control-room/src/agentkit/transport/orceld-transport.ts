// Orcel code. CR-02 step 2: the transport the AgentKit-derived client uses to
// reach orceld's app API (CR-01). AgentKit's own transport is HTTP
// (packages/agentkit/src/adapters, not taken); this one is the local IPC
// endpoint of ORCEL_APP_API_1.md section 1. It only connects: it never
// listens, never starts a server and never spawns orceld.
//
// Endpoint authentication follows CR-01's rules:
// - Unix: the socket lives in a private `orcel` directory of the user's
//   short runtime directory (macOS DARWIN_USER_TEMP_DIR, Linux
//   XDG_RUNTIME_DIR; #381), or in `run/` of the state root without one.
//   Before connecting the client checks, without following links, that the
//   directory is one this uid owns with no group or other permission and
//   that the socket is a socket this uid owns. Another user's socket, a
//   symbolic link or a non-socket is refused before any byte is sent.
// - Windows: the pipe `\\.\pipe\orcel-<user SID>-app` carries a DACL for the
//   user only, so another account cannot open orceld's pipe. But the pipe
//   namespace is shared: another account can create that name first, and
//   the client must then refuse it (ORCEL_APP_API_1.md section 7). Node's
//   libuv opens pipes without SECURITY_SQOS_PRESENT (so the server could
//   impersonate the client) and cannot read the server's process or token,
//   so this connector cannot verify the server. It therefore REFUSES to
//   connect on Windows. The `allowUnverifiedWindowsPipe` opt-in is
//   test-only and the code enforces it (#381 item 2): it is refused unless
//   the process environment also sets UNVERIFIED_PIPE_TEST_ENV to "1",
//   which only this package's `npm test` does (test.env). The Windows
//   Control Room transport is the CR-03 Tauri bridge (Rust), which must open
//   with SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION and compare the
//   token user of GetNamedPipeServerProcessId with its own.

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

/**
 * The directory orceld binds its socket in, as CR-01 `unix::socket_dir`
 * derives it (#381): `<darwinTempDir>/orcel` on macOS when the system names
 * the per-user temp directory, `$XDG_RUNTIME_DIR/orcel` on Linux when it is
 * an absolute path, and `<state root>/run` otherwise. HOME never decides
 * the location when a runtime directory exists, so a long home still fits
 * in a socket address.
 */
export function unixSocketDir(
  platform: NodeJS.Platform,
  env: Env,
  darwinTempDir?: string,
): string {
  if (platform === "darwin") {
    const temp = usableUnixAbsolute(darwinTempDir);
    if (temp) return path.posix.join(temp, "orcel");
  } else {
    const runtime = usableUnixAbsolute(env.XDG_RUNTIME_DIR);
    if (runtime) return path.posix.join(runtime, "orcel");
  }
  return path.posix.join(unixStateRoot(platform, env), "run");
}

export function unixSocketPath(
  platform: NodeJS.Platform,
  env: Env,
  darwinTempDir?: string,
): string {
  return path.posix.join(
    unixSocketDir(platform, env, darwinTempDir),
    `app-api${instanceSuffix(env.ORCEL_APP_API_INSTANCE)}.sock`,
  );
}

/**
 * macOS: the per-user temp directory (`/var/folders/<xx>/<id>/T/`), asked
 * of the system with `getconf DARWIN_USER_TEMP_DIR`, the same confstr value
 * orceld reads, never TMPDIR. Undefined when the system does not answer.
 */
export function darwinUserTempDir(): Promise<string | undefined> {
  return new Promise((resolve) => {
    execFile(
      "/usr/bin/getconf",
      ["DARWIN_USER_TEMP_DIR"],
      { timeout: 10_000 },
      (error, stdout) => {
        const dir = stdout.trim();
        resolve(!error && dir.startsWith("/") ? dir : undefined);
      },
    );
  });
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
  const darwinTempDir = process.platform === "darwin" ? await darwinUserTempDir() : undefined;
  return unixSocketPath(process.platform, env, darwinTempDir);
}

/**
 * Unix: refuses an endpoint another user could have placed. The private
 * directory is what keeps other users out; this checks it is really ours.
 */
export async function assertPrivateUnixEndpoint(socketPath: string): Promise<void> {
  const uid = process.getuid?.();
  if (uid === undefined) return;
  const length = Buffer.byteLength(socketPath, "utf8");
  if (length > MAX_UNIX_SOCKET_PATH) {
    // orceld refuses the same path (CR-01 unix::bind), so nothing can be
    // listening there; say why instead of failing with ENAMETOOLONG.
    throw new EndpointRefusedError(
      socketPath,
      `is ${length} bytes, longer than the ${MAX_UNIX_SOCKET_PATH} a Unix socket allows; set XDG_RUNTIME_DIR (Linux), or use a shorter HOME or XDG_STATE_HOME`,
    );
  }
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

/** orceld's limit: `sun_path` holds 104 bytes on macOS, 108 on Linux. */
export const MAX_UNIX_SOCKET_PATH = 100;

/**
 * Lines buffered for a consumer that lags. The queue never holds more than
 * the high mark: bytes are decoded one line at a time and only while there
 * is room (#381 item 3), and the socket is paused while any read bytes wait
 * undecoded. So at most this many frames (each at most 64 KiB) plus the
 * read chunks that arrived before the pause wait in memory. Reading resumes
 * once those chunks are decoded and the queue is down to the low mark.
 */
export const LINE_QUEUE_HIGH = 256;
export const LINE_QUEUE_LOW = 64;

const NEWLINE = 0x0a;

/** The part of a net.Socket a connection uses. */
export type LineSocket = Pick<
  net.Socket,
  "on" | "pause" | "resume" | "isPaused" | "destroy" | "write" | "destroyed" | "writable"
>;

export class SocketConnection implements FrameConnection {
  private readonly decoder = new LineDecoder();
  private readonly queue: string[] = [];
  /** Read but not yet decoded: what arrived while the queue was full. */
  private readonly held: Buffer[] = [];
  private failure: unknown;
  private ended = false;
  private wake: (() => void) | undefined;

  public constructor(private readonly socket: LineSocket) {
    socket.on("data", (chunk: Buffer) => {
      this.held.push(chunk);
      this.fill();
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

  /** Lines waiting for the consumer; never more than LINE_QUEUE_HIGH. */
  public get queuedLines(): number {
    return this.queue.length;
  }

  /**
   * Decodes held bytes into the queue, one line at a time, while the queue
   * has room, and pauses the socket while bytes are still held.
   */
  private fill(): void {
    try {
      while (this.queue.length < LINE_QUEUE_HIGH && this.held.length > 0) {
        const chunk = this.held[0] as Buffer;
        const newline = chunk.indexOf(NEWLINE);
        if (newline === -1) {
          // Part of a frame: the decoder buffers it (and enforces 64 KiB).
          this.held.shift();
          this.queue.push(...this.decoder.push(chunk));
          continue;
        }
        const rest = chunk.subarray(newline + 1);
        if (rest.length > 0) this.held[0] = rest;
        else this.held.shift();
        // Bytes up to one newline decode to at most one line.
        this.queue.push(...this.decoder.push(chunk.subarray(0, newline + 1)));
      }
    } catch (error) {
      this.held.length = 0;
      this.fail(error);
      this.socket.destroy();
      return;
    }
    if ((this.held.length > 0 || this.queue.length >= LINE_QUEUE_HIGH) && !this.socket.isPaused()) {
      this.socket.pause();
    }
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
        this.fill();
        if (this.held.length === 0 && this.queue.length <= LINE_QUEUE_LOW && this.socket.isPaused()) {
          this.socket.resume();
        }
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
  /**
   * Windows only, tests only: connect although the pipe server's account
   * cannot be verified from Node (see the header). Default false: refuse.
   * Refused anyway unless UNVERIFIED_PIPE_TEST_ENV is "1".
   */
  allowUnverifiedWindowsPipe?: boolean;
}

export interface ConnectOptions {
  connectTimeoutMs?: number;
  allowUnverifiedWindowsPipe?: boolean;
}

/** Why the default connector refuses Windows pipes. */
export const UNVERIFIED_WINDOWS_PIPE =
  "the pipe server's account cannot be verified from Node (no SECURITY_IDENTIFICATION open, " +
  "no GetNamedPipeServerProcessId check); the Windows Control Room transport is the CR-03 Rust bridge";

/**
 * The variable without which `allowUnverifiedWindowsPipe` is refused. Only
 * this package's test script sets it (`node --env-file=test.env`); the
 * Control Room never does, so a caller that passes the option outside the
 * tests gets an error instead of an unverified connection.
 */
export const UNVERIFIED_PIPE_TEST_ENV = "ORCEL_CONTROL_ROOM_UNVERIFIED_PIPE_TEST";

/** Why the opt-in itself was refused. */
export const UNVERIFIED_PIPE_TEST_ONLY =
  `allowUnverifiedWindowsPipe is test-only: it is honoured only when ${UNVERIFIED_PIPE_TEST_ENV}=1, ` +
  "which only this package's npm test sets";

/** Connects to `endpoint` once its privacy checks pass. */
export function connectEndpoint(
  endpoint: string,
  options: ConnectOptions = {},
): Promise<FrameConnection> {
  const connectTimeoutMs = options.connectTimeoutMs ?? 5_000;
  return (async () => {
    if (process.platform === "win32") {
      if (options.allowUnverifiedWindowsPipe !== true) {
        throw new EndpointRefusedError(endpoint, UNVERIFIED_WINDOWS_PIPE);
      }
      if (process.env[UNVERIFIED_PIPE_TEST_ENV] !== "1") {
        throw new EndpointRefusedError(endpoint, UNVERIFIED_PIPE_TEST_ONLY);
      }
    } else {
      await assertPrivateUnixEndpoint(endpoint);
    }
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
    connect: () =>
      connectEndpoint(endpoint, {
        ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
        allowUnverifiedWindowsPipe: options.allowUnverifiedWindowsPipe === true,
      }),
  };
}
