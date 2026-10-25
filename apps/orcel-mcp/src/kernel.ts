import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";

/**
 * SG-000055 remote dispatch context. Supplied only by the device uplink
 * from a verified relay route at kernel construction; never derived from
 * tool arguments. `orceld` requires an exact active local remote-session
 * lease for every request that carries it.
 */
export interface RemoteDispatchContext {
  readonly principal: string;
  readonly remoteConnectionId: string;
  readonly connectionId: string;
  readonly deviceId: string;
  readonly deviceEpoch: number;
  readonly providerKind: string;
  readonly clientProfileId: string;
  readonly clientProfileRevision: number;
  readonly toolSurfaceProfile: "core";
  readonly scopes: readonly string[];
}

export interface KernelRequest {
  version: 1;
  request_id: string;
  client_session_id: string;
  workspace_id: string;
  capability: string;
  operation: string;
  target?: string;
  arguments: Record<string, unknown>;
  remote?: RemoteDispatchContext;
  /**
   * SG-000108 decision 6: the local transport's tool surface profile, from
   * local configuration. It grants nothing by itself: `orceld` requires
   * `browser_structured` for a live browser shape and ignores it otherwise.
   */
  profile?: string;
}

export interface KernelResponse {
  version: number;
  request_id: string;
  ok: boolean;
  result?: unknown;
  error?: {
    code: string;
    message: string;
  };
  evidence?: {
    workspace_id: string;
    policy_revision: string;
    target?: string;
  };
}

type Pending = {
  resolve: (value: KernelResponse) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
};

const SAFE_ENV_NAMES = new Set([
  "PATH",
  "Path",
  "PATHEXT",
  "SystemRoot",
  "WINDIR",
  "COMSPEC",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "LOCALAPPDATA",
  "APPDATA",
  "PROGRAMDATA",
  "ProgramFiles",
  "ProgramFiles(x86)",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
  // XP-01/XP-19 on macOS and Linux: orceld resolves its private state root
  // from HOME/XDG_STATE_HOME and reaches the Secret Service on the session
  // bus. None of these carries a secret.
  "HOME",
  "XDG_STATE_HOME",
  "XDG_RUNTIME_DIR",
  "DBUS_SESSION_BUS_ADDRESS"
]);

const SECRETISH = /(secret|token|password|passwd|credential|api[_-]?key|tunnel[_-]?key)/i;

export function buildDaemonEnv(
  source: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const output: NodeJS.ProcessEnv = {};

  for (const [name, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (SAFE_ENV_NAMES.has(name)) {
      output[name] = value;
      continue;
    }
    if (name.startsWith("ORCEL_") && !SECRETISH.test(name)) {
      output[name] = value;
    }
  }

  return output;
}

export function buildRequest(input: {
  sessionId: string;
  workspaceId: string;
  capability: string;
  operation: string;
  target?: string | undefined;
  arguments?: Record<string, unknown> | undefined;
}): KernelRequest {
  const request: KernelRequest = {
    version: 1,
    request_id: randomUUID(),
    client_session_id: input.sessionId,
    workspace_id: input.workspaceId,
    capability: input.capability,
    operation: input.operation,
    arguments: input.arguments ?? {}
  };
  if (input.target !== undefined) {
    request.target = input.target;
  }
  return request;
}

/**
 * Attach the server-supplied remote context to a kernel request. Tool
 * arguments never reach this field; `orceld` requires an exact active
 * local remote-session lease whenever it is present.
 */
export function attachRemoteContext(
  request: KernelRequest,
  remote: RemoteDispatchContext | null
): KernelRequest {
  if (remote !== null) {
    request.remote = remote;
  }
  return request;
}

/**
 * Stamp the local transport's tool surface profile on a kernel request.
 * Remote requests carry their profile in the remote context instead.
 */
export function attachProfile(request: KernelRequest, profile: string | null): KernelRequest {
  if (profile !== null) {
    request.profile = profile;
  }
  return request;
}

export class KernelClient {
  readonly sessionId = randomUUID();
  /**
   * The current orceld. SG-000120 RJ-03: when it exits (a crash), the next
   * call starts a new one for the same session, so a client can read what
   * its task did; requests that were in flight are rejected, never re-sent.
   */
  child: ChildProcessWithoutNullStreams;
  readonly pending = new Map<string, Pending>();

  readonly remote: RemoteDispatchContext | null;

  /** The local transport's tool surface profile, stamped on every request. */
  readonly profile: string | null;

  private readonly command: string;
  private readonly args: readonly string[];
  private exited = false;
  private closed = false;

  constructor(
    command = process.env.ORCEL_DAEMON ?? "orceld",
    remote: RemoteDispatchContext | null = null,
    profile: string | null = null,
    args: readonly string[] = []
  ) {
    this.remote = remote === null ? null : Object.freeze({ ...remote, scopes: [...remote.scopes] });
    this.profile = profile;
    this.command = command;
    this.args = args;
    this.child = this.spawnDaemon();
  }

  private spawnDaemon(): ChildProcessWithoutNullStreams {
    const child = spawn(this.command, [...this.args], {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      env: buildDaemonEnv()
    });

    child.stderr.on("data", (chunk: Buffer) => {
      process.stderr.write("[orceld] " + chunk.toString("utf8"));
    });

    const lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => this.handleLine(line));

    child.on("error", (error) => {
      if (child === this.child) this.exited = true;
      this.rejectAll(new Error("orceld failed to start: " + error.message));
    });
    child.on("exit", (code, signal) => {
      if (child === this.child) this.exited = true;
      this.rejectAll(
        new Error(
          "orceld exited while requests were pending (code=" +
            String(code) +
            " signal=" +
            String(signal) +
            ")"
        )
      );
    });
    return child;
  }

  async call(input: {
    workspaceId: string;
    capability: string;
    operation: string;
    target?: string | undefined;
    arguments?: Record<string, unknown> | undefined;
    timeoutMs?: number | undefined;
  }): Promise<KernelResponse> {
    const request = buildRequest({
      sessionId: this.sessionId,
      workspaceId: input.workspaceId,
      capability: input.capability,
      operation: input.operation,
      target: input.target,
      arguments: input.arguments
    });
    attachRemoteContext(request, this.remote);
    attachProfile(request, this.profile);
    if (this.exited && !this.closed) {
      // Only for a new request: nothing that was in flight is sent again.
      this.exited = false;
      this.child = this.spawnDaemon();
    }

    const timeoutMs = input.timeoutMs ?? 30_000;
    const response = new Promise<KernelResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(request.request_id);
        reject(new Error("orceld request timed out after " + timeoutMs + "ms"));
      }, timeoutMs);
      this.pending.set(request.request_id, { resolve, reject, timer });
    });

    const payload = JSON.stringify(request) + "\n";
    this.child.stdin.write(payload, "utf8", (error) => {
      if (!error) return;
      const pending = this.pending.get(request.request_id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(request.request_id);
      pending.reject(error);
    });

    return response;
  }

  close(): void {
    this.closed = true;
    this.rejectAll(new Error("kernel client closed"));
    this.child.stdin.end();
    if (!this.child.killed) {
      this.child.kill();
    }
  }

  private handleLine(line: string): void {
    let response: KernelResponse;
    try {
      response = JSON.parse(line) as KernelResponse;
    } catch {
      process.stderr.write("[orcel-mcp] ignored malformed orceld response\n");
      return;
    }

    const pending = this.pending.get(response.request_id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(response.request_id);
    pending.resolve(response);
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }
}
