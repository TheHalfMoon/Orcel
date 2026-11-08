// Test support: an in-memory connector whose server side is a script, for
// stream faults the real orceld never produces (a skipped sequence, a
// duplicate, an event of another epoch, an extra envelope field). No socket
// or listener is involved.

import { APP_API_PROTOCOL } from "../agentkit/protocol/version.js";
import type { AppApiConnector, FrameConnection } from "../agentkit/transport/orceld-transport.js";

export interface ScriptedRequest {
  id: string | number;
  method: string;
  params: Record<string, unknown>;
}

/** Returns the server's lines for one request; the connection then ends. */
export type Script = (request: ScriptedRequest, connection: number) => unknown[];

export class ScriptedConnector implements AppApiConnector {
  public readonly endpoint = "scripted";
  public readonly sent: ScriptedRequest[] = [];
  private connections = 0;

  public constructor(private readonly script: Script) {}

  public connect(): Promise<FrameConnection> {
    const index = this.connections++;
    const lines: string[] = [];
    let closed = false;
    let wake: (() => void) | undefined;
    const connection: FrameConnection = {
      send: async (line) => {
        const request = JSON.parse(line) as ScriptedRequest;
        this.sent.push(request);
        for (const frame of this.script(request, index)) {
          lines.push(typeof frame === "string" ? frame : JSON.stringify(frame));
        }
        closed = true;
        wake?.();
      },
      lines: async function* () {
        for (;;) {
          const line = lines.shift();
          if (line !== undefined) {
            yield line;
            continue;
          }
          if (closed) return;
          await new Promise<void>((resolve) => {
            wake = resolve;
          });
        }
      },
      close: () => {
        closed = true;
        wake?.();
      },
    };
    return Promise.resolve(connection);
  }
}

export const v = APP_API_PROTOCOL;

export function statusResult(epoch: string, head: number, oldest = 1) {
  return {
    name: "orceld",
    version: "0.2.0",
    app_api: APP_API_PROTOCOL,
    read_only: true,
    os: "linux",
    pid: 1,
    events: { epoch, head_seq: head, oldest_seq: oldest, ring_capacity: 1024 },
  };
}

export const capabilitiesResult = {
  os: "linux",
  read_only: true,
  methods: ["status.get", "capabilities.get", "events.subscribe", "task.list", "task.get"],
  reserved_methods: ["devices.list"],
  capabilities: [],
};

export function eventFrame(id: unknown, seq: number, epoch: string) {
  return {
    v,
    id,
    event: { seq, epoch, run_id: null, step_id: null, kind: "request.completed", at_ms: seq, data: {} },
  };
}
