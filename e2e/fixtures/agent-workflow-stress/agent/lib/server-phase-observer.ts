/**
 * Benchmark-only, process-local event capture. This never observes model content.
 * A clock domain is unique per module instance: readings cannot be subtracted
 * across worker processes, restarts, or realms.
 */
export type ServerPhaseEventName =
  | "turn.started"
  | "model.call.started"
  | "turn.completed"
  | "turn.cancelled"
  | "turn.failed";

export interface ServerPhaseLifecycleEvent {
  readonly type: ServerPhaseEventName;
  readonly sessionId?: string;
  readonly turnId?: string;
  readonly scope?: {
    readonly attemptId?: string;
    readonly sessionId?: string;
    readonly turnId?: string;
  };
}

export interface ServerPhaseObservation {
  readonly schemaVersion: 1;
  readonly source: "orcel-instrumentation-handler";
  readonly clock: "server-process-monotonic";
  readonly clockDomainId: string;
  readonly sequence: number;
  readonly timestampMs: number;
  readonly event: ServerPhaseEventName;
  readonly sessionId: string;
  readonly turnId: string;
  readonly attemptId: string | null;
}

export function createServerPhaseObserver(options: {
  readonly emit: (row: ServerPhaseObservation) => void;
  readonly clock?: () => number;
  readonly clockDomainId?: string;
}): { observe(event: ServerPhaseLifecycleEvent): ServerPhaseObservation | null } {
  const clockDomainId = options.clockDomainId ?? crypto.randomUUID();
  if (!clockDomainId || typeof clockDomainId !== "string") {
    throw new Error("Clock domain ID is required");
  }
  const clock = options.clock ?? (() => performance.now());
  let sequence = 0;

  return {
    observe(event) {
      const sessionId = event.scope?.sessionId ?? event.sessionId;
      const turnId = event.scope?.turnId ?? event.turnId;
      if (!sessionId || !turnId) return null;
      const timestampMs = clock();
      if (!Number.isFinite(timestampMs) || timestampMs < 0) {
        throw new Error("Invalid local monotonic timestamp");
      }
      const row: ServerPhaseObservation = {
        schemaVersion: 1,
        source: "orcel-instrumentation-handler",
        clock: "server-process-monotonic",
        clockDomainId,
        sequence: ++sequence,
        timestampMs,
        event: event.type,
        sessionId,
        turnId,
        attemptId: event.type === "model.call.started" ? (event.scope?.attemptId ?? null) : null,
      };
      options.emit(row);
      return row;
    },
  };
}
