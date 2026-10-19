// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/client/client.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-02).
// Taken: the headless, deterministic client shape (one state object,
// listeners notified after each reduction), integrity reports for
// duplicate and gap deliveries (AgentKit's reportIntegrity), reconnect
// after the last accepted sequence (invariant 2), resubscribe is never a
// retry of anything (invariant 16), and capped exponential backoff.
// Orcel changes: the client is read-only. AgentKit's startRun, cancelRun,
// resumeRun, continueRun, queue, upload, action, connection-request and
// resolveApproval paths are not taken, and nothing replaces them: the only
// requests this client can send are status.get, capabilities.get and
// events.subscribe (READ_METHODS, enforced by encodeRequest). A pending
// approval can be displayed from event data but never answered here
// (invariants 12/23, ORCEL_APP_API_1.md section 7). Every subscription
// carries the epoch it resumes (#375 item 4), and a snapshot from orceld
// replaces the view and is followed by a resubscribe from its cursor.

import { AppApiProtocolError, AppApiValidationError } from "../protocol/errors.js";
import type {
  DaemonCapabilities,
  DaemonStatus,
  JsonValue,
  ReadMethod,
  RequestId,
} from "../protocol/index.js";
import {
  encodeRequest,
  parseCapabilities,
  parseServerFrame,
  parseSnapshotData,
  parseStatus,
  parseSubscribeAck,
} from "../protocol/validation.js";
import type { AppApiConnector, FrameConnection } from "../transport/orceld-transport.js";
import {
  applySnapshot,
  applyStatus,
  classifyEvent,
  createControlRoomState,
  reduceEvent,
  type ControlRoomState,
} from "./state.js";

export type IntegrityReport =
  | { code: "duplicate_event"; expectedSequence: number; receivedSequence: number }
  | { code: "sequence_gap"; expectedSequence: number; receivedSequence: number }
  | { code: "foreign_epoch"; expectedEpoch: string | null; receivedEpoch: string }
  | { code: "invalid_frame"; message: string };

export interface ReconnectOptions {
  initialDelayMs?: number;
  maxDelayMs?: number;
}

export interface ControlRoomClientOptions {
  connector: AppApiConnector;
  /**
   * Where a fresh view starts: "ring" replays what orceld still holds,
   * "new" starts at the current head. Default "ring".
   */
  replay?: "ring" | "new";
  reconnect?: ReconnectOptions;
  /** Milliseconds a one-shot request may take. Default 10,000. */
  requestTimeoutMs?: number;
}

type StateListener = (state: ControlRoomState) => void;
type IntegrityListener = (report: IntegrityReport) => void;

/**
 * Ends one subscription. After a snapshot the loop resubscribes at once;
 * after an integrity fault it backs off first, so a faulty stream cannot
 * spin the client.
 */
class Resubscribe extends Error {
  public constructor(public readonly immediate: boolean) {
    super("resubscribe");
  }
}

export class ControlRoomClient {
  private state = createControlRoomState();
  private readonly stateListeners = new Set<StateListener>();
  private readonly integrityListeners = new Set<IntegrityListener>();
  private readonly connector: AppApiConnector;
  private readonly replay: "ring" | "new";
  private readonly initialDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly requestTimeoutMs: number;
  private nextId = 1;
  private running: Promise<void> | undefined;
  private stopped = false;
  private current: FrameConnection | undefined;
  private wakeSleep: (() => void) | undefined;

  public constructor(options: ControlRoomClientOptions) {
    this.connector = options.connector;
    this.replay = options.replay ?? "ring";
    this.initialDelayMs = options.reconnect?.initialDelayMs ?? 100;
    this.maxDelayMs = options.reconnect?.maxDelayMs ?? 5_000;
    this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
  }

  public getState(): ControlRoomState {
    return this.state;
  }

  /** Calls `listener` after every state change. Returns an unsubscribe. */
  public onState(listener: StateListener): () => void {
    this.stateListeners.add(listener);
    return () => this.stateListeners.delete(listener);
  }

  public onIntegrity(listener: IntegrityListener): () => void {
    this.integrityListeners.add(listener);
    return () => this.integrityListeners.delete(listener);
  }

  private setState(next: ControlRoomState): void {
    if (next === this.state) return;
    this.state = next;
    for (const listener of this.stateListeners) listener(next);
  }

  private reportIntegrity(report: IntegrityReport): void {
    for (const listener of this.integrityListeners) listener(report);
  }

  private requestId(prefix: string): RequestId {
    return `${prefix}-${this.nextId++}`;
  }

  /** One read-only request on its own connection. */
  public async request(method: Exclude<ReadMethod, "events.subscribe">): Promise<JsonValue> {
    const id = this.requestId("req");
    const line = encodeRequest(id, method);
    const connection = await this.connector.connect();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const answer = (async () => {
        await connection.send(line);
        for await (const text of connection.lines()) {
          const frame = parseServerFrame(text);
          if (frame.type === "error") throw new AppApiProtocolError(frame.error);
          if (frame.type !== "result" || frame.id !== id) {
            throw new AppApiValidationError("frame", `unexpected ${frame.type} for ${String(id)}`);
          }
          return frame.result;
        }
        throw new Error(`orceld closed the connection before answering ${method}`);
      })();
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${method} did not answer within ${this.requestTimeoutMs}ms`)),
          this.requestTimeoutMs,
        );
      });
      return await Promise.race([answer, timeout]);
    } finally {
      if (timer) clearTimeout(timer);
      connection.close();
    }
  }

  public async getStatus(): Promise<DaemonStatus> {
    return parseStatus(await this.request("status.get"));
  }

  public async getCapabilities(): Promise<DaemonCapabilities> {
    return parseCapabilities(await this.request("capabilities.get"));
  }

  /** Starts following orceld's events. Resolves once `stop()` is called. */
  public start(): Promise<void> {
    if (this.running && !this.stopped) return this.running;
    this.stopped = false;
    this.running = this.run();
    return this.running;
  }

  public async stop(): Promise<void> {
    this.stopped = true;
    this.current?.close();
    this.wakeSleep?.();
    await this.running?.catch(() => undefined);
    this.setState({ ...this.state, connection: "idle" });
  }

  private async sleep(ms: number): Promise<void> {
    if (this.stopped) return;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms);
      this.wakeSleep = () => {
        clearTimeout(timer);
        resolve();
      };
    });
    this.wakeSleep = undefined;
  }

  private async refreshView(): Promise<void> {
    const status = await this.getStatus();
    const startAfter =
      this.replay === "new"
        ? status.events.head_seq
        : Math.max(0, status.events.oldest_seq - 1);
    const epochChanged = this.state.epoch !== status.events.epoch;
    this.setState(applyStatus(this.state, status, startAfter));
    if (epochChanged || this.state.capabilities === null) {
      this.setState({ ...this.state, capabilities: await this.getCapabilities() });
    }
  }

  private async run(): Promise<void> {
    let failures = 0;
    while (!this.stopped) {
      this.setState({
        ...this.state,
        connection: failures === 0 && this.state.epoch === null ? "connecting" : "reconnecting",
      });
      try {
        if (this.state.epoch === null) await this.refreshView();
        await this.follow(() => {
          failures = 0;
        });
        // orceld ended the stream without a snapshot (it exited, or the
        // subscriber was dropped): reconnect from the cursor after a pause.
        failures += 1;
      } catch (error) {
        if (this.stopped) break;
        if (error instanceof Resubscribe && error.immediate) continue;
        failures += 1;
        const fatal = !(error instanceof Resubscribe) &&
          error instanceof AppApiProtocolError && error.code === "UNSUPPORTED_VERSION";
        this.setState({
          ...this.state,
          connection: fatal ? "error" : error instanceof Resubscribe ? "reconnecting" : "offline",
        });
        if (fatal) throw error;
      }
      if (this.stopped) break;
      await this.sleep(Math.min(this.initialDelayMs * 2 ** Math.max(0, failures - 1), this.maxDelayMs));
    }
  }

  /** One subscription, from the cursor of the current epoch. */
  private async follow(onConnected: () => void): Promise<void> {
    const epoch = this.state.epoch;
    if (epoch === null) throw new Error("no epoch to resume");
    const id = this.requestId("sub");
    const connection = await this.connector.connect();
    this.current = connection;
    try {
      await connection.send(
        encodeRequest(id, "events.subscribe", { after_seq: this.state.cursor, epoch }),
      );
      let acknowledged = false;
      for await (const text of connection.lines()) {
        let frame;
        try {
          frame = parseServerFrame(text);
        } catch (error) {
          this.reportIntegrity({ code: "invalid_frame", message: String(error) });
          throw new Resubscribe(false);
        }
        if (frame.type === "error") throw new AppApiProtocolError(frame.error);
        if (frame.id !== id) {
          this.reportIntegrity({
            code: "invalid_frame",
            message: `frame for ${String(frame.id)} on subscription ${String(id)}`,
          });
          throw new Resubscribe(false);
        }
        if (!acknowledged) {
          if (frame.type !== "result") {
            this.reportIntegrity({ code: "invalid_frame", message: "stream began without an acknowledgement" });
            throw new Resubscribe(false);
          }
          parseSubscribeAck(frame.result);
          acknowledged = true;
          this.setState({ ...this.state, connection: "connected" });
          onConnected();
          continue;
        }
        if (frame.type === "heartbeat") continue;
        if (frame.type !== "event") {
          this.reportIntegrity({ code: "invalid_frame", message: `unexpected ${frame.type} while streaming` });
          throw new Resubscribe(false);
        }
        const event = frame.event;
        if (event.kind === "snapshot") {
          const snapshot = parseSnapshotData(event.data);
          const epochChanged = snapshot.resubscribe.epoch !== this.state.epoch;
          this.setState(applySnapshot(this.state, snapshot));
          if (epochChanged) {
            this.setState({ ...this.state, capabilities: await this.getCapabilities() });
          }
          throw new Resubscribe(true);
        }
        const admission = classifyEvent(this.state, event);
        if (admission.status === "duplicate") {
          this.reportIntegrity({
            code: "duplicate_event",
            expectedSequence: admission.lastSequence + 1,
            receivedSequence: event.seq,
          });
          continue;
        }
        if (admission.status === "foreign") {
          // orceld answers a subscription of another epoch with a snapshot;
          // an event of another epoch on this stream is an integrity fault.
          this.reportIntegrity({
            code: "foreign_epoch",
            expectedEpoch: this.state.epoch,
            receivedEpoch: event.epoch,
          });
          throw new Resubscribe(false);
        }
        if (admission.status === "gap") {
          this.reportIntegrity({
            code: "sequence_gap",
            expectedSequence: admission.expectedSequence,
            receivedSequence: admission.receivedSequence,
          });
          // The cursor has not moved: resubscribe from the last accepted event.
          throw new Resubscribe(false);
        }
        this.setState(reduceEvent(this.state, event));
      }
    } finally {
      connection.close();
      if (this.current === connection) this.current = undefined;
    }
  }
}
