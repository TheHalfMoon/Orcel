// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/client/state.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-02).
// Taken: AgentConnectionStatus, the event admission classes of
// classifyAgentEvent (foreign / accepted / duplicate / gap) and
// reduceAgentEvent's rule that a gap throws before the cursor advances
// (AgentKit invariant 22) while a duplicate leaves state untouched.
// Orcel changes: the cursor is per daemon epoch instead of per thread run;
// an event of another epoch is "foreign"; AgentKit's thread, message,
// queue, roster, suggestion and approval projections are not taken; a
// `snapshot` event replaces the state's epoch, cursor and status instead
// of being reduced like an ordinary event.

import { AppApiValidationError } from "../protocol/errors.js";
import type {
  AppApiEvent,
  DaemonCapabilities,
  DaemonStatus,
  SnapshotData,
} from "../protocol/index.js";

export type ConnectionStatus =
  | "idle"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "offline"
  | "error";

/** The newest events kept per epoch; orceld's own ring holds 1,024. */
export const MAX_TIMELINE_EVENTS = 1_024;

export interface ControlRoomState {
  connection: ConnectionStatus;
  /** The daemon run the cursor belongs to; null before the first status. */
  epoch: string | null;
  /** The last accepted `seq` in `epoch`. */
  cursor: number;
  status: DaemonStatus | null;
  capabilities: DaemonCapabilities | null;
  /** Accepted events of `epoch`, oldest first, at most MAX_TIMELINE_EVENTS. */
  events: AppApiEvent[];
  snapshots: number;
  lastSnapshot: SnapshotData | null;
}

export function createControlRoomState(): ControlRoomState {
  return {
    connection: "idle",
    epoch: null,
    cursor: 0,
    status: null,
    capabilities: null,
    events: [],
    snapshots: 0,
    lastSnapshot: null,
  };
}

export type EventAdmission =
  | { status: "foreign"; epoch: string }
  | { status: "accepted"; sequence: number }
  | { status: "duplicate"; lastSequence: number }
  | { status: "gap"; expectedSequence: number; receivedSequence: number };

export function classifyEvent(
  state: ControlRoomState,
  event: AppApiEvent,
): EventAdmission {
  if (state.epoch === null || event.epoch !== state.epoch) {
    return { status: "foreign", epoch: event.epoch };
  }
  const lastSequence = state.cursor;
  if (lastSequence >= event.seq) {
    return { status: "duplicate", lastSequence };
  }
  const expectedSequence = lastSequence + 1;
  if (event.seq !== expectedSequence) {
    return { status: "gap", expectedSequence, receivedSequence: event.seq };
  }
  return { status: "accepted", sequence: event.seq };
}

/**
 * Applies one streamed event. Foreign and duplicate events change nothing;
 * a gap throws and leaves the cursor where it was, so the next subscription
 * resumes from the last accepted event and orceld either replays the
 * missing events or answers with a snapshot.
 */
export function reduceEvent(
  state: ControlRoomState,
  event: AppApiEvent,
): ControlRoomState {
  if (event.kind === "snapshot") {
    throw new AppApiValidationError(
      "event.kind",
      "snapshot events are applied with applySnapshot",
    );
  }
  const admission = classifyEvent(state, event);
  if (admission.status === "foreign" || admission.status === "duplicate") {
    return state;
  }
  if (admission.status === "gap") {
    throw new AppApiValidationError(
      "event.seq",
      `must be contiguous; expected ${admission.expectedSequence} after ${admission.expectedSequence - 1}, received ${admission.receivedSequence}`,
    );
  }
  const events =
    state.events.length >= MAX_TIMELINE_EVENTS
      ? [...state.events.slice(state.events.length - MAX_TIMELINE_EVENTS + 1), event]
      : [...state.events, event];
  return { ...state, cursor: admission.sequence, events };
}

/**
 * Applies a snapshot: the daemon's status replaces the view, and the cursor
 * moves to the snapshot's resubscribe point. Events of an older epoch are
 * dropped from the timeline; within the same epoch the timeline is kept and
 * the skipped range is covered by the status.
 */
export function applySnapshot(
  state: ControlRoomState,
  snapshot: SnapshotData,
): ControlRoomState {
  const sameEpoch = state.epoch === snapshot.resubscribe.epoch;
  return {
    ...state,
    epoch: snapshot.resubscribe.epoch,
    cursor: snapshot.resubscribe.after_seq,
    status: snapshot.status,
    events: sameEpoch ? state.events : [],
    snapshots: state.snapshots + 1,
    lastSnapshot: snapshot,
  };
}

/** Starts (or restarts) the view from a `status.get` answer. */
export function applyStatus(
  state: ControlRoomState,
  status: DaemonStatus,
  startAfter: number,
): ControlRoomState {
  const sameEpoch = state.epoch === status.events.epoch;
  return {
    ...state,
    status,
    epoch: status.events.epoch,
    cursor: sameEpoch ? state.cursor : startAfter,
    events: sameEpoch ? state.events : [],
  };
}
