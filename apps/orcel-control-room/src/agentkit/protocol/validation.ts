// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/protocol/validation.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-01).
// Taken: the runtime-validator style (record, knownKeys, string,
// nonNegativeSafeInteger, path-qualified errors) and the rule that a field
// the protocol version does not define is rejected, not ignored.
// Orcel changes: validators for orceld's frames, events, status,
// capabilities, snapshot and subscribe acknowledgement replace AgentKit's
// thread/run/message/approval validators; encodeRequest refuses every
// method outside READ_METHODS and every frame over MAX_FRAME_BYTES before
// anything is written, and events.subscribe always carries an epoch
// (#375 item 4).

import { AppApiProtocolError, AppApiValidationError } from "./errors.js";
import {
  APP_API_ERROR_CODES,
  type AppApiErrorBody,
  type AppApiErrorCode,
  type AppApiEvent,
  type CapabilityRow,
  type DaemonCapabilities,
  type DaemonStatus,
  type JsonValue,
  type ReadMethod,
  type RequestId,
  type ServerFrame,
  type SnapshotData,
  type SubscribeAck,
  isReadMethod,
} from "./index.js";
import { APP_API_PROTOCOL, MAX_FRAME_BYTES } from "./version.js";

type UnknownRecord = Record<string, unknown>;

const MAX_ID_CHARS = 128;

function record(value: unknown, path: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AppApiValidationError(path, "expected an object");
  }
  return value as UnknownRecord;
}

function knownKeys(
  value: UnknownRecord,
  allowed: readonly string[],
  path: string,
): void {
  const allowedKeys = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) {
      throw new AppApiValidationError(
        `${path}.${key}`,
        "is not defined by this protocol version",
      );
    }
  }
}

function string(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AppApiValidationError(path, "expected a non-empty string");
  }
  return value;
}

function nullableString(value: unknown, path: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string") {
    throw new AppApiValidationError(path, "expected a string or null");
  }
  return value;
}

function nonNegativeSafeInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new AppApiValidationError(
      path,
      "expected a non-negative safe integer",
    );
  }
  return Number(value);
}

function literalTrue(value: unknown, path: string): true {
  if (value !== true) {
    throw new AppApiValidationError(path, "must be true");
  }
  return true;
}

function epoch(value: unknown, path: string): string {
  const text = string(value, path);
  if (Buffer.byteLength(text, "utf8") > MAX_ID_CHARS) {
    throw new AppApiValidationError(path, "must be at most 128 bytes");
  }
  return text;
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) {
    throw new AppApiValidationError(path, "expected an array");
  }
  return value.map((item, index) => string(item, `${path}[${index}]`));
}

function requestId(value: unknown, path: string): RequestId | null {
  if (value === undefined || value === null) return null;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && [...value].length <= MAX_ID_CHARS) {
    return value;
  }
  throw new AppApiValidationError(
    path,
    "expected a number, null, or a string of at most 128 characters",
  );
}

function errorBody(value: unknown, path: string): AppApiErrorBody {
  const body = record(value, path);
  knownKeys(body, ["code", "message"], path);
  const code = string(body.code, `${path}.code`);
  if (!(APP_API_ERROR_CODES as readonly string[]).includes(code)) {
    throw new AppApiValidationError(`${path}.code`, "is not an app API code");
  }
  if (typeof body.message !== "string") {
    throw new AppApiValidationError(`${path}.message`, "expected a string");
  }
  return { code: code as AppApiErrorCode, message: body.message };
}

export function parseEvent(value: unknown, path = "event"): AppApiEvent {
  const event = record(value, path);
  knownKeys(
    event,
    ["seq", "epoch", "run_id", "step_id", "kind", "at_ms", "data"],
    path,
  );
  if (!("data" in event)) {
    throw new AppApiValidationError(`${path}.data`, "is required");
  }
  return {
    seq: nonNegativeSafeInteger(event.seq, `${path}.seq`),
    epoch: epoch(event.epoch, `${path}.epoch`),
    run_id: nullableString(event.run_id, `${path}.run_id`),
    step_id: nullableString(event.step_id, `${path}.step_id`),
    kind: string(event.kind, `${path}.kind`),
    at_ms: nonNegativeSafeInteger(event.at_ms, `${path}.at_ms`),
    data: event.data as JsonValue,
  };
}

/**
 * Parses one line from orceld. The envelope is closed: a field that
 * orcel-app-api/1 does not define is rejected, so a frame cannot carry
 * anything the client would silently ignore.
 */
export function parseServerFrame(line: string): ServerFrame {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new AppApiValidationError("frame", "is not JSON");
  }
  const frame = record(value, "frame");
  if (frame.v !== APP_API_PROTOCOL) {
    throw new AppApiValidationError("frame.v", `must be ${APP_API_PROTOCOL}`);
  }
  const id = requestId(frame.id, "frame.id");
  if ("event" in frame) {
    knownKeys(frame, ["v", "id", "event"], "frame");
    return { type: "event", id, event: parseEvent(frame.event, "frame.event") };
  }
  if ("heartbeat" in frame) {
    knownKeys(frame, ["v", "id", "heartbeat"], "frame");
    const heartbeat = record(frame.heartbeat, "frame.heartbeat");
    knownKeys(heartbeat, ["head_seq"], "frame.heartbeat");
    return {
      type: "heartbeat",
      id,
      headSeq: nonNegativeSafeInteger(
        heartbeat.head_seq,
        "frame.heartbeat.head_seq",
      ),
    };
  }
  if (frame.ok === true) {
    knownKeys(frame, ["v", "id", "ok", "result"], "frame");
    if (!("result" in frame)) {
      throw new AppApiValidationError("frame.result", "is required");
    }
    return { type: "result", id, result: frame.result as JsonValue };
  }
  if (frame.ok === false) {
    knownKeys(frame, ["v", "id", "ok", "error"], "frame");
    return { type: "error", id, error: errorBody(frame.error, "frame.error") };
  }
  throw new AppApiValidationError(
    "frame",
    "is neither a response, an event nor a heartbeat",
  );
}

function eventsStatus(value: unknown, path: string): DaemonStatus["events"] {
  const events = record(value, path);
  return {
    epoch: epoch(events.epoch, `${path}.epoch`),
    head_seq: nonNegativeSafeInteger(events.head_seq, `${path}.head_seq`),
    oldest_seq: nonNegativeSafeInteger(events.oldest_seq, `${path}.oldest_seq`),
    ring_capacity: nonNegativeSafeInteger(
      events.ring_capacity,
      `${path}.ring_capacity`,
    ),
  };
}

/** `status.get`. Fields beyond the ones the client relies on are kept as-is. */
export function parseStatus(value: unknown, path = "status"): DaemonStatus {
  const status = record(value, path);
  string(status.name, `${path}.name`);
  string(status.version, `${path}.version`);
  if (status.app_api !== APP_API_PROTOCOL) {
    throw new AppApiValidationError(`${path}.app_api`, `must be ${APP_API_PROTOCOL}`);
  }
  literalTrue(status.read_only, `${path}.read_only`);
  string(status.os, `${path}.os`);
  nonNegativeSafeInteger(status.pid, `${path}.pid`);
  return {
    ...(status as DaemonStatus),
    events: eventsStatus(status.events, `${path}.events`),
  };
}

function capabilityRow(value: unknown, path: string): CapabilityRow {
  const row = record(value, path);
  knownKeys(row, ["id", "state", "reason"], path);
  const state = row.state;
  if (state !== "available" && state !== "unavailable") {
    throw new AppApiValidationError(
      `${path}.state`,
      'must be "available" or "unavailable"',
    );
  }
  const reason = nullableString(row.reason, `${path}.reason`);
  if (state === "unavailable" && !reason) {
    // ORCEL_APP_API_1.md: an unavailable capability always says why.
    throw new AppApiValidationError(`${path}.reason`, "is required when unavailable");
  }
  return { id: string(row.id, `${path}.id`), state, reason };
}

export function parseCapabilities(
  value: unknown,
  path = "capabilities",
): DaemonCapabilities {
  const caps = record(value, path);
  knownKeys(
    caps,
    ["os", "read_only", "methods", "reserved_methods", "capabilities"],
    path,
  );
  if (!Array.isArray(caps.capabilities)) {
    throw new AppApiValidationError(`${path}.capabilities`, "expected an array");
  }
  return {
    os: string(caps.os, `${path}.os`),
    read_only: literalTrue(caps.read_only, `${path}.read_only`),
    methods: stringArray(caps.methods, `${path}.methods`),
    reserved_methods: stringArray(caps.reserved_methods, `${path}.reserved_methods`),
    capabilities: caps.capabilities.map((row, index) =>
      capabilityRow(row, `${path}.capabilities[${index}]`),
    ),
  };
}

export function parseSubscribeAck(value: unknown, path = "ack"): SubscribeAck {
  const ack = record(value, path);
  knownKeys(ack, ["epoch", "head_seq", "after_seq"], path);
  return {
    epoch: epoch(ack.epoch, `${path}.epoch`),
    head_seq: nonNegativeSafeInteger(ack.head_seq, `${path}.head_seq`),
    after_seq: nonNegativeSafeInteger(ack.after_seq, `${path}.after_seq`),
  };
}

export function parseSnapshotData(
  value: unknown,
  path = "snapshot.data",
): SnapshotData {
  const data = record(value, path);
  knownKeys(
    data,
    ["reason", "head_seq", "oldest_seq", "status", "resubscribe"],
    path,
  );
  if (data.reason !== "gap" && data.reason !== "epoch") {
    throw new AppApiValidationError(`${path}.reason`, 'must be "gap" or "epoch"');
  }
  const resubscribe = record(data.resubscribe, `${path}.resubscribe`);
  knownKeys(resubscribe, ["after_seq", "epoch"], `${path}.resubscribe`);
  return {
    reason: data.reason,
    head_seq: nonNegativeSafeInteger(data.head_seq, `${path}.head_seq`),
    oldest_seq: nonNegativeSafeInteger(data.oldest_seq, `${path}.oldest_seq`),
    status: parseStatus(data.status, `${path}.status`),
    resubscribe: {
      after_seq: nonNegativeSafeInteger(
        resubscribe.after_seq,
        `${path}.resubscribe.after_seq`,
      ),
      epoch: epoch(resubscribe.epoch, `${path}.resubscribe.epoch`),
    },
  };
}

export interface SubscribeParams {
  after_seq: number;
  epoch: string;
}

/**
 * Encodes one request line. Refuses, before anything is written:
 * - a method outside READ_METHODS (the client has no other method to send);
 * - events.subscribe without an epoch, or with any other parameter;
 * - a frame over MAX_FRAME_BYTES, newline included.
 */
export function encodeRequest(
  id: RequestId,
  method: ReadMethod,
  params: SubscribeParams | Record<string, never> = {},
): string {
  if (!isReadMethod(method)) {
    throw new AppApiProtocolError({
      code: "UNKNOWN_METHOD",
      message: `${String(method)} is not a read-only method this client sends`,
    });
  }
  requestId(id, "request.id");
  const body = record(params, "request.params");
  if (method === "events.subscribe") {
    knownKeys(body, ["after_seq", "epoch"], "request.params");
    nonNegativeSafeInteger(body.after_seq, "request.params.after_seq");
    epoch(body.epoch, "request.params.epoch");
  } else {
    knownKeys(body, [], "request.params");
  }
  const line = `${JSON.stringify({ v: APP_API_PROTOCOL, id, method, params: body })}\n`;
  const bytes = Buffer.byteLength(line, "utf8");
  if (bytes > MAX_FRAME_BYTES) {
    throw new AppApiProtocolError({
      code: "FRAME_TOO_LARGE",
      message: `a request of ${bytes} bytes exceeds ${MAX_FRAME_BYTES}`,
    });
  }
  return line;
}
