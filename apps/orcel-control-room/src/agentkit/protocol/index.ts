// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/protocol/index.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-01).
// Orcel changes: AgentKit's thread/run/message model, its approval,
// connection-request, queue, upload and action types, and every input type
// that starts, resumes, cancels or answers anything are not taken. What
// remains is the envelope idea (versioned frames, typed errors, ordered
// events with a sequence) bound to the shapes orceld serves in
// docs/orcel/implementation-readiness/protocol/ORCEL_APP_API_1.md.
// The Control Room is a read-only client: no type here can carry a request
// that submits work or answers, mints or forwards an approval.

export {
  APP_API_PROTOCOL,
  APP_API_SUPPORTED_PROTOCOLS,
  MAX_FRAME_BYTES,
  isAppApiProtocol,
  type AppApiProtocol,
} from "./version.js";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type RequestId = string | number;

/**
 * The only methods this client sends. Every one is read-only in orceld.
 * The list is closed: the client refuses any other name before a byte is
 * written, so nothing here can submit, approve, mint, stop or write.
 */
export const READ_METHODS = [
  "status.get",
  "capabilities.get",
  "events.subscribe",
] as const;
export type ReadMethod = (typeof READ_METHODS)[number];

/** Read-only names orceld reserves; it answers METHOD_UNAVAILABLE today. */
export const RESERVED_READ_METHODS = [
  "devices.list",
  "task.get",
  "task.list",
] as const;

export function isReadMethod(value: unknown): value is ReadMethod {
  return (READ_METHODS as readonly unknown[]).includes(value);
}

export type AppApiErrorCode =
  | "INVALID_REQUEST"
  | "UNSUPPORTED_VERSION"
  | "UNKNOWN_METHOD"
  | "METHOD_UNAVAILABLE"
  | "FRAME_TOO_LARGE"
  | "BUSY"
  | "INTERNAL";

export const APP_API_ERROR_CODES: readonly AppApiErrorCode[] = [
  "INVALID_REQUEST",
  "UNSUPPORTED_VERSION",
  "UNKNOWN_METHOD",
  "METHOD_UNAVAILABLE",
  "FRAME_TOO_LARGE",
  "BUSY",
  "INTERNAL",
];

export interface AppApiErrorBody {
  code: AppApiErrorCode;
  message: string;
}

/** One daemon event. `seq` grows by one per event within an `epoch`. */
export interface AppApiEvent {
  seq: number;
  epoch: string;
  run_id: string | null;
  step_id: string | null;
  kind: string;
  at_ms: number;
  data: JsonValue;
}

export interface EventsStatus {
  epoch: string;
  head_seq: number;
  oldest_seq: number;
  ring_capacity: number;
}

/** `status.get`. Only the fields the client relies on are typed. */
export interface DaemonStatus {
  name: string;
  version: string;
  app_api: string;
  read_only: true;
  os: string;
  pid: number;
  events: EventsStatus;
  [field: string]: unknown;
}

export interface CapabilityRow {
  id: string;
  state: "available" | "unavailable";
  reason: string | null;
}

/** `capabilities.get`. */
export interface DaemonCapabilities {
  os: string;
  read_only: true;
  methods: string[];
  reserved_methods: string[];
  capabilities: CapabilityRow[];
}

/** The `data` of a `snapshot` event. */
export interface SnapshotData {
  reason: "gap" | "epoch";
  head_seq: number;
  oldest_seq: number;
  status: DaemonStatus;
  resubscribe: { after_seq: number; epoch: string };
}

/** The acknowledgement that opens a subscription stream. */
export interface SubscribeAck {
  epoch: string;
  head_seq: number;
  after_seq: number;
}

export type ServerFrame =
  | { type: "result"; id: RequestId | null; result: JsonValue }
  | { type: "error"; id: RequestId | null; error: AppApiErrorBody }
  | { type: "event"; id: RequestId | null; event: AppApiEvent }
  | { type: "heartbeat"; id: RequestId | null; headSeq: number };

export {
  AppApiProtocolError,
  AppApiValidationError,
  isAppApiProtocolError,
} from "./errors.js";

export {
  encodeRequest,
  parseCapabilities,
  parseEvent,
  parseServerFrame,
  parseSnapshotData,
  parseStatus,
  parseSubscribeAck,
} from "./validation.js";
