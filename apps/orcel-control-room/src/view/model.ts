// SG-000119 slice A4: the Control Room view's model of what the shell's five
// commands answer (docs/orcel/implementation-readiness/prep/SG-000119.md,
// "What the web view can call"). Every value here was already shaped in Rust
// by the A1 sanitiser (crates/orcel-app-api-client/src/sanitize); the view
// treats it as untrusted all the same: it reads only the fields named below,
// replaces control and format characters again, bounds every string, and
// renders text only (see dom.ts). Nothing here reads a file, opens a path,
// resolves a location or acts on orceld.

/** A retained field as the sanitiser serializes `Field<T>`. */
export type Field<T> =
  | { state: "shown"; value: T }
  | { state: "withheld" }
  | { state: "absent" };

export interface EventsInfo {
  epoch: string;
  head_seq: number;
  oldest_seq: number;
  ring_capacity: number;
}

export interface Status {
  name: Field<string>;
  version: Field<string>;
  app_api: Field<string>;
  internal_protocol_version: Field<string>;
  os: Field<string>;
  arch: Field<string>;
  mode: Field<string>;
  policy_revision: Field<string>;
  started_at_ms: Field<number>;
  uptime_ms: Field<number>;
  events: Field<EventsInfo>;
  clients: Field<{ active: number; max: number }>;
  endpoint_wait: Field<{ since_ms: number; attempts: number }>;
  withheld: number;
}

export interface Capability {
  id: string;
  state: "available" | "unavailable";
  reason?: string | null;
}

export interface Capabilities {
  os: Field<string>;
  capabilities: Capability[];
  withheld: number;
}

export interface TaskSummary {
  task_id: string;
  workspace_id: string;
  kind: string;
  state: string;
  owner: string;
  created_at_ms: Field<number>;
  updated_at_ms: Field<number>;
}

export interface TaskList {
  tasks: TaskSummary[];
  withheld: number;
}

export interface Source {
  path: Field<string>;
  sha256: Field<string>;
  bytes: Field<number>;
}

export interface DocumentInfo {
  name: Field<string>;
  destination: Field<string>;
  sha256: Field<string>;
  bytes: Field<number>;
}

export interface Check {
  checker: string;
  passed: Field<boolean>;
  destination: Field<string>;
  bytes: Field<number>;
  sha256: Field<string>;
  sources_unchanged: Field<number>;
  figures_confirmed: Field<number>;
  checked_at_ms: Field<number>;
}

export interface Step {
  step_id: string;
  kind: string;
  outcome: string;
  at_ms: Field<number>;
}

export interface TaskDetail extends TaskSummary {
  folder: Field<string>;
  sources: Source[];
  proposal: Field<DocumentInfo>;
  report: Field<DocumentInfo>;
  check: Field<Check>;
  steps: Step[];
  withheld: number;
}

/** A sanitised event: `seq`, `epoch`, `at_ms`, `kind` and the kind's fields. */
export interface ViewEvent {
  seq: number;
  epoch: string;
  at_ms: number;
  kind: string;
  withheld: number;
  [field: string]: unknown;
}

/** One message on the `app_events` channel. */
export type StreamItem =
  | { type: "event"; event: ViewEvent }
  | { type: "withheld" }
  | { type: "cleared" }
  | { type: "gap" }
  | { type: "unavailable"; reason: string }
  | { type: "not_yours" }
  | { type: "incompatible" }
  | { type: "ended" };

// ---------------------------------------------------------------------------
// Bounds

/** The longest text the view shows for any one value, in code points. */
export const MAX_TEXT = 256;
/** Paths may be longer (the path rule allows 1024 bytes). */
export const MAX_PATH_TEXT = 1024;
/** The sanitiser's own caps, applied again. */
export const MAX_TASKS = 64;
export const MAX_CAPABILITIES = 64;
export const MAX_SOURCES = 64;
export const MAX_STEPS = 32;
/** The newest timeline rows the view draws (the reducer keeps 1,024). */
export const MAX_TIMELINE_ROWS = 200;

export const PATH_WITHHELD = "path withheld";
export const WITHHELD = "withheld";
export const NOT_REPORTED = "not reported";
/**
 * A value orceld marked as shown but whose shape the view does not expect
 * (it formats to nothing). It is not a withheld field, so it never reads
 * "withheld"; it has its own label and style.
 */
export const UNEXPECTED = "not shown (unexpected value)";

/** A field as the view draws it. */
export interface FieldView {
  text: string;
  /** The sanitiser withheld it. */
  withheld: boolean;
  /** Marked shown, but its value had a shape the view does not draw. */
  unexpected?: boolean;
}

const UNSAFE = /[\p{Cc}\p{Cf}\u2028\u2029]/gu;

/**
 * Plain text for display: control and format characters (bidi controls and
 * zero-width characters included) and the line and paragraph separators are
 * replaced with U+FFFD, as the Rust text rule does, then the text is cut to
 * `max` code points with an ellipsis.
 */
export function plain(value: unknown, max: number = MAX_TEXT): string {
  let text: string;
  if (typeof value === "string") text = value;
  else if (typeof value === "number" && Number.isFinite(value)) text = String(value);
  else if (typeof value === "boolean") text = value ? "yes" : "no";
  else return "";
  const points = Array.from(text.replace(UNSAFE, "\uFFFD"));
  return points.length > max ? `${points.slice(0, Math.max(0, max - 1)).join("")}\u2026` : points.join("");
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The first `max` entries of an array; anything else is no entries. */
export function bounded<T>(value: unknown, max: number): T[] {
  return Array.isArray(value) ? (value.slice(0, max) as T[]) : [];
}

/** A non-negative safe integer, or null. */
export function count(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/**
 * How a field reads: its value as text, "withheld" (or "path withheld") only
 * where the sanitiser withheld it, "not shown (unexpected value)" for a shown
 * value that formats to nothing, or "not reported".
 */
export function fieldText<T>(
  field: unknown,
  format: (value: T) => string,
  withheld: string = WITHHELD,
): FieldView {
  if (!isRecord(field)) return { text: NOT_REPORTED, withheld: false };
  if (field.state === "withheld") return { text: withheld, withheld: true };
  if (field.state === "shown" && "value" in field) {
    const text = format(field.value as T);
    return text === "" ? { text: UNEXPECTED, withheld: false, unexpected: true } : { text, withheld: false };
  }
  return { text: NOT_REPORTED, withheld: false };
}

export function textOf(value: unknown): string {
  return plain(value);
}

export function pathOf(value: unknown): string {
  return plain(value, MAX_PATH_TEXT);
}

/** A closed enum value shown as words: `approval_denied` reads "approval denied". */
export function words(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z0-9_]{1,48}$/u.test(value)) return "other";
  return value.replace(/_/gu, " ");
}

function pad(n: number, width = 2): string {
  return String(n).padStart(width, "0");
}

/** A local date and time, `YYYY-MM-DD HH:MM:SS`. */
export function timeOf(value: unknown): string {
  const ms = count(value);
  if (ms === null) return "";
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return "";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function durationOf(value: unknown): string {
  const ms = count(value);
  if (ms === null) return "";
  const seconds = Math.floor(ms / 1000);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h} h ${m} min ${s} s`;
  if (m > 0) return `${m} min ${s} s`;
  return `${s} s`;
}

export function bytesOf(value: unknown): string {
  const n = count(value);
  return n === null ? "" : n === 1 ? "1 byte" : `${n} bytes`;
}

export function numberOf(value: unknown): string {
  const n = count(value);
  return n === null ? "" : String(n);
}

export function hashOf(value: unknown): string {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value) ? value : "";
}

/** "n fields withheld", or "" for none. */
export function withheldCount(value: unknown): string {
  const n = count(value);
  if (n === null || n === 0) return "";
  return n === 1 ? "1 field withheld" : `${n} fields withheld`;
}

// ---------------------------------------------------------------------------
// Refusals and stream states, as fixed English text

const UNAVAILABLE: Record<string, string> = {
  not_running: "orceld is not running",
  no_free_instance: "orceld's endpoint has no free instance",
  timed_out: "orceld did not answer in time",
  connection_lost: "the connection to orceld was lost",
  no_location: "orceld's endpoint could not be located",
  busy: "orceld is busy: all its client slots are in use",
  refused: "orceld refused the request",
  frame_too_large: "orceld sent a frame larger than 64 KiB",
  protocol: "orceld sent a frame this window does not understand",
  internal: "this window could not read orceld",
};

/** Why orceld is unavailable, from a fixed reason name only. */
export function unavailableText(reason: unknown): string {
  return typeof reason === "string" && Object.hasOwn(UNAVAILABLE, reason)
    ? (UNAVAILABLE[reason] as string)
    : "orceld is unavailable";
}

export const NOT_YOURS = "orceld could not be confirmed as yours; nothing was sent to it";
export const INCOMPATIBLE = "Incompatible orceld: it does not report itself as read-only. This window shows nothing else.";

export type Refusal =
  | { kind: "unavailable"; text: string }
  | { kind: "not_yours"; text: string }
  | { kind: "incompatible"; text: string }
  | { kind: "other"; text: string };

/** A command's refusal (`{"error": kind, ...}` or Tauri's own text) as fixed text. */
export function refusalOf(error: unknown): Refusal {
  if (!isRecord(error) || typeof error.error !== "string") {
    return { kind: "other", text: "the shell refused the request" };
  }
  switch (error.error) {
    case "unavailable":
      return { kind: "unavailable", text: unavailableText(error.reason) };
    case "busy":
      return { kind: "unavailable", text: unavailableText("busy") };
    case "not_yours":
      return { kind: "not_yours", text: NOT_YOURS };
    case "incompatible":
      return { kind: "incompatible", text: INCOMPATIBLE };
    case "refused":
      return {
        kind: "other",
        text:
          typeof error.code === "string" && /^[A-Z_]{1,32}$/u.test(error.code)
            ? `orceld refused the request (${error.code})`
            : "orceld refused the request",
      };
    case "frame_too_large":
      return { kind: "other", text: unavailableText("frame_too_large") };
    case "protocol":
      return { kind: "other", text: unavailableText("protocol") };
    case "task_withheld":
      return { kind: "other", text: "orceld's record of this task was withheld" };
    default:
      return { kind: "other", text: "the shell refused the request" };
  }
}
