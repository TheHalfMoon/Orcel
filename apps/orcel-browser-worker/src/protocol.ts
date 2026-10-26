// SG-000108 private worker protocol.
//
// The Rust browser host and this worker exchange length-prefixed JSON frames
// (u32 little-endian length, then UTF-8 JSON) over the worker's anonymous
// stdio pipes, the same framing as the SG-000074 host protocol. There is no
// listener. The vocabulary is closed and versioned; unknown frames or fields
// are protocol violations. The host remains the authority: everything the
// worker checks here is defense in depth against a host bug.

import { isIPv4, isIPv6 } from "node:net";
import type { SnapshotNode } from "./snapshot.js";
import type { ControlKind, DeclaredTool } from "./webmcp/declarative.js";
import { MAX_VERIFY_PROBES, MAX_VERIFY_TEXT_BYTES, type VerifyProbe, type VerifyResult } from "./verify.js";
import { PRESS_KEYS, type FormAction, type PressKey } from "./actions/form.js";
import { MAX_WAIT_MS } from "./actions/wait.js";

/// One form field to enter when executing a tool (host-validated).
export interface ExecField {
  name: string;
  control: ControlKind;
  values: string[];
}

const EXEC_CONTROLS: readonly ControlKind[] = ["text", "textarea", "select", "select_multiple", "radio", "checkbox", "checkboxes"];
/// Mirrors the host's bounds.
export const MAX_EXEC_FIELDS = 32;
export const MAX_EXEC_VALUES = 64;
export const MAX_EXEC_VALUE_CHARS = 1024;

/// Generation 2 adds the slice-3a navigation frames, generation 3 slice-3b
/// observation, generation 4 slice-3c activation, generation 5 slice-3d
/// downloads, generation 6 slice-4 WebMCP discovery, generation 7 slice-5
/// WebMCP execution, generation 8 slice-6 page extraction, generation 9
/// text documents for robots.txt and sitemaps (#317), generation 10 BR-07
/// postcondition probes, generation 11 BR-02 form actions, generation 12
/// BR-02 press, hover and bounded waits.
export const WORKER_PROTOCOL_GENERATION = 12;
/// BR-02: the longest value filled, and the most options selected at once
/// (mirrors the host).
export const MAX_FORM_VALUE_BYTES = 1024;
export const MAX_FORM_OPTIONS = 16;
export const WORKER_IDENTITY = "orcel-browser-worker";
export const MAX_FRAME_BYTES = 64 * 1024;
/// One extraction piece's content on the wire (JSON-escaped UTF-8 bytes),
/// leaving room for the frame's other fields (the URL is at most 2 KiB).
export const MAX_PIECE_BYTES = MAX_FRAME_BYTES - 8 * 1024;
/// A fetched text document's content on the wire (JSON-escaped UTF-8
/// bytes); longer text is cut and marked truncated.
export const MAX_FETCH_TEXT_BYTES = MAX_FRAME_BYTES - 8 * 1024;
/// The media types a text fetch returns content for: text, XML, HTML (a
/// robots.txt served as a page is still read as one) and none at all.
export const FETCH_TEXT_MEDIA: readonly string[] = ["text/plain", "application/xml", "text/xml", "text/html", ""];
/// Mirrors the host's bound on pieces per extraction.
export const MAX_EXTRACT_PIECES = 96;

export const MAX_ARGV_ENTRIES = 64;
export const MAX_ARG_BYTES = 8192;
export const MAX_PATH_BYTES = 1024;
export const MAX_ENV_ENTRIES = 16;
export const MAX_ENV_VALUE_BYTES = 4096;
/// Mirrors MAX_URL_BYTES in the Rust navigation policy.
export const MAX_URL_BYTES = 2048;
/// Mirrors the bound on requesting origins in route requests.
export const MAX_ORIGIN_BYTES = 512;
/// Mirrors MAX_ADMITTED_DESTINATIONS in the Rust host.
export const MAX_ADMITTED_DESTINATIONS = 16;

/// Engine environment keys the host may pass (its scrubbed environment).
export const ENGINE_ENV_ALLOWLIST: readonly string[] = ["SystemRoot", "SystemDrive", "PATH", "TEMP", "TMP", "LANG"];

/// The SG-000074 frozen flags, in order.
export const FROZEN_FLAGS: readonly string[] = [
  "--headless",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-extensions",
  "--disable-background-networking",
  "--disable-sync",
  "--no-service-autorun"
];

/// Fixed confinement values from the SG-000108 decision record. The two
/// host-built values (resolver rules, bypass list) are checked for shape.
export const NO_ROUTE_PROXY = "--proxy-server=http://0.0.0.0:9";
export const WEBRTC_POLICY = "--webrtc-ip-handling-policy=disable_non_proxied_udp";
export const DISABLE_QUIC = "--disable-quic";
/// SG-000108 slice 3a: SharedWorker requests are never routed, so the API is removed.
export const DISABLE_SHARED_WORKER = "--disable-blink-features=SharedWorker";
/// #324: browser-process services that reach the network outside the
/// resolver and no-route layers (Media Router; Edge account integration).
export const DISABLE_FEATURES = "--disable-features=MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,msImplicitSignin,msEdgeOSAccountInfoSubstrate,msEdgeOnlineAccounts,msOneAuthWAM,msLoadOneAuthInBackground,msIdentityCore,WebRtcHideLocalIpsWithMdns";
export const PIPE = "--remote-debugging-pipe";
export const INITIAL_URL = "about:blank";

export type HostFrame =
  | { frame: "hello"; generation: number }
  | { frame: "launch"; engine: string; profile_dir: string; argv: string[]; env: Record<string, string> }
  | { frame: "ping"; nonce: string }
  | { frame: "navigate"; nav_id: number; url: string }
  | { frame: "fetch_text"; fetch_id: number; url: string }
  | { frame: "route_decision"; request_id: number; allow: boolean }
  | { frame: "observe"; obs_id: number }
  | { frame: "discover"; disc_id: number }
  | { frame: "extract"; ext_id: number; links: boolean; images: boolean }
  | { frame: "extract_more"; ext_id: number; piece: number }
  | { frame: "execute"; exec_id: number; tool: string; fields: ExecField[] }
  | { frame: "activate"; act_id: number; ref: string; target?: ApprovedTarget }
  | { frame: "download"; dl_id: number; ref: string; path: string; target?: ApprovedTarget }
  | { frame: "verify"; ver_id: number; probes: VerifyProbe[] }
  | { frame: "form_action"; form_id: number; ref: string; act: FormAction; target?: ApprovedTarget }
  | { frame: "wait_for"; wait_id: number; text: string; appear: boolean; timeout_ms: number }
  | { frame: "shutdown" };

export type RouteKind = "document" | "redirect" | "frame" | "popup" | "fetch" | "subresource" | "service_worker";

export type NavigationFailure = "denied" | "timeout" | "failed" | "busy" | "http_status" | "oversized" | "stale";

/// BR-01: the approved element's role and accessible name, as the host
/// observed them. Used only when the element's snapshot ref went stale:
/// the worker then acts on the one element with exactly this role and
/// name in the main frame, or on none.
export interface ApprovedTarget {
  role: string;
  name: string;
}

/// The longest accessible name the host sends back (the snapshot bound).
export const MAX_TARGET_NAME_BYTES = 1024;

function approvedTarget(raw: Record<string, unknown>): ApprovedTarget | undefined {
  if (!("role" in raw) && !("name" in raw)) return undefined;
  if (typeof raw.role !== "string" || !/^[a-z][a-z-]{0,39}$/.test(raw.role)) {
    throw new ProtocolViolation("approved role is malformed");
  }
  return { role: raw.role, name: boundedString(raw.name, MAX_TARGET_NAME_BYTES, "approved name") };
}

/// BR-02: a value to fill; empty clears the field.
function formValue(value: unknown): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > MAX_FORM_VALUE_BYTES) {
    throw new ProtocolViolation("fill value is not a bounded string");
  }
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new ProtocolViolation("fill value carries control characters");
  return value;
}

/// BR-07: one read-only probe, as the host sends it.
function verifyProbe(raw: unknown): VerifyProbe {
  if (!isPlainObject(raw) || typeof raw.probe !== "string") throw new ProtocolViolation("verify probe is not a tagged object");
  switch (raw.probe) {
    case "visible_role": {
      exactKeys(raw, ["probe", "role", "name"]);
      if (typeof raw.role !== "string" || !/^[a-z][a-z-]{0,39}$/.test(raw.role)) {
        throw new ProtocolViolation("verify role is malformed");
      }
      return { probe: "visible_role", role: raw.role, name: boundedString(raw.name, MAX_VERIFY_TEXT_BYTES, "verify name") };
    }
    case "visible_text": {
      exactKeys(raw, ["probe", "text"]);
      return { probe: "visible_text", text: boundedString(raw.text, MAX_VERIFY_TEXT_BYTES, "verify text") };
    }
    case "value":
    case "checked": {
      exactKeys(raw, ["probe", "ref"]);
      if (typeof raw.ref !== "string" || !/^(?:f\d{1,4})?e\d{1,6}$/.test(raw.ref)) {
        throw new ProtocolViolation("verify ref is malformed");
      }
      return { probe: raw.probe, ref: raw.ref };
    }
    default:
      throw new ProtocolViolation("verify probe is unknown");
  }
}

export type ErrorCode = "protocol_violation" | "launch_refused" | "launch_failed" | "engine_exited" | "not_ready";

export type WorkerFrame =
  | { frame: "hello"; generation: number; worker: string }
  | { frame: "launched" }
  | { frame: "pong"; nonce: string }
  | { frame: "bye" }
  | {
      frame: "route_request";
      request_id: number;
      kind: RouteKind;
      url: string;
      origin: string;
      method: string;
      content_type: string;
      body: string | null;
      body_bytes: number;
    }
  | { frame: "navigated"; nav_id: number; url: string; status: number }
  | { frame: "navigation_failed"; nav_id: number; reason: NavigationFailure }
  | { frame: "fetched_text"; fetch_id: number; url: string; status: number; media: string; text: string; truncated: boolean }
  | { frame: "fetch_failed"; fetch_id: number; reason: NavigationFailure }
  | { frame: "observed"; obs_id: number; url: string; truncated: boolean; nodes: SnapshotNode[] }
  | { frame: "observation_failed"; obs_id: number }
  | { frame: "discovered"; disc_id: number; url: string; truncated: boolean; tools: DeclaredTool[] }
  | { frame: "discovery_failed"; disc_id: number }
  | { frame: "extracted"; ext_id: number; url: string; truncated: boolean; piece: number; total: number; chunk: number; content: string }
  | { frame: "extraction_failed"; ext_id: number }
  | { frame: "executed"; exec_id: number; url: string; status: number; structured: string[]; structured_complete: boolean }
  | { frame: "execution_failed"; exec_id: number; reason: NavigationFailure }
  | { frame: "activated"; act_id: number; url: string; status: number }
  | { frame: "activation_failed"; act_id: number; reason: NavigationFailure }
  | { frame: "downloaded"; dl_id: number; url: string; name: string; media: string; bytes: number }
  | { frame: "download_failed"; dl_id: number; reason: NavigationFailure }
  | { frame: "verified"; ver_id: number; url: string; results: VerifyResult[] }
  | { frame: "form_done"; form_id: number; url: string }
  | { frame: "waited"; wait_id: number; url: string; met: boolean }
  | { frame: "wait_failed"; wait_id: number }
  | { frame: "form_failed"; form_id: number; reason: NavigationFailure }
  | { frame: "verification_failed"; ver_id: number }
  | { frame: "error"; code: ErrorCode };

export class ProtocolViolation extends Error {}

export function encodeFrame(value: WorkerFrame | HostFrame): Buffer {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  if (body.length === 0 || body.length > MAX_FRAME_BYTES) {
    throw new ProtocolViolation("frame exceeds the size bound");
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length, 0);
  return Buffer.concat([prefix, body]);
}

/// Incremental decoder: push stream chunks, take complete frame bodies. The
/// length bound is enforced before the body is buffered.
export class FrameDecoder {
  private buffered: Buffer = Buffer.alloc(0);
  // Invalid UTF-8 is a violation, as in the Rust host (no replacement).
  private readonly utf8 = new TextDecoder("utf-8", { fatal: true });

  push(chunk: Buffer): unknown[] {
    this.buffered = Buffer.concat([this.buffered, chunk]);
    const frames: unknown[] = [];
    for (;;) {
      if (this.buffered.length < 4) return frames;
      const length = this.buffered.readUInt32LE(0);
      if (length === 0 || length > MAX_FRAME_BYTES) {
        throw new ProtocolViolation("frame length out of bounds");
      }
      if (this.buffered.length < 4 + length) return frames;
      const bytes = this.buffered.subarray(4, 4 + length);
      this.buffered = this.buffered.subarray(4 + length);
      let body: string;
      try {
        body = this.utf8.decode(bytes);
      } catch {
        throw new ProtocolViolation("frame is not valid UTF-8");
      }
      try {
        frames.push(JSON.parse(body) as unknown);
      } catch {
        throw new ProtocolViolation("frame is not JSON");
      }
    }
  }

  get pendingBytes(): number {
    return this.buffered.length;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value: Record<string, unknown>, keys: string[]): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ProtocolViolation("frame has unexpected or missing fields");
  }
}

function boundedString(value: unknown, maxBytes: number, what: string): string {
  if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > maxBytes) {
    throw new ProtocolViolation(`${what} is not a bounded string`);
  }
  // Control characters (including NUL) never cross the boundary.
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new ProtocolViolation(`${what} carries control characters`);
  }
  return value;
}

function positiveId(value: unknown, what: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new ProtocolViolation(`${what} is not a positive integer`);
  }
  return value as number;
}

/// Decode one host frame into the closed vocabulary.
export function parseHostFrame(raw: unknown): HostFrame {
  if (!isPlainObject(raw) || typeof raw.frame !== "string") {
    throw new ProtocolViolation("frame is not a tagged object");
  }
  switch (raw.frame) {
    case "hello": {
      exactKeys(raw, ["frame", "generation"]);
      if (!Number.isSafeInteger(raw.generation)) throw new ProtocolViolation("hello generation is not an integer");
      return { frame: "hello", generation: raw.generation as number };
    }
    case "ping": {
      exactKeys(raw, ["frame", "nonce"]);
      const nonce = boundedString(raw.nonce, 64, "ping nonce");
      if (!/^[A-Za-z0-9_-]+$/.test(nonce)) throw new ProtocolViolation("ping nonce is malformed");
      return { frame: "ping", nonce };
    }
    case "shutdown": {
      exactKeys(raw, ["frame"]);
      return { frame: "shutdown" };
    }
    case "navigate": {
      exactKeys(raw, ["frame", "nav_id", "url"]);
      const navId = positiveId(raw.nav_id, "nav_id");
      const url = boundedString(raw.url, MAX_URL_BYTES, "navigation URL");
      if (!url.startsWith("https://")) throw new ProtocolViolation("navigation URL is not https");
      return { frame: "navigate", nav_id: navId, url };
    }
    case "fetch_text": {
      exactKeys(raw, ["frame", "fetch_id", "url"]);
      const fetchId = positiveId(raw.fetch_id, "fetch_id");
      const url = boundedString(raw.url, MAX_URL_BYTES, "fetch URL");
      if (!url.startsWith("https://")) throw new ProtocolViolation("fetch URL is not https");
      return { frame: "fetch_text", fetch_id: fetchId, url };
    }
    case "download": {
      exactKeys(raw, "role" in raw || "name" in raw ? ["frame", "dl_id", "ref", "path", "role", "name"] : ["frame", "dl_id", "ref", "path"]);
      const dlId = positiveId(raw.dl_id, "dl_id");
      if (typeof raw.ref !== "string" || !/^(?:f\d{1,4})?e\d{1,6}$/.test(raw.ref)) {
        throw new ProtocolViolation("download ref is malformed");
      }
      const path = boundedString(raw.path, MAX_PATH_BYTES, "download path");
      if (!isAbsoluteWindowsPath(path) || !path.toLowerCase().endsWith(".part")) {
        throw new ProtocolViolation("download path is not an absolute .part path");
      }
      const target = approvedTarget(raw);
      return target ? { frame: "download", dl_id: dlId, ref: raw.ref, path, target } : { frame: "download", dl_id: dlId, ref: raw.ref, path };
    }
    case "activate": {
      exactKeys(raw, "role" in raw || "name" in raw ? ["frame", "act_id", "ref", "role", "name"] : ["frame", "act_id", "ref"]);
      const actId = positiveId(raw.act_id, "act_id");
      if (typeof raw.ref !== "string" || !/^(?:f\d{1,4})?e\d{1,6}$/.test(raw.ref)) {
        throw new ProtocolViolation("activation ref is malformed");
      }
      const target = approvedTarget(raw);
      return target ? { frame: "activate", act_id: actId, ref: raw.ref, target } : { frame: "activate", act_id: actId, ref: raw.ref };
    }
    case "form_action": {
      const targeted = "role" in raw || "name" in raw ? ["role", "name"] : [];
      const own: Record<string, string[]> = { fill: ["value"], select: ["values"], check: ["checked"], press: ["key"], hover: [] };
      const fields = typeof raw.action === "string" && Object.hasOwn(own, raw.action) ? own[raw.action] : undefined;
      if (!fields) throw new ProtocolViolation("form action is unknown");
      exactKeys(raw, ["frame", "form_id", "action", "ref", ...fields, ...targeted]);
      const formId = positiveId(raw.form_id, "form_id");
      if (typeof raw.ref !== "string" || !/^e\d{1,6}$/.test(raw.ref)) {
        throw new ProtocolViolation("form action ref is malformed");
      }
      let act: FormAction;
      if (raw.action === "fill") {
        act = { action: "fill", value: formValue(raw.value) };
      } else if (raw.action === "select") {
        if (!Array.isArray(raw.values) || raw.values.length === 0 || raw.values.length > MAX_FORM_OPTIONS) {
          throw new ProtocolViolation("select options are malformed");
        }
        const values = raw.values.map((label: unknown) => boundedString(label, MAX_FORM_VALUE_BYTES, "select option"));
        if (new Set(values).size !== values.length) throw new ProtocolViolation("select options repeat");
        act = { action: "select", values };
      } else if (raw.action === "check") {
        if (typeof raw.checked !== "boolean") throw new ProtocolViolation("check state is not a boolean");
        act = { action: "check", checked: raw.checked };
      } else if (raw.action === "press") {
        if (typeof raw.key !== "string" || !(PRESS_KEYS as readonly string[]).includes(raw.key)) {
          throw new ProtocolViolation("press key is not allowed");
        }
        act = { action: "press", key: raw.key as PressKey };
      } else {
        act = { action: "hover" };
      }
      const target = approvedTarget(raw);
      return target ? { frame: "form_action", form_id: formId, ref: raw.ref, act, target } : { frame: "form_action", form_id: formId, ref: raw.ref, act };
    }
    case "wait_for": {
      exactKeys(raw, ["frame", "wait_id", "text", "appear", "timeout_ms"]);
      const waitId = positiveId(raw.wait_id, "wait_id");
      if (typeof raw.appear !== "boolean") throw new ProtocolViolation("wait appear is not a boolean");
      if (!Number.isSafeInteger(raw.timeout_ms) || (raw.timeout_ms as number) < 1 || (raw.timeout_ms as number) > MAX_WAIT_MS) {
        throw new ProtocolViolation("wait timeout is out of range");
      }
      const text = boundedString(raw.text, MAX_VERIFY_TEXT_BYTES, "wait text");
      return { frame: "wait_for", wait_id: waitId, text, appear: raw.appear, timeout_ms: raw.timeout_ms as number };
    }
    case "verify": {
      exactKeys(raw, ["frame", "ver_id", "probes"]);
      const verId = positiveId(raw.ver_id, "ver_id");
      if (!Array.isArray(raw.probes) || raw.probes.length === 0 || raw.probes.length > MAX_VERIFY_PROBES) {
        throw new ProtocolViolation("verify probes are malformed");
      }
      return { frame: "verify", ver_id: verId, probes: raw.probes.map(verifyProbe) };
    }
    case "observe": {
      exactKeys(raw, ["frame", "obs_id"]);
      return { frame: "observe", obs_id: positiveId(raw.obs_id, "obs_id") };
    }
    case "discover": {
      exactKeys(raw, ["frame", "disc_id"]);
      return { frame: "discover", disc_id: positiveId(raw.disc_id, "disc_id") };
    }
    case "extract": {
      exactKeys(raw, ["frame", "ext_id", "links", "images"]);
      if (typeof raw.links !== "boolean" || typeof raw.images !== "boolean") {
        throw new ProtocolViolation("extract options are not booleans");
      }
      return { frame: "extract", ext_id: positiveId(raw.ext_id, "ext_id"), links: raw.links, images: raw.images };
    }
    case "extract_more": {
      exactKeys(raw, ["frame", "ext_id", "piece"]);
      const piece = positiveId(raw.piece, "piece");
      if (piece >= MAX_EXTRACT_PIECES) throw new ProtocolViolation("extract piece is out of range");
      return { frame: "extract_more", ext_id: positiveId(raw.ext_id, "ext_id"), piece };
    }
    case "execute": {
      exactKeys(raw, ["frame", "exec_id", "tool", "fields"]);
      const execId = positiveId(raw.exec_id, "exec_id");
      if (typeof raw.tool !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(raw.tool)) {
        throw new ProtocolViolation("execute tool name is malformed");
      }
      if (!Array.isArray(raw.fields) || raw.fields.length > MAX_EXEC_FIELDS) {
        throw new ProtocolViolation("execute fields are malformed");
      }
      const fields: ExecField[] = raw.fields.map((field: unknown) => {
        if (typeof field !== "object" || field === null || Array.isArray(field)) {
          throw new ProtocolViolation("execute field is malformed");
        }
        const entry = field as Record<string, unknown>;
        exactKeys(entry, ["name", "control", "values"]);
        const { name, control, values } = entry;
        if (typeof name !== "string" || name.length === 0 || Array.from(name).length > 64 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
          throw new ProtocolViolation("execute field name is malformed");
        }
        if (typeof control !== "string" || !(EXEC_CONTROLS as readonly string[]).includes(control)) {
          throw new ProtocolViolation("execute field control is malformed");
        }
        if (!Array.isArray(values) || values.length > MAX_EXEC_VALUES || !values.every((v) => typeof v === "string" && Array.from(v).length <= MAX_EXEC_VALUE_CHARS)) {
          throw new ProtocolViolation("execute field values are malformed");
        }
        return { name, control: control as ControlKind, values: values as string[] };
      });
      return { frame: "execute", exec_id: execId, tool: raw.tool, fields };
    }
    case "route_decision": {
      exactKeys(raw, ["frame", "request_id", "allow"]);
      const requestId = positiveId(raw.request_id, "request_id");
      if (typeof raw.allow !== "boolean") throw new ProtocolViolation("route decision is not a boolean");
      return { frame: "route_decision", request_id: requestId, allow: raw.allow };
    }
    case "launch": {
      exactKeys(raw, ["frame", "engine", "profile_dir", "argv", "env"]);
      const engine = boundedString(raw.engine, MAX_PATH_BYTES, "engine path");
      const profileDir = boundedString(raw.profile_dir, MAX_PATH_BYTES, "profile directory");
      if (!Array.isArray(raw.argv) || raw.argv.length === 0 || raw.argv.length > MAX_ARGV_ENTRIES) {
        throw new ProtocolViolation("argv is not a bounded array");
      }
      const argv = raw.argv.map((arg, index) => boundedString(arg, MAX_ARG_BYTES, `argv[${index}]`));
      if (!isPlainObject(raw.env)) throw new ProtocolViolation("env is not an object");
      const entries = Object.entries(raw.env);
      if (entries.length > MAX_ENV_ENTRIES) throw new ProtocolViolation("env has too many entries");
      // A null prototype: no key (including "__proto__") is special.
      const env: Record<string, string> = Object.create(null) as Record<string, string>;
      for (const [key, value] of entries) {
        env[key] = boundedString(value, MAX_ENV_VALUE_BYTES, `env ${key}`);
      }
      return { frame: "launch", engine, profile_dir: profileDir, argv, env };
    }
    default:
      throw new ProtocolViolation("unknown frame");
  }
}

/// Mirrors validate_admitted_host in the Rust host: lowercase ASCII LDH, two
/// or more labels of 1..=63 bytes, at most 253 bytes, no label starting or
/// ending with a hyphen, and a last label that is not numeric or 0x-prefixed.
export function isAdmittedHost(host: string): boolean {
  if (host.length === 0 || host.length > 253 || !/^[a-z0-9.-]+$/.test(host)) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length === 0 || label.length > 63 || label.startsWith("-") || label.endsWith("-")) return false;
  }
  const last = labels[labels.length - 1] ?? "";
  return !/^[0-9]+$/.test(last) && !last.startsWith("0x");
}

/// Parse the resolver rules into admitted names, in order, or null when the
/// value is not exactly `MAP <name> <ipv4|[ipv6]>:443, …, MAP * ~NOTFOUND`.
/// Address class is the host's policy (test builds pin fixtures to loopback);
/// the worker checks the grammar so nothing else can be smuggled in.
export function parseResolverRules(value: string): string[] | null {
  const entries = value.split(", ");
  if (entries.pop() !== "MAP * ~NOTFOUND") return null;
  if (entries.length === 0 || entries.length > MAX_ADMITTED_DESTINATIONS) return null;
  const names: string[] = [];
  for (const entry of entries) {
    const match = /^MAP ([^ ]+) ([^ ]+):443$/.exec(entry);
    if (!match) return null;
    const [, name = "", address = ""] = match;
    if (!isAdmittedHost(name) || names.includes(name)) return null;
    const v6 = /^\[(.+)\]$/.exec(address);
    // No zone index: the host never emits one.
    if (address.includes("%") || (v6 ? !isIPv6(v6[1] ?? "") : !isIPv4(address))) return null;
    names.push(name);
  }
  return names;
}

function isAbsoluteWindowsPath(path: string): boolean {
  if (!/^[A-Za-z]:\\/.test(path) || path.includes("/")) return false;
  // No empty, "." or ".." segments anywhere.
  return path.slice(3).split("\\").every((segment) => segment !== "" && segment !== "." && segment !== "..");
}

/// Defense-in-depth check of a launch frame against the SG-000108 contract.
/// Returns a reason when the frame must be refused, otherwise null.
export function launchRefusal(launch: Extract<HostFrame, { frame: "launch" }>): string | null {
  if (!isAbsoluteWindowsPath(launch.engine)) return "engine path is not an absolute Windows path";
  const leaf = launch.engine.split("\\").pop()?.toLowerCase();
  if (leaf !== "msedge.exe" && leaf !== "chrome.exe") return "engine is not a supported browser executable";
  if (!isAbsoluteWindowsPath(launch.profile_dir)) return "profile directory is not an absolute Windows path";
  for (const key of Object.keys(launch.env)) {
    if (!ENGINE_ENV_ALLOWLIST.includes(key)) return `engine environment key ${key} is not allowed`;
  }
  const { argv } = launch;
  const frozenCount = FROZEN_FLAGS.length;
  for (let index = 0; index < frozenCount; index++) {
    if (argv[index] !== FROZEN_FLAGS[index]) return "argv does not start with the frozen SG-000074 flags";
  }
  let rest = argv.slice(frozenCount);
  // Test fixtures only: one trusted certificate hash, accepted solely when
  // every admitted pin is loopback. Production pins come from the host's
  // public-address selection and are never loopback, so a release host
  // cannot use this even by mistake (and it never emits it).
  if (rest.length === 11) {
    const certificate = rest[9] ?? "";
    if (!/^--ignore-certificate-errors-spki-list=[A-Za-z0-9+/]{43}=$/.test(certificate)) {
      return "argv carries an unexpected flag";
    }
    const resolver = rest[2] ?? "";
    const pins = [...resolver.matchAll(/MAP [^ ,]+ (\S+):443/g)].map((match) => match[1]);
    if (pins.length === 0 || !pins.every((pin) => pin === "127.0.0.1" || pin === "[::1]")) {
      return "a trusted test certificate requires loopback fixture pins";
    }
    rest = [...rest.slice(0, 9), ...rest.slice(10)];
  }
  if (rest.length !== 10) return "argv does not carry exactly the profile and the eight confinement flags";
  const [profile, pipe, resolver, proxy, bypass, webrtc, quic, sharedWorker, features, initial] = rest;
  if (profile !== `--user-data-dir=${launch.profile_dir}`) return "argv profile differs from the launch profile";
  if (pipe !== PIPE) return "argv lacks the debugging pipe";
  const resolverPrefix = "--host-resolver-rules=";
  const names = resolver?.startsWith(resolverPrefix) ? parseResolverRules(resolver.slice(resolverPrefix.length)) : null;
  if (names === null) return "argv resolver rules are not an exact pinned map ending in MAP * ~NOTFOUND";
  if (proxy !== NO_ROUTE_PROXY) return "argv proxy is not the no-route proxy";
  if (bypass !== `--proxy-bypass-list=${[...names, "<-loopback>"].join(";")}`) {
    return "argv bypass list is not exactly the admitted names followed by <-loopback>";
  }
  if (webrtc !== WEBRTC_POLICY) return "argv lacks the WebRTC UDP policy";
  if (quic !== DISABLE_QUIC) return "argv lacks the QUIC refusal";
  if (sharedWorker !== DISABLE_SHARED_WORKER) return "argv lacks the SharedWorker refusal";
  if (features !== DISABLE_FEATURES) return "argv lacks the disabled network-reaching features";
  if (initial !== INITIAL_URL) return "argv does not end with the blank page";
  return null;
}
