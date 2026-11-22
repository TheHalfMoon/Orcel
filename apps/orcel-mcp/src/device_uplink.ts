/**
 * SG-000055 outbound-only device uplink.
 *
 * The device opens no listener. It reaches one configured relay origin with
 * outbound HTTPS requests only (challenge, session, long-poll, push) and
 * carries frozen SG-000052 frames: it accepts `mcp_request`, `cancel`, and
 * `heartbeat` from the relay and returns `mcp_response` and `mcp_error`.
 * There is no proxy, tunnel, socket forwarding, shell, or generic dispatch:
 * a request payload can only become one MCP message for the authoritative
 * Orcel tool registry, and every resulting kernel request carries the
 * server-supplied remote context that `orceld` checks against the local
 * remote-session lease.
 *
 * Frames are validated for exact shape, protocol version, channel
 * authentication, route, principal, connection, and device binding,
 * connection-scoped sequence, single-use replay nonces, duplicate
 * correlation, expiry, payload bounds, the device-verifiable authorization
 * envelope, and the leased scope ceiling. Queues, concurrency, rate, and
 * reconnect grace are bounded by the frozen relay contract. Nothing is
 * durably queued.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { JSONRPCMessage, Transport } from "@modelcontextprotocol/server";
import {
  isDeviceId,
  isRouteRevoked,
  signDeviceChallenge,
  verifyAuthorizationEnvelope,
  type DeviceChallenge,
  type RevocationRecord
} from "./device_identity.js";
import { KernelClient, type RemoteDispatchContext } from "./kernel.js";
import {
  authorizeToolByScopes,
  isOAuthScope,
  parseScopeString,
  REMOTE_CONNECTION_PATTERN,
  REMOTE_PRINCIPAL_PATTERN,
  type OAuthScope
} from "./oauth_authorization.js";
import {
  RELAY_BOUNDS,
  RELAY_ENVELOPE_FIELDS,
  RELAY_PROTOCOL_VERSION,
  type RelayFailureCode
} from "./relay_contract.js";
import { buildOrcelServer } from "./server.js";

/** Device channel endpoint paths below the relay origin. */
export const UPLINK_PATHS = {
  challenge: "/device/v1/challenge",
  session: "/device/v1/session",
  poll: "/device/v1/poll",
  push: "/device/v1/push"
} as const;

export const UPLINK_POLL_TIMEOUT_MS = 35_000;
export const UPLINK_REQUEST_TIMEOUT_MS = 15_000;
export const UPLINK_MIN_BACKOFF_MS = 1_000;
export const UPLINK_MAX_BACKOFF_MS = 30_000;
export const UPLINK_CLOCK_SKEW_MS = 30_000;
export const UPLINK_MAX_NONCES = 4096;
export const UPLINK_MAX_CORRELATIONS = 4096;
/** Hard cap on one relay response body (queued frames plus framing). */
export const UPLINK_MAX_BODY_BYTES =
  RELAY_BOUNDS.maxQueuedFrames * (RELAY_BOUNDS.maxFrameBytes + 8192) + 65536;

const CHANNEL_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,86}$/;
const CORRELATION_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const CONNECTION_ID_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;
const PROFILE_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const PROVIDER_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;

const INBOUND_KINDS = ["mcp_request", "cancel", "heartbeat"] as const;
type InboundKind = (typeof INBOUND_KINDS)[number];
const INBOUND_FIELDS: readonly string[] = [...RELAY_ENVELOPE_FIELDS, "payload"];

/** One locally paired remote provider connection (stable route). */
export interface PairedConnection {
  readonly principal: string;
  readonly remoteConnectionId: string;
  readonly providerKind: string;
  readonly clientProfileId: string;
  readonly clientProfileRevision: number;
  readonly toolSurfaceProfile: "core";
  readonly scopeCeiling: readonly OAuthScope[];
}

export interface UplinkIdentity {
  readonly deviceId: string;
  readonly deviceEpoch: number;
}

export interface InboundFrame {
  readonly protocolVersion: string;
  readonly routeDeviceId: string;
  readonly remoteConnectionId: string;
  readonly connectionId: string;
  readonly sequence: number;
  readonly replayNonce: string;
  readonly correlationId: string;
  readonly messageKind: InboundKind;
  readonly payloadLength: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly channelAuth: string;
  readonly authorizationEnvelope: Record<string, unknown>;
  readonly payload: string;
}

export interface OutboundFrame {
  readonly protocolVersion: string;
  readonly routeDeviceId: string;
  readonly remoteConnectionId: string;
  readonly connectionId: string;
  readonly sequence: number;
  readonly replayNonce: string;
  readonly correlationId: string;
  readonly messageKind: "mcp_response" | "mcp_error";
  readonly payloadLength: number;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly channelAuth: string;
  readonly payload: string | null;
  readonly failure: RelayFailureCode | null;
}

/** The MCP edge behind the uplink: one JSON-RPC message in, one response out. */
export interface UplinkDispatcher {
  dispatch(binding: ConnectionBinding, payload: string): Promise<string | null>;
  closeConnection(connectionId: string): void;
}

/** Everything that identifies one short-lived remote connection. */
export interface ConnectionBinding {
  readonly paired: PairedConnection;
  readonly connectionId: string;
  readonly scopes: readonly OAuthScope[];
  readonly remote: RemoteDispatchContext;
}

interface ConnectionState {
  readonly connectionId: string;
  readonly paired: PairedConnection;
  readonly scopes: readonly OAuthScope[];
  lastInboundSequence: number;
  inFlight: number;
  lastSeenMs: number;
  readonly correlations: Map<string, number>;
  readonly cancelled: Set<string>;
}

interface QueuedRequest {
  readonly frame: InboundFrame;
  readonly connection: ConnectionState;
  readonly receivedAtMs: number;
  readonly toolName: string | null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function equalAscii(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Canonical request digest over the frozen binding (principal, connection
 * identifiers, device, correlation, sequence, MCP method, payload digest).
 * The relay computes the same digest; the device recomputes it locally.
 */
export function computeRequestDigest(input: {
  readonly principal: string;
  readonly remoteConnectionId: string;
  readonly connectionId: string;
  readonly deviceId: string;
  readonly correlationId: string;
  readonly sequence: number;
  readonly method: string;
  readonly payload: string;
}): string {
  const hash = createHash("sha256");
  for (const field of [
    "ORCEL_RELAY_REQUEST_V1",
    input.principal,
    input.remoteConnectionId,
    input.connectionId,
    input.deviceId,
    input.correlationId,
    String(input.sequence),
    input.method,
    sha256Hex(Buffer.from(input.payload, "utf8"))
  ]) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

/**
 * The session context carries the token scopes the relay verified for this
 * connection as a canonical OAuth scope string. It is bounded by the
 * locally paired scope ceiling and pinned per connection.
 */
export function sessionContextFor(scopes: readonly OAuthScope[]): string {
  return `scopes=${["orcel.read", "orcel.write", "orcel.execute"].filter((s) => scopes.includes(s as OAuthScope)).join(" ")}`;
}

function parseSessionContext(value: unknown): readonly OAuthScope[] | null {
  if (typeof value !== "string" || !value.startsWith("scopes=")) {
    return null;
  }
  const parsed = parseScopeString(value.slice("scopes=".length));
  if (!parsed.ok || sessionContextFor(parsed.scopes) !== value) {
    return null;
  }
  return parsed.scopes;
}

/** Validate one locally stored pairing record. */
export function isPairedConnection(value: unknown): value is PairedConnection {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  const expected = [
    "clientProfileId",
    "clientProfileRevision",
    "principal",
    "providerKind",
    "remoteConnectionId",
    "scopeCeiling",
    "toolSurfaceProfile"
  ];
  if (keys.length !== expected.length || !expected.every((key, i) => keys[i] === key)) {
    return false;
  }
  return (
    typeof value.principal === "string" &&
    REMOTE_PRINCIPAL_PATTERN.test(value.principal) &&
    typeof value.remoteConnectionId === "string" &&
    REMOTE_CONNECTION_PATTERN.test(value.remoteConnectionId) &&
    typeof value.providerKind === "string" &&
    PROVIDER_PATTERN.test(value.providerKind) &&
    typeof value.clientProfileId === "string" &&
    PROFILE_PATTERN.test(value.clientProfileId) &&
    isSafeInt(value.clientProfileRevision) &&
    value.clientProfileRevision >= 0 &&
    value.toolSurfaceProfile === "core" &&
    Array.isArray(value.scopeCeiling) &&
    value.scopeCeiling.length > 0 &&
    value.scopeCeiling.every((s) => typeof s === "string" && isOAuthScope(s)) &&
    new Set(value.scopeCeiling).size === value.scopeCeiling.length
  );
}

/**
 * Relay origin: https only, or http on an exact loopback IP literal for a
 * self-hosted relay on the same machine. Origin only: no path, query,
 * fragment, or credentials.
 */
export function isRelayOrigin(value: unknown): value is string {
  if (typeof value !== "string") {
    return false;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.origin !== value || url.username !== "" || url.password !== "") {
    return false;
  }
  if (url.protocol === "https:") {
    return true;
  }
  return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "[::1]");
}

type Rejection = {
  readonly failure: RelayFailureCode;
  readonly frame: InboundFrame | null;
  readonly connection: ConnectionState | null;
};

/**
 * Pure channel core. It holds no socket and performs no I/O: frames come in
 * through `receive`, responses leave through `drainOutbox`, and dispatch
 * goes only through the injected MCP dispatcher.
 */
export class DeviceUplinkCore {
  private channelToken: string | null = null;
  private readonly connections = new Map<string, ConnectionState>();
  private readonly nonces = new Map<string, number>();
  private readonly queue: QueuedRequest[] = [];
  private readonly accepted: number[] = [];
  private readonly outbox: Omit<OutboundFrame, "channelAuth">[] = [];
  private readonly outboundSequences = new Map<string, { sequence: number; lastUsedMs: number }>();
  private readonly paired: ReadonlyMap<string, PairedConnection>;

  constructor(
    private readonly identity: UplinkIdentity,
    paired: readonly PairedConnection[],
    private readonly dispatcher: UplinkDispatcher,
    private readonly revocations: () => readonly RevocationRecord[],
    private readonly clock: () => number = Date.now
  ) {
    if (!isDeviceId(identity.deviceId) || !Number.isSafeInteger(identity.deviceEpoch) || identity.deviceEpoch < 1) {
      throw new Error("ROUTE_MISMATCH: invalid uplink device identity");
    }
    const map = new Map<string, PairedConnection>();
    for (const connection of paired) {
      if (!isPairedConnection(connection) || map.has(connection.remoteConnectionId)) {
        throw new Error("PAIRING_REQUIRED: invalid or duplicate paired connection");
      }
      map.set(connection.remoteConnectionId, connection);
    }
    this.paired = map;
  }

  /** Install the channel token from a fresh challenge-response session. */
  setChannelToken(token: string | null): void {
    if (token !== null && !CHANNEL_TOKEN_PATTERN.test(token)) {
      throw new Error("REMOTE_AUTH_INVALID: malformed channel token");
    }
    this.channelToken = token;
  }

  /**
   * Responses ready to push, authenticated with the current channel token.
   * Responses older than the bounded reconnect grace are dropped, never
   * persisted.
   */
  drainOutbox(nowMs: number): OutboundFrame[] {
    if (this.channelToken === null) {
      return [];
    }
    const token = this.channelToken;
    return this.outbox
      .splice(0, this.outbox.length)
      .filter((frame) => nowMs - frame.createdAt <= RELAY_BOUNDS.reconnectGraceSeconds * 1000)
      .map((frame) => ({ ...frame, channelAuth: token }));
  }

  queueLength(): number {
    return this.queue.length;
  }

  connectionCount(): number {
    return this.connections.size;
  }

  /** Validate and accept inbound frames. Rejections become `mcp_error`. */
  receive(rawFrames: readonly unknown[], nowMs: number): void {
    this.prune(nowMs);
    for (const raw of rawFrames) {
      const result = this.accept(raw, nowMs);
      if (result !== null) {
        this.reject(result, nowMs);
      }
    }
  }

  /** Dispatch queued requests up to the per-connection concurrency bound. */
  pump(nowMs: number): Promise<void>[] {
    const started: Promise<void>[] = [];
    for (let index = 0; index < this.queue.length; ) {
      const item = this.queue[index] as QueuedRequest;
      if (item.connection.inFlight >= RELAY_BOUNDS.maxConcurrentRequestsPerConnection) {
        index += 1;
        continue;
      }
      this.queue.splice(index, 1);
      if (
        nowMs > item.frame.expiresAt ||
        nowMs - item.receivedAtMs > RELAY_BOUNDS.queueLifetimeSeconds * 1000
      ) {
        this.emitError(item.connection, item.frame.correlationId, "REMOTE_QUEUE_EXPIRED", nowMs);
        continue;
      }
      const revoked = isRouteRevoked(
        {
          principal: item.connection.paired.principal,
          stableConnectionId: item.connection.paired.remoteConnectionId,
          deviceId: this.identity.deviceId,
          epoch: this.identity.deviceEpoch
        },
        this.revocations()
      );
      if (!revoked.ok) {
        this.emitError(item.connection, item.frame.correlationId, revoked.failure, nowMs);
        continue;
      }
      if (item.connection.cancelled.has(item.frame.correlationId)) {
        continue;
      }
      started.push(this.run(item));
    }
    return started;
  }

  private async run(item: QueuedRequest): Promise<void> {
    const connection = item.connection;
    connection.inFlight += 1;
    const binding: ConnectionBinding = {
      paired: connection.paired,
      connectionId: connection.connectionId,
      scopes: connection.scopes,
      remote: {
        principal: connection.paired.principal,
        remoteConnectionId: connection.paired.remoteConnectionId,
        connectionId: connection.connectionId,
        deviceId: this.identity.deviceId,
        deviceEpoch: this.identity.deviceEpoch,
        providerKind: connection.paired.providerKind,
        clientProfileId: connection.paired.clientProfileId,
        clientProfileRevision: connection.paired.clientProfileRevision,
        toolSurfaceProfile: "core",
        scopes: [...connection.scopes]
      }
    };
    let result: string | null = null;
    let failure: RelayFailureCode | null = null;
    try {
      result = await this.dispatcher.dispatch(binding, item.frame.payload);
    } catch {
      failure = "TRANSPORT_UNAVAILABLE";
    } finally {
      connection.inFlight -= 1;
    }
    const now = this.clock();
    if (connection.cancelled.has(item.frame.correlationId)) {
      return;
    }
    if (failure !== null) {
      this.emitError(connection, item.frame.correlationId, failure, now);
      return;
    }
    if (result === null) {
      return;
    }
    if (Buffer.byteLength(result, "utf8") > RELAY_BOUNDS.maxResultBytes) {
      this.emitError(connection, item.frame.correlationId, "REMOTE_RATE_LIMITED", now);
      return;
    }
    this.emit(connection, item.frame.correlationId, "mcp_response", result, null, now);
  }

  private prune(nowMs: number): void {
    for (const [nonce, expiresAt] of this.nonces) {
      if (expiresAt < nowMs) {
        this.nonces.delete(nonce);
      }
    }
    for (const [id, connection] of this.connections) {
      for (const [correlation, expiresAt] of connection.correlations) {
        if (expiresAt < nowMs) {
          connection.correlations.delete(correlation);
          connection.cancelled.delete(correlation);
        }
      }
      if (
        connection.inFlight === 0 &&
        nowMs - connection.lastSeenMs > RELAY_BOUNDS.idleChannelSuspendSeconds * 1000 &&
        !this.queue.some((item) => item.connection === connection)
      ) {
        this.connections.delete(id);
        this.dispatcher.closeConnection(id);
      }
    }
    while (this.accepted.length > 0 && nowMs - (this.accepted[0] as number) > 60_000) {
      this.accepted.shift();
    }
    for (const [id, entry] of this.outboundSequences) {
      if (!this.connections.has(id) && nowMs - entry.lastUsedMs > RELAY_BOUNDS.idleChannelSuspendSeconds * 1000) {
        this.outboundSequences.delete(id);
      }
    }
  }

  private accept(raw: unknown, nowMs: number): Rejection | null {
    const malformed: Rejection = { failure: "MCP_PROTOCOL_UNSUPPORTED", frame: null, connection: null };
    if (!isPlainObject(raw)) {
      return malformed;
    }
    const keys = Object.keys(raw);
    if (keys.length !== INBOUND_FIELDS.length || !INBOUND_FIELDS.every((key) => Object.hasOwn(raw, key))) {
      return malformed;
    }
    if (raw.protocolVersion !== RELAY_PROTOCOL_VERSION) {
      return malformed;
    }
    if (typeof raw.messageKind !== "string" || !(INBOUND_KINDS as readonly string[]).includes(raw.messageKind)) {
      return malformed;
    }
    if (
      typeof raw.routeDeviceId !== "string" ||
      typeof raw.remoteConnectionId !== "string" ||
      typeof raw.connectionId !== "string" ||
      !CONNECTION_ID_PATTERN.test(raw.connectionId) ||
      typeof raw.replayNonce !== "string" ||
      typeof raw.correlationId !== "string" ||
      !CORRELATION_PATTERN.test(raw.correlationId) ||
      typeof raw.channelAuth !== "string" ||
      typeof raw.payload !== "string" ||
      !isSafeInt(raw.sequence) ||
      raw.sequence < 1 ||
      !isSafeInt(raw.payloadLength) ||
      !isSafeInt(raw.createdAt) ||
      !isSafeInt(raw.expiresAt) ||
      !isPlainObject(raw.authorizationEnvelope)
    ) {
      return malformed;
    }
    const frame = raw as unknown as InboundFrame;
    if (this.channelToken === null || !equalAscii(frame.channelAuth, this.channelToken)) {
      return { failure: "REMOTE_AUTH_INVALID", frame: null, connection: null };
    }
    if (frame.routeDeviceId !== this.identity.deviceId) {
      return { failure: "ROUTE_MISMATCH", frame: null, connection: null };
    }
    const paired = this.paired.get(frame.remoteConnectionId);
    if (paired === undefined) {
      return { failure: "ROUTE_MISMATCH", frame: null, connection: null };
    }
    const bytes = Buffer.byteLength(frame.payload, "utf8");
    if (bytes > RELAY_BOUNDS.maxFrameBytes || frame.payloadLength > RELAY_BOUNDS.maxFrameBytes) {
      return { failure: "REMOTE_RATE_LIMITED", frame, connection: null };
    }
    if (bytes !== frame.payloadLength) {
      return { failure: "MCP_PROTOCOL_UNSUPPORTED", frame, connection: null };
    }
    if (
      frame.expiresAt <= frame.createdAt ||
      frame.expiresAt - frame.createdAt > RELAY_BOUNDS.maxFrameLifetimeSeconds * 1000 ||
      nowMs > frame.expiresAt ||
      frame.createdAt > nowMs + UPLINK_CLOCK_SKEW_MS
    ) {
      return { failure: "REMOTE_QUEUE_EXPIRED", frame, connection: null };
    }
    if (!NONCE_PATTERN.test(frame.replayNonce)) {
      return malformed;
    }
    if (this.nonces.has(frame.replayNonce)) {
      return { failure: "RELAY_REPLAY_DETECTED", frame, connection: null };
    }
    const scopes = parseSessionContext(frame.authorizationEnvelope.sessionContext);
    if (scopes === null || !scopes.every((scope) => paired.scopeCeiling.includes(scope))) {
      return { failure: "REMOTE_SCOPE_DENIED", frame, connection: null };
    }
    let method = "";
    let toolName: string | null = null;
    if (frame.messageKind === "mcp_request") {
      const parsed = parseJsonRpc(frame.payload);
      if (parsed === null) {
        return { failure: "MCP_PROTOCOL_UNSUPPORTED", frame, connection: null };
      }
      method = parsed.method;
      toolName = parsed.toolName;
    } else if (frame.payload !== "") {
      return malformed;
    }
    const envelope = verifyAuthorizationEnvelope(
      {
        principal: frame.authorizationEnvelope.principal,
        connection: frame.authorizationEnvelope.connection,
        device: frame.authorizationEnvelope.device,
        requestDigest: frame.authorizationEnvelope.requestDigest,
        epoch: frame.authorizationEnvelope.epoch,
        sessionContext: frame.authorizationEnvelope.sessionContext
      },
      {
        principal: paired.principal,
        connection: paired.remoteConnectionId,
        deviceId: this.identity.deviceId,
        requestDigestHex: computeRequestDigest({
          principal: paired.principal,
          remoteConnectionId: paired.remoteConnectionId,
          connectionId: frame.connectionId,
          deviceId: this.identity.deviceId,
          correlationId: frame.correlationId,
          sequence: frame.sequence,
          method,
          payload: frame.payload
        }),
        epoch: this.identity.deviceEpoch,
        sessionContext: sessionContextFor(scopes)
      },
      this.revocations()
    );
    if (!envelope.ok) {
      return { failure: envelope.failure, frame, connection: null };
    }
    let connection = this.connections.get(frame.connectionId);
    if (connection !== undefined) {
      if (connection.paired.remoteConnectionId !== paired.remoteConnectionId) {
        return { failure: "ROUTE_MISMATCH", frame: null, connection: null };
      }
      if (sessionContextFor(connection.scopes) !== sessionContextFor(scopes)) {
        return { failure: "ROUTE_MISMATCH", frame, connection };
      }
    } else {
      const sameRoute = [...this.connections.values()].filter(
        (state) => state.paired.remoteConnectionId === paired.remoteConnectionId
      );
      if (this.connections.size >= RELAY_BOUNDS.maxConnectionsPerDevice || sameRoute.length >= RELAY_BOUNDS.maxConnectionsPerDevice) {
        return { failure: "REMOTE_RATE_LIMITED", frame, connection: null };
      }
      if (frame.sequence !== 1) {
        return { failure: "RELAY_SEQUENCE_INVALID", frame, connection: null };
      }
      connection = {
        connectionId: frame.connectionId,
        paired,
        scopes,
        lastInboundSequence: 0,
        inFlight: 0,
        lastSeenMs: nowMs,
        correlations: new Map(),
        cancelled: new Set()
      };
    }
    if (frame.sequence <= connection.lastInboundSequence) {
      return { failure: "RELAY_REPLAY_DETECTED", frame, connection };
    }
    if (frame.sequence !== connection.lastInboundSequence + 1) {
      return { failure: "RELAY_SEQUENCE_INVALID", frame, connection };
    }
    if (this.nonces.size >= UPLINK_MAX_NONCES) {
      return { failure: "REMOTE_RATE_LIMITED", frame, connection };
    }
    if (frame.messageKind === "mcp_request") {
      if (connection.correlations.has(frame.correlationId)) {
        return { failure: "RELAY_REPLAY_DETECTED", frame, connection };
      }
      if (connection.correlations.size >= UPLINK_MAX_CORRELATIONS) {
        return { failure: "REMOTE_RATE_LIMITED", frame, connection };
      }
      if (
        this.queue.length >= RELAY_BOUNDS.maxQueuedFrames ||
        this.accepted.length >= RELAY_BOUNDS.maxRequestsPerMinutePerDevice
      ) {
        return { failure: "REMOTE_RATE_LIMITED", frame, connection };
      }
      if (toolName !== null) {
        const scopeCheck = authorizeToolByScopes(toolName, "core", scopes, paired.scopeCeiling);
        if (!scopeCheck.ok) {
          this.commit(frame, connection, nowMs);
          connection.correlations.set(frame.correlationId, frame.expiresAt + 60_000);
          return { failure: scopeCheck.failure, frame, connection };
        }
      }
    }
    this.commit(frame, connection, nowMs);
    switch (frame.messageKind) {
      case "heartbeat":
        return null;
      case "cancel": {
        connection.cancelled.add(frame.correlationId);
        const queued = this.queue.findIndex(
          (item) => item.connection === connection && item.frame.correlationId === frame.correlationId
        );
        if (queued >= 0) {
          this.queue.splice(queued, 1);
        }
        return null;
      }
      case "mcp_request":
        connection.correlations.set(frame.correlationId, frame.expiresAt + 60_000);
        this.accepted.push(nowMs);
        this.queue.push({ frame, connection, receivedAtMs: nowMs, toolName });
        return null;
    }
  }

  private commit(frame: InboundFrame, connection: ConnectionState, nowMs: number): void {
    this.nonces.set(frame.replayNonce, frame.expiresAt + UPLINK_CLOCK_SKEW_MS);
    connection.lastInboundSequence = frame.sequence;
    connection.lastSeenMs = nowMs;
    if (!this.connections.has(connection.connectionId)) {
      this.connections.set(connection.connectionId, connection);
    }
  }

  private reject(rejection: Rejection, nowMs: number): void {
    // Rejections that cannot be attributed to an authenticated, paired
    // route produce no frame: there is no verified recipient to answer.
    if (rejection.frame === null) {
      return;
    }
    const frame = rejection.frame;
    const paired = this.paired.get(frame.remoteConnectionId);
    if (paired === undefined) {
      return;
    }
    const connection =
      rejection.connection ??
      this.connections.get(frame.connectionId) ?? {
        connectionId: frame.connectionId,
        paired,
        scopes: [],
        lastInboundSequence: 0,
        inFlight: 0,
        lastSeenMs: nowMs,
        correlations: new Map<string, number>(),
        cancelled: new Set<string>()
      };
    if (connection.paired.remoteConnectionId !== paired.remoteConnectionId) {
      return;
    }
    this.emitError(connection, frame.correlationId, rejection.failure, nowMs);
  }

  private emitError(
    connection: ConnectionState,
    correlationId: string,
    failure: RelayFailureCode,
    nowMs: number
  ): void {
    this.emit(connection, correlationId, "mcp_error", null, failure, nowMs);
  }

  private emit(
    connection: ConnectionState,
    correlationId: string,
    messageKind: "mcp_response" | "mcp_error",
    payload: string | null,
    failure: RelayFailureCode | null,
    nowMs: number
  ): void {
    const entry = this.outboundSequences.get(connection.connectionId) ?? { sequence: 0, lastUsedMs: nowMs };
    entry.sequence += 1;
    entry.lastUsedMs = nowMs;
    this.outboundSequences.set(connection.connectionId, entry);
    this.outbox.push({
      protocolVersion: RELAY_PROTOCOL_VERSION,
      routeDeviceId: this.identity.deviceId,
      remoteConnectionId: connection.paired.remoteConnectionId,
      connectionId: connection.connectionId,
      sequence: entry.sequence,
      replayNonce: randomBytes(16).toString("base64url"),
      correlationId,
      messageKind,
      payloadLength: payload === null ? 0 : Buffer.byteLength(payload, "utf8"),
      createdAt: nowMs,
      expiresAt: nowMs + RELAY_BOUNDS.maxFrameLifetimeSeconds * 1000,
      payload,
      failure
    });
  }
}

/** Parse one JSON-RPC message; returns its method and any tool name. */
function parseJsonRpc(payload: string): { method: string; toolName: string | null } | null {
  let message: unknown;
  try {
    message = JSON.parse(payload);
  } catch {
    return null;
  }
  if (!isPlainObject(message) || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return null;
  }
  if (message.method.length === 0 || message.method.length > 128) {
    return null;
  }
  let toolName: string | null = null;
  if (message.method === "tools/call") {
    if (!isPlainObject(message.params) || typeof message.params.name !== "string") {
      return null;
    }
    toolName = message.params.name;
  }
  return { method: message.method, toolName };
}

// ---------------------------------------------------------------------------
// MCP edge behind the uplink

/** In-process MCP transport fed by verified frames; it opens nothing. */
class FrameTransport implements Transport {
  onclose?: (() => void) | undefined;
  onerror?: ((error: Error) => void) | undefined;
  onmessage?: ((message: JSONRPCMessage) => void) | undefined;
  private readonly pending = new Map<string, (response: string) => void>();
  private closed = false;

  async start(): Promise<void> {}

  async send(message: JSONRPCMessage): Promise<void> {
    if (!isPlainObject(message) || !("id" in message) || "method" in message) {
      // Server-initiated requests and notifications have no channel back.
      return;
    }
    const key = JSON.stringify((message as { id: unknown }).id);
    const resolve = this.pending.get(key);
    if (resolve !== undefined) {
      this.pending.delete(key);
      resolve(JSON.stringify(message));
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const resolve of this.pending.values()) {
      resolve(
        JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32603, message: "TRANSPORT_UNAVAILABLE" }
        })
      );
    }
    this.pending.clear();
    this.onclose?.();
  }

  deliver(message: Record<string, unknown>): Promise<string | null> {
    if (this.closed) {
      return Promise.reject(new Error("TRANSPORT_UNAVAILABLE"));
    }
    if (!("id" in message)) {
      this.onmessage?.(message as unknown as JSONRPCMessage);
      return Promise.resolve(null);
    }
    const key = JSON.stringify(message.id);
    if (this.pending.has(key)) {
      return Promise.resolve(
        JSON.stringify({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32600, message: "duplicate in-flight request id" }
        })
      );
    }
    return new Promise((resolve) => {
      this.pending.set(key, resolve);
      this.onmessage?.(message as unknown as JSONRPCMessage);
    });
  }
}

/**
 * Dispatch verified frames into the authoritative Orcel MCP builder. One
 * server and one remote-context kernel exist per short-lived connection.
 */
export function createMcpFrameDispatcher(options: {
  readonly defaultWorkspace: string;
  readonly kernelFactory?: (remote: RemoteDispatchContext) => KernelClient;
}): UplinkDispatcher {
  const sessions = new Map<string, { transport: FrameTransport; close: () => void }>();
  const kernelFactory =
    options.kernelFactory ?? ((remote) => new KernelClient(process.env.ORCEL_DAEMON ?? "orceld", remote));
  return {
    async dispatch(binding, payload) {
      let session = sessions.get(binding.connectionId);
      if (session === undefined) {
        const kernel = kernelFactory(binding.remote);
        const server = buildOrcelServer(kernel, options.defaultWorkspace, {
          transportKind: "relay",
          providerKind: binding.paired.providerKind,
          toolSurfaceProfile: "core"
        });
        const transport = new FrameTransport();
        await server.connect(transport);
        session = {
          transport,
          close: () => {
            void server.close();
          }
        };
        sessions.set(binding.connectionId, session);
      }
      const message: unknown = JSON.parse(payload);
      if (!isPlainObject(message)) {
        throw new Error("MCP_PROTOCOL_UNSUPPORTED");
      }
      return session.transport.deliver(message);
    },
    closeConnection(connectionId) {
      const session = sessions.get(connectionId);
      if (session !== undefined) {
        sessions.delete(connectionId);
        session.close();
      }
    }
  };
}

// ---------------------------------------------------------------------------
// Outbound-only network client

export interface UplinkConfig {
  readonly relayOrigin: string;
  readonly identity: UplinkIdentity;
  readonly privateKeyJwkBase64: string;
  readonly connections: readonly PairedConnection[];
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

/** Read a response body with a hard byte cap. */
export async function readBoundedJson(response: Response, maxBytes: number): Promise<unknown> {
  const reader = response.body?.getReader();
  if (reader === undefined) {
    return null;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error("REMOTE_RATE_LIMITED: relay response exceeds the bound");
    }
    chunks.push(value);
  }
  if (total === 0) {
    return null;
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function postJson(
  fetchImpl: FetchLike,
  origin: string,
  path: string,
  body: unknown,
  timeoutMs: number,
  signal: AbortSignal
): Promise<{ status: number; json: unknown }> {
  const response = await fetchImpl(origin + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    credentials: "omit",
    signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
  });
  const json = await readBoundedJson(response, UPLINK_MAX_BODY_BYTES);
  return { status: response.status, json };
}

/** Challenge-response channel authentication with the SG-000053 device key. */
export async function openChannel(
  config: UplinkConfig,
  fetchImpl: FetchLike,
  nowMs: () => number,
  signal: AbortSignal
): Promise<string> {
  const challengeReply = await postJson(
    fetchImpl,
    config.relayOrigin,
    UPLINK_PATHS.challenge,
    { deviceId: config.identity.deviceId, epoch: config.identity.deviceEpoch },
    UPLINK_REQUEST_TIMEOUT_MS,
    signal
  );
  if (challengeReply.status !== 200 || !isPlainObject(challengeReply.json)) {
    throw new Error("TRANSPORT_UNAVAILABLE: channel challenge failed");
  }
  const challenge = challengeReply.json.challenge;
  if (
    !isPlainObject(challenge) ||
    challenge.deviceId !== config.identity.deviceId ||
    challenge.epoch !== config.identity.deviceEpoch ||
    typeof challenge.nonceBase64 !== "string" ||
    !isSafeInt(challenge.createdAtMs) ||
    !isSafeInt(challenge.expiresAtMs) ||
    challenge.expiresAtMs <= challenge.createdAtMs ||
    challenge.expiresAtMs - challenge.createdAtMs > RELAY_BOUNDS.maxFrameLifetimeSeconds * 1000 ||
    nowMs() > challenge.expiresAtMs
  ) {
    throw new Error("REMOTE_AUTH_INVALID: relay challenge does not bind this device");
  }
  const response = signDeviceChallenge(config.privateKeyJwkBase64, challenge as unknown as DeviceChallenge);
  const sessionReply = await postJson(
    fetchImpl,
    config.relayOrigin,
    UPLINK_PATHS.session,
    { response },
    UPLINK_REQUEST_TIMEOUT_MS,
    signal
  );
  if (
    sessionReply.status !== 200 ||
    !isPlainObject(sessionReply.json) ||
    typeof sessionReply.json.channelToken !== "string" ||
    !CHANNEL_TOKEN_PATTERN.test(sessionReply.json.channelToken)
  ) {
    throw new Error("REMOTE_AUTH_INVALID: relay refused the device channel");
  }
  return sessionReply.json.channelToken;
}

/** At most this many refresh-proof challenges are answered per poll. */
export const UPLINK_MAX_PROOFS = 16;

/**
 * SG-000057: sign refresh-proof challenges delivered on the live channel.
 * Only challenges that bind this exact device and epoch, carry a lifetime of
 * at most 120 seconds, and have not expired are signed; anything else is
 * ignored. Signing proves only that this device is online now; the relay
 * binds the proof to one refresh family and verifies it.
 */
export function signRefreshProofs(
  config: UplinkConfig,
  raw: unknown,
  nowMs: number
): ReturnType<typeof signDeviceChallenge>[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const signed: ReturnType<typeof signDeviceChallenge>[] = [];
  for (const challenge of raw.slice(0, UPLINK_MAX_PROOFS)) {
    if (
      !isPlainObject(challenge) ||
      challenge.deviceId !== config.identity.deviceId ||
      challenge.epoch !== config.identity.deviceEpoch ||
      typeof challenge.nonceBase64 !== "string" ||
      challenge.nonceBase64.length < 16 ||
      challenge.nonceBase64.length > 128 ||
      !isSafeInt(challenge.createdAtMs) ||
      !isSafeInt(challenge.expiresAtMs) ||
      challenge.expiresAtMs <= challenge.createdAtMs ||
      challenge.expiresAtMs - challenge.createdAtMs > RELAY_BOUNDS.maxFrameLifetimeSeconds * 1000 ||
      nowMs > challenge.expiresAtMs
    ) {
      continue;
    }
    signed.push(signDeviceChallenge(config.privateKeyJwkBase64, challenge as unknown as DeviceChallenge));
  }
  return signed;
}

export function backoffMs(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(UPLINK_MAX_BACKOFF_MS, UPLINK_MIN_BACKOFF_MS * 2 ** Math.min(attempt, 10));
  return Math.floor(base / 2 + random() * (base / 2));
}

/**
 * Run the uplink until `signal` aborts. Every network operation is an
 * outbound POST to the configured relay origin; redirects are refused and
 * bodies are bounded. Errors re-authenticate with bounded backoff.
 */
export async function runDeviceUplink(
  config: UplinkConfig,
  deps: {
    readonly fetch: FetchLike;
    readonly dispatcher: UplinkDispatcher;
    readonly revocations: () => readonly RevocationRecord[];
    readonly signal: AbortSignal;
    readonly now?: () => number;
    readonly sleep?: (ms: number) => Promise<void>;
    readonly log?: (event: string) => void;
  }
): Promise<void> {
  if (!isRelayOrigin(config.relayOrigin)) {
    throw new Error("TRANSPORT_UNAVAILABLE: relay origin must be https or an exact loopback origin");
  }
  const now = deps.now ?? Date.now;
  const sleep =
    deps.sleep ??
    ((ms: number) =>
      new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, ms);
        deps.signal.addEventListener("abort", () => {
          clearTimeout(timer);
          resolve();
        });
      }));
  const log = deps.log ?? (() => {});
  const core = new DeviceUplinkCore(
    config.identity,
    config.connections,
    deps.dispatcher,
    deps.revocations,
    now
  );
  let attempt = 0;
  let proofs: ReturnType<typeof signDeviceChallenge>[] = [];
  const pushOutbox = async (token: string): Promise<void> => {
    const frames = core.drainOutbox(now());
    const signedProofs = proofs.splice(0, proofs.length);
    if (frames.length === 0 && signedProofs.length === 0) {
      return;
    }
    const reply = await postJson(
      deps.fetch,
      config.relayOrigin,
      UPLINK_PATHS.push,
      signedProofs.length === 0
        ? { channelToken: token, frames }
        : { channelToken: token, frames, proofs: signedProofs },
      UPLINK_REQUEST_TIMEOUT_MS,
      deps.signal
    );
    if (reply.status !== 200 && reply.status !== 204) {
      throw new Error("TRANSPORT_UNAVAILABLE: relay refused pushed frames");
    }
  };
  while (!deps.signal.aborted) {
    let token: string;
    try {
      token = await openChannel(config, deps.fetch, now, deps.signal);
      core.setChannelToken(token);
      attempt = 0;
      log("channel_open");
    } catch {
      core.setChannelToken(null);
      log("channel_failed");
      await sleep(backoffMs(attempt));
      attempt += 1;
      continue;
    }
    try {
      while (!deps.signal.aborted) {
        const reply = await postJson(
          deps.fetch,
          config.relayOrigin,
          UPLINK_PATHS.poll,
          { channelToken: token },
          UPLINK_POLL_TIMEOUT_MS,
          deps.signal
        );
        if (reply.status === 401 || reply.status === 403) {
          throw new Error("REMOTE_AUTH_INVALID: channel session ended");
        }
        if (reply.status !== 200 || !isPlainObject(reply.json) || !Array.isArray(reply.json.frames)) {
          throw new Error("TRANSPORT_UNAVAILABLE: malformed poll reply");
        }
        if (reply.json.frames.length > RELAY_BOUNDS.maxQueuedFrames) {
          throw new Error("REMOTE_RATE_LIMITED: relay exceeded the frame bound");
        }
        core.receive(reply.json.frames, now());
        proofs.push(...signRefreshProofs(config, reply.json.proofs, now()));
        await pushOutbox(token);
        const running = core.pump(now());
        if (running.length > 0) {
          void Promise.allSettled(running).then(() => pushOutbox(token).catch(() => undefined));
        }
      }
    } catch {
      core.setChannelToken(null);
      log("channel_lost");
      await sleep(backoffMs(attempt));
      attempt += 1;
    }
  }
}
