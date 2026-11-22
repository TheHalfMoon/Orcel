/**
 * SG-000056 public Streamable HTTP MCP edge.
 *
 * `/mcp` accepts one JSON-RPC message per POST. Every request carries an
 * SG-000054 bearer access token that is verified (signature, issuer,
 * audience equal to this resource, lifetime, revocation, device epoch) and
 * scope-checked against the default-deny tool ceiling before any frame is
 * created. Remote context is derived only from the verified token and the
 * stored paired route; MCP payloads and tool arguments never select a
 * principal, device, connection, profile, or scope. Each MCP session maps
 * onto exactly one short-lived device connection and one paired route.
 * The edge forwards frozen MCP frames only; it has no executor, no proxy,
 * and no tool of its own.
 */
import { randomBytes } from "node:crypto";
import { SUPPORTED_PROTOCOL_VERSIONS } from "@modelcontextprotocol/server";
import {
  computeRequestDigest,
  sessionContextFor
} from "@orcel/mcp/dist/device_uplink.js";
import {
  authorizeToolByScopes,
  verifyAccessToken,
  type OAuthScope,
  type RemotePrincipalIdentity
} from "@orcel/mcp/dist/oauth_authorization.js";
import {
  RELAY_BOUNDS,
  RELAY_PROTOCOL_VERSION,
  type RelayFailureCode
} from "@orcel/mcp/dist/relay_contract.js";
import type { DeviceChannelHub } from "./device_channel.js";
import type { QuotaGuard } from "./quotas.js";
import type { RelayConnectionRecord, RelayStore } from "./store.js";

export const MAX_SESSIONS_PER_ROUTE = RELAY_BOUNDS.maxConnectionsPerDevice;
export const MAX_SESSIONS_TOTAL = 1024;
/** Below the device's 120-second idle suspend so a session never outlives its device state. */
export const SESSION_IDLE_MS = 100_000;
export const REQUEST_TIMEOUT_MS = 55_000;
export const FRAME_LIFETIME_MS = 60_000;

export interface EdgeConfig {
  /** Public origin of this relay, for example `https://relay.example`. */
  readonly publicOrigin: string;
  /** Authorization server issuer whose tokens this resource accepts. */
  readonly issuer: string;
  /** Browser origins allowed to call `/mcp`; empty denies every Origin. */
  readonly allowedOrigins: readonly string[];
}

export interface EdgeRequest {
  readonly method: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: string;
}

export interface EdgeResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

interface Session {
  readonly id: string;
  readonly connectionId: string;
  readonly principal: string;
  readonly remoteConnectionId: string;
  readonly deviceId: string;
  readonly epoch: number;
  readonly scopes: readonly OAuthScope[];
  nextSequence: number;
  inFlight: number;
  lastUsedMs: number;
}

const JSON_HEADERS = {
  "content-type": "application/json",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff"
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonRpcError(
  id: unknown,
  code: number,
  message: string,
  failure?: RelayFailureCode
): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: id === undefined ? null : id,
    error: failure === undefined ? { code, message } : { code, message, data: { failure } }
  });
}

const SESSION_BREAKING_FAILURES: readonly RelayFailureCode[] = [
  "DEVICE_OFFLINE",
  "TRANSPORT_UNAVAILABLE",
  "RELAY_SEQUENCE_INVALID",
  "RELAY_REPLAY_DETECTED",
  "ROUTE_MISMATCH",
  "DEVICE_REVOKED"
];

const FAILURE_STATUS: Partial<Record<RelayFailureCode, number>> = {
  DEVICE_OFFLINE: 503,
  TRANSPORT_UNAVAILABLE: 503,
  REMOTE_RATE_LIMITED: 429,
  REMOTE_QUEUE_EXPIRED: 504,
  REMOTE_SCOPE_DENIED: 403,
  TOOL_SURFACE_DENIED: 403,
  ROUTE_MISMATCH: 403,
  DEVICE_REVOKED: 403,
  REMOTE_AUTH_INVALID: 401,
  REMOTE_AUTH_REQUIRED: 401
};

export class McpEdge {
  private readonly sessions = new Map<string, Session>();

  constructor(
    private readonly config: EdgeConfig,
    private readonly store: RelayStore,
    private readonly hub: DeviceChannelHub,
    private readonly clock: () => number = Date.now,
    private readonly quotas: QuotaGuard | null = null
  ) {}

  get resource(): string {
    return `${this.config.publicOrigin}/mcp`;
  }

  get resourceMetadataUrl(): string {
    return `${this.config.publicOrigin}/.well-known/oauth-protected-resource/mcp`;
  }

  sessionCount(): number {
    return this.sessions.size;
  }

  private respond(status: number, body: string, extra: Record<string, string> = {}): EdgeResponse {
    return { status, headers: { ...JSON_HEADERS, ...extra }, body };
  }

  private challenge(status: 401 | 403, error: string | null, scope?: string): EdgeResponse {
    const parts = [`resource_metadata="${this.resourceMetadataUrl}"`];
    if (error !== null) {
      parts.push(`error="${error}"`);
    }
    if (scope !== undefined) {
      parts.push(`scope="${scope}"`);
    }
    return this.respond(
      status,
      jsonRpcError(null, -32001, error ?? "authorization required"),
      { "www-authenticate": `Bearer ${parts.join(", ")}` }
    );
  }

  private prune(now: number): void {
    for (const [id, session] of this.sessions) {
      if (session.inFlight === 0 && now - session.lastUsedMs > SESSION_IDLE_MS) {
        this.sessions.delete(id);
      }
    }
  }

  private authenticate(
    headers: EdgeRequest["headers"]
  ): { identity: RemotePrincipalIdentity; route: RelayConnectionRecord } | EdgeResponse {
    const authorization = headers.authorization;
    if (authorization === undefined || authorization === "") {
      return this.challenge(401, null);
    }
    const match = /^Bearer ([A-Za-z0-9._~+/=-]+)$/.exec(authorization);
    if (match === null) {
      return this.challenge(401, "invalid_token");
    }
    const verified = verifyAccessToken(match[1], {
      issuer: this.config.issuer,
      resource: this.resource,
      keys: this.store.verificationKeys(),
      nowMs: this.clock(),
      revokedTokenIds: this.store.revokedTokenIds(),
      revokedFamilyIds: this.store.revokedFamilyIds(),
      revocations: this.store.revocations(),
      deviceEpochs: this.store.deviceEpochs()
    });
    if (!verified.ok) {
      return this.challenge(401, "invalid_token");
    }
    const identity = verified.identity;
    const route = this.store.connection(identity.connection);
    const device = this.store.device(identity.deviceId);
    if (
      route === undefined ||
      route.revoked ||
      device === undefined ||
      device.revoked ||
      route.principal !== identity.principal ||
      route.deviceId !== identity.deviceId ||
      route.clientId !== identity.clientId
    ) {
      return this.challenge(401, "invalid_token");
    }
    return { identity, route };
  }

  async handle(request: EdgeRequest): Promise<EdgeResponse> {
    const now = this.clock();
    this.prune(now);
    const origin = request.headers.origin;
    if (origin !== undefined && !this.config.allowedOrigins.includes(origin)) {
      return this.respond(403, jsonRpcError(null, -32600, "origin not allowed"));
    }
    if (request.method === "GET") {
      return this.respond(405, jsonRpcError(null, -32600, "server-initiated streams are not offered"), {
        allow: "POST, DELETE"
      });
    }
    if (request.method !== "POST" && request.method !== "DELETE") {
      return this.respond(405, jsonRpcError(null, -32600, "method not allowed"), { allow: "POST, DELETE" });
    }
    const auth = this.authenticate(request.headers);
    if ("status" in auth) {
      return auth;
    }
    const { identity, route } = auth;
    if (this.quotas !== null) {
      const quota = this.quotas.mcpRequest(route.remoteConnectionId);
      if (!quota.ok) {
        // No-billing overflow: exhaustion fails closed and never scales.
        return this.respond(429, jsonRpcError(null, -32000, "quota exhausted", "REMOTE_RATE_LIMITED"), {
          "retry-after": String(quota.retryAfterSeconds)
        });
      }
    }
    const sessionHeader = request.headers["mcp-session-id"];
    if (request.method === "DELETE") {
      const session = sessionHeader === undefined ? undefined : this.sessions.get(sessionHeader);
      if (session === undefined || session.principal !== identity.principal || session.remoteConnectionId !== route.remoteConnectionId) {
        return this.respond(404, jsonRpcError(null, -32001, "session not found"));
      }
      this.sessions.delete(session.id);
      return { status: 204, headers: { "cache-control": "no-store" }, body: "" };
    }
    const contentType = request.headers["content-type"] ?? "";
    if (!contentType.toLowerCase().startsWith("application/json")) {
      return this.respond(415, jsonRpcError(null, -32700, "content-type must be application/json"));
    }
    const accept = request.headers.accept ?? "";
    if (!/application\/json|\*\/\*/i.test(accept)) {
      return this.respond(406, jsonRpcError(null, -32600, "accept must include application/json"));
    }
    if (Buffer.byteLength(request.body, "utf8") > RELAY_BOUNDS.maxFrameBytes) {
      return this.respond(413, jsonRpcError(null, -32600, "request too large", "REMOTE_RATE_LIMITED"));
    }
    let message: unknown;
    try {
      message = JSON.parse(request.body);
    } catch {
      return this.respond(400, jsonRpcError(null, -32700, "parse error"));
    }
    if (!isPlainObject(message) || message.jsonrpc !== "2.0") {
      return this.respond(400, jsonRpcError(null, -32600, "one JSON-RPC 2.0 message per request; batches are not supported"));
    }
    const id = message.id;
    const method = message.method;
    if (typeof method !== "string") {
      return this.respond(400, jsonRpcError(id, -32600, "client responses are not accepted"));
    }
    const version = request.headers["mcp-protocol-version"];
    if (version !== undefined && !(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(version)) {
      return this.respond(400, jsonRpcError(id, -32600, "unsupported MCP protocol version"));
    }
    const scopes = identity.scopes.filter((scope) => route.scopeCeiling.includes(scope));
    if (scopes.length === 0) {
      return this.challenge(403, "insufficient_scope");
    }
    let session: Session;
    if (method === "initialize") {
      if (sessionHeader !== undefined) {
        return this.respond(400, jsonRpcError(id, -32600, "initialize must not carry a session"));
      }
      const sameRoute = [...this.sessions.values()].filter((s) => s.remoteConnectionId === route.remoteConnectionId);
      if (sameRoute.length >= MAX_SESSIONS_PER_ROUTE || this.sessions.size >= MAX_SESSIONS_TOTAL) {
        return this.respond(429, jsonRpcError(id, -32000, "too many sessions", "REMOTE_RATE_LIMITED"));
      }
      session = {
        id: randomBytes(32).toString("base64url"),
        connectionId: "cn-" + randomBytes(16).toString("hex"),
        principal: identity.principal,
        remoteConnectionId: route.remoteConnectionId,
        deviceId: identity.deviceId,
        epoch: identity.epoch,
        scopes,
        nextSequence: 1,
        inFlight: 0,
        lastUsedMs: now
      };
    } else {
      const existing = sessionHeader === undefined ? undefined : this.sessions.get(sessionHeader);
      if (sessionHeader === undefined) {
        return this.respond(400, jsonRpcError(id, -32600, "Mcp-Session-Id is required"));
      }
      if (
        existing === undefined ||
        existing.principal !== identity.principal ||
        existing.remoteConnectionId !== route.remoteConnectionId ||
        existing.deviceId !== identity.deviceId ||
        existing.epoch !== identity.epoch
      ) {
        return this.respond(404, jsonRpcError(id, -32001, "session not found"));
      }
      if (!existing.scopes.every((scope) => scopes.includes(scope))) {
        return this.challenge(403, "insufficient_scope", existing.scopes.join(" "));
      }
      session = existing;
    }
    if (method === "tools/call") {
      const params = message.params;
      const name = isPlainObject(params) && typeof params.name === "string" ? params.name : "";
      const check = authorizeToolByScopes(name, "core", session.scopes, route.scopeCeiling);
      if (!check.ok) {
        if (check.failure === "REMOTE_SCOPE_DENIED") {
          return this.challenge(403, "insufficient_scope");
        }
        return this.respond(403, jsonRpcError(id, -32602, "tool is not available", check.failure));
      }
    }
    if (session.inFlight >= RELAY_BOUNDS.maxConcurrentRequestsPerConnection) {
      return this.respond(429, jsonRpcError(id, -32000, "too many concurrent requests", "REMOTE_RATE_LIMITED"));
    }
    const refusal = this.hub.refusal(session.deviceId);
    if (refusal !== null) {
      // Refused before a sequence is allocated, so the session stays contiguous.
      return this.respond(FAILURE_STATUS[refusal] ?? 503, jsonRpcError(id, -32000, refusal, refusal));
    }
    const payload = request.body;
    const sequence = session.nextSequence;
    const correlationId = randomBytes(16).toString("base64url");
    const frame: Record<string, unknown> = {
      protocolVersion: RELAY_PROTOCOL_VERSION,
      routeDeviceId: session.deviceId,
      remoteConnectionId: session.remoteConnectionId,
      connectionId: session.connectionId,
      sequence,
      replayNonce: randomBytes(24).toString("base64url"),
      correlationId,
      messageKind: "mcp_request",
      payloadLength: Buffer.byteLength(payload, "utf8"),
      createdAt: now,
      expiresAt: now + FRAME_LIFETIME_MS,
      channelAuth: "",
      authorizationEnvelope: {
        principal: session.principal,
        connection: session.remoteConnectionId,
        device: session.deviceId,
        requestDigest: computeRequestDigest({
          principal: session.principal,
          remoteConnectionId: session.remoteConnectionId,
          connectionId: session.connectionId,
          deviceId: session.deviceId,
          correlationId,
          sequence,
          method,
          payload
        }),
        epoch: session.epoch,
        sessionContext: sessionContextFor(session.scopes)
      },
      payload
    };
    const expectResponse = id !== undefined;
    session.nextSequence += 1;
    session.inFlight += 1;
    session.lastUsedMs = now;
    if (method === "initialize") {
      this.sessions.set(session.id, session);
    }
    let outcome;
    try {
      outcome = await this.hub.dispatch(session.deviceId, session.remoteConnectionId, frame, REQUEST_TIMEOUT_MS, expectResponse);
    } finally {
      session.inFlight -= 1;
      session.lastUsedMs = this.clock();
    }
    if (outcome.kind === "failure") {
      if (method === "initialize" || SESSION_BREAKING_FAILURES.includes(outcome.failure)) {
        // Continuity with the device connection is lost or unknown; the
        // client must re-initialize rather than continue a broken sequence.
        this.sessions.delete(session.id);
      }
      return this.respond(
        FAILURE_STATUS[outcome.failure] ?? 502,
        jsonRpcError(id, -32000, outcome.failure, outcome.failure)
      );
    }
    if (!expectResponse) {
      return { status: 202, headers: { "cache-control": "no-store" }, body: "" };
    }
    let reply: unknown;
    try {
      reply = JSON.parse(outcome.payload);
    } catch {
      reply = null;
    }
    if (!isPlainObject(reply) || reply.jsonrpc !== "2.0" || JSON.stringify(reply.id) !== JSON.stringify(id)) {
      if (method === "initialize") {
        this.sessions.delete(session.id);
      }
      return this.respond(502, jsonRpcError(id, -32603, "malformed device response", "TRANSPORT_UNAVAILABLE"));
    }
    if (method === "initialize" && "error" in reply) {
      this.sessions.delete(session.id);
      return this.respond(200, outcome.payload);
    }
    const headers: Record<string, string> = method === "initialize" ? { "mcp-session-id": session.id } : {};
    return this.respond(200, outcome.payload, headers);
  }
}
