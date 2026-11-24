/**
 * SG-000057 authorization server with device-backed pairing.
 *
 * Implements the SG-000054 vocabulary as HTTP endpoints: RFC 8414
 * metadata, RFC 7591 dynamic client registration for public clients,
 * the authorization endpoint with pairing-code entry, the token endpoint
 * (authorization code with PKCE S256, and refresh with a fresh device-key
 * proof obtained over the live device channel), and RFC 7009 revocation.
 *
 * The user authenticates an authorization by pairing a Orcel device: the
 * device registers a one-time pairing offer (hash only), the user types the
 * code on the authorization page, and the device confirms the exact client,
 * redirect origin, and scopes locally before any code is issued. Pairing
 * proves device possession only; it grants no workspace trust, approval,
 * or remote-session lease. There is no password, implicit, or client
 * credentials grant, and no cloud account.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  createDeviceChallenge,
  isDeviceId,
  verifyChallengeResponse,
  type ChallengeResponse,
  type DeviceChallenge,
  type DeviceIdentity
} from "@orcel/mcp/dist/device_identity.js";
import {
  ACCESS_TOKEN_LIFETIME_SECONDS,
  applyTokenRevocation,
  buildAuthorizationResponseUrl,
  buildAuthorizationServerMetadata,
  createRefreshFamily,
  createRefreshProofChallenge,
  generateRemoteConnectionId,
  generateRemotePrincipalId,
  isAcceptableRedirectUri,
  issueAuthorizationCode,
  mintAccessTokenClaims,
  OAUTH_SCOPES,
  parseScopeString,
  redeemAuthorizationCode,
  redeemRefreshToken,
  REFRESH_TOKEN_PATTERN,
  signAccessToken,
  validateAuthorizationRequest,
  validateClientRegistration,
  verifyAccessToken,
  type AuthorizationCodeRecord,
  type AuthorizationTransaction,
  type OAuthScope
} from "@orcel/mcp/dist/oauth_authorization.js";
import type { DeviceChannelHub } from "./device_channel.js";
import type { FileRelayStore, StoredClient } from "./file_store.js";
import type { QuotaDecision, QuotaGuard } from "./quotas.js";

export const PAIRING_OFFER_LIFETIME_MS = 300_000;
export const TRANSACTION_LIFETIME_MS = 600_000;
export const MAX_TRANSACTIONS = 1_000;
export const MAX_OFFERS = 1_000;
export const MAX_CODE_ATTEMPTS = 5;
export const REFRESH_PROOF_WAIT_MS = 10_000;

export interface HttpReply {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

const PAGE_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store"
};

const JSON_HEADERS = { "content-type": "application/json", "cache-control": "no-store", pragma: "no-cache" };

function json(status: number, value: unknown, extra: Record<string, string> = {}): HttpReply {
  return { status, headers: { ...JSON_HEADERS, ...extra }, body: JSON.stringify(value) };
}

function oauthError(status: number, error: string, description: string): HttpReply {
  return json(status, { error, error_description: description });
}

function limited(decision: QuotaDecision): HttpReply | null {
  if (decision.ok) {
    return null;
  }
  return json(
    429,
    { error: "temporarily_unavailable", error_description: "REMOTE_RATE_LIMITED" },
    { "retry-after": String(decision.retryAfterSeconds) }
  );
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function page(status: number, title: string, body: string, refresh?: string): HttpReply {
  const meta = refresh === undefined ? "" : `<meta http-equiv="refresh" content="2;url=${escapeHtml(refresh)}">`;
  return {
    status,
    headers: PAGE_HEADERS,
    body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${meta}<title>${escapeHtml(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}code,input{font-family:ui-monospace,monospace}input{width:100%;padding:.5rem}button{margin-top:1rem;padding:.5rem 1rem}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function equalHex(left: string, right: string): boolean {
  if (left.length !== right.length || left.length === 0) {
    return false;
  }
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isEd25519PublicJwkBase64(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 512) {
    return false;
  }
  try {
    const jwk = JSON.parse(Buffer.from(value, "base64").toString("utf8")) as Record<string, unknown>;
    return jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string" && jwk.d === undefined;
  } catch {
    return false;
  }
}

type TransactionState = "awaiting_code" | "awaiting_device" | "approved" | "denied" | "delivered";

interface Transaction {
  readonly id: string;
  readonly tx: AuthorizationTransaction;
  readonly clientName: string;
  state: TransactionState;
  attempts: number;
  offerId: string | null;
  code: string | null;
}

interface Offer {
  readonly id: string;
  readonly deviceId: string;
  readonly codeHashHex: string;
  readonly expiresAtMs: number;
  state: "open" | "matched" | "done";
  transactionId: string | null;
  principal: string | null;
  connection: string | null;
  confirmChallenge: DeviceChallenge | null;
}

export interface AuthorizationConfig {
  readonly issuer: string;
  readonly resource: string;
}

export class AuthorizationService {
  private readonly transactions = new Map<string, Transaction>();
  private readonly offers = new Map<string, Offer>();
  private readonly pairingChallenges = new Map<string, DeviceChallenge>();
  private readonly codes = new Map<string, { record: AuthorizationCodeRecord; familyId: string | null }>();

  constructor(
    private readonly config: AuthorizationConfig,
    private readonly store: FileRelayStore,
    private readonly hub: DeviceChannelHub,
    private readonly quotas: QuotaGuard,
    private readonly clock: () => number = Date.now
  ) {}

  private prune(now: number): void {
    for (const [id, transaction] of this.transactions) {
      if (now > transaction.tx.expiresAtMs) {
        this.transactions.delete(id);
      }
    }
    for (const [id, offer] of this.offers) {
      if (now > offer.expiresAtMs) {
        this.offers.delete(id);
      }
    }
    for (const [hash, entry] of this.codes) {
      if (now > entry.record.expiresAtMs + 60_000) {
        this.codes.delete(hash);
      }
    }
    for (const [deviceId, challenge] of this.pairingChallenges) {
      if (now > challenge.expiresAtMs) {
        this.pairingChallenges.delete(deviceId);
      }
    }
  }

  metadata(): HttpReply {
    return json(200, buildAuthorizationServerMetadata(this.config.issuer));
  }

  // ---- dynamic client registration (RFC 7591, public clients) ---------------

  register(body: unknown): HttpReply {
    const quota = limited(this.quotas.registration());
    if (quota !== null) {
      return quota;
    }
    if (!isPlainObject(body)) {
      return oauthError(400, "invalid_client_metadata", "registration must be a JSON object");
    }
    const allowed = new Set(["redirect_uris", "client_name", "token_endpoint_auth_method", "grant_types", "response_types", "scope"]);
    if (Object.keys(body).some((key) => !allowed.has(key))) {
      return oauthError(400, "invalid_client_metadata", "unsupported registration field");
    }
    const redirects = body.redirect_uris;
    if (
      !Array.isArray(redirects) ||
      redirects.length === 0 ||
      redirects.length > 5 ||
      !redirects.every((uri) => isAcceptableRedirectUri(uri))
    ) {
      return oauthError(400, "invalid_redirect_uri", "redirect URIs must be https or exact loopback http");
    }
    if (body.token_endpoint_auth_method !== undefined && body.token_endpoint_auth_method !== "none") {
      return oauthError(400, "invalid_client_metadata", "only public clients with PKCE are supported");
    }
    const grants = body.grant_types ?? ["authorization_code", "refresh_token"];
    if (!Array.isArray(grants) || !grants.every((grant) => grant === "authorization_code" || grant === "refresh_token")) {
      return oauthError(400, "invalid_client_metadata", "unsupported grant type");
    }
    const responses = body.response_types ?? ["code"];
    if (!Array.isArray(responses) || !responses.every((type) => type === "code")) {
      return oauthError(400, "invalid_client_metadata", "only the code response type is supported");
    }
    let scopes: readonly OAuthScope[] = OAUTH_SCOPES;
    if (body.scope !== undefined) {
      const parsed = parseScopeString(body.scope);
      if (!parsed.ok) {
        return oauthError(400, "invalid_client_metadata", "unknown scope");
      }
      scopes = parsed.scopes;
    }
    const clientName =
      typeof body.client_name === "string" && body.client_name.length > 0 && body.client_name.length <= 100
        ? body.client_name
        : "MCP client";
    if (this.store.clientCount() >= this.quotas.config.maxClients) {
      return limited({ ok: false, retryAfterSeconds: 3600 }) as HttpReply;
    }
    const client: StoredClient = {
      clientId: "cc-" + randomBytes(16).toString("hex"),
      providerKind: "generic",
      redirectUris: redirects as string[],
      identification: "dynamic_client_registration",
      allowedScopes: [...scopes],
      clientName,
      createdAtMs: this.clock()
    };
    if (!validateClientRegistration(client).ok) {
      return oauthError(400, "invalid_client_metadata", "registration rejected");
    }
    this.store.putClient(client);
    return json(201, {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAtMs / 1000),
      client_name: clientName,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: scopes.join(" ")
    });
  }

  // ---- authorization endpoint ---------------------------------------------

  authorizeGet(query: URLSearchParams): HttpReply {
    const now = this.clock();
    this.prune(now);
    const quota = this.quotas.authorizeAttempt();
    if (!quota.ok) {
      return page(429, "Try again later", "<p>The relay is at its configured limit. Please try again later.</p>");
    }
    const request = {
      response_type: query.get("response_type") ?? undefined,
      client_id: query.get("client_id") ?? undefined,
      redirect_uri: query.get("redirect_uri") ?? undefined,
      code_challenge: query.get("code_challenge") ?? undefined,
      code_challenge_method: query.get("code_challenge_method") ?? undefined,
      resource: query.get("resource") ?? undefined,
      scope: query.get("scope") ?? undefined,
      state: query.get("state") ?? undefined
    };
    const result = validateAuthorizationRequest(request, this.config, this.store.clients(), now);
    if (!result.ok) {
      if (result.reason === "client_unknown" || result.reason === "redirect_mismatch") {
        return page(400, "Authorization request rejected", "<p>The client or redirect address is not registered.</p>");
      }
      const target = new URL(String(request.redirect_uri));
      target.searchParams.set("error", result.failure === "REMOTE_SCOPE_DENIED" ? "invalid_scope" : "invalid_request");
      if (typeof request.state === "string") {
        target.searchParams.set("state", request.state);
      }
      target.searchParams.set("iss", this.config.issuer);
      return { status: 302, headers: { location: target.toString(), "cache-control": "no-store" }, body: "" };
    }
    if (this.transactions.size >= MAX_TRANSACTIONS) {
      return page(429, "Try again later", "<p>Too many authorizations are in progress.</p>");
    }
    const client = this.store.client(result.transaction.clientId);
    const transaction: Transaction = {
      id: randomBytes(32).toString("base64url"),
      tx: result.transaction,
      clientName: client?.clientName ?? "MCP client",
      state: "awaiting_code",
      attempts: 0,
      offerId: null,
      code: null
    };
    this.transactions.set(transaction.id, transaction);
    return this.codeForm(transaction, null);
  }

  private codeForm(transaction: Transaction, error: string | null): HttpReply {
    const redirect = new URL(transaction.tx.redirectUri);
    return page(
      error === null ? 200 : 400,
      "Connect a Orcel device",
      `<p><strong>${escapeHtml(transaction.clientName)}</strong> (returns to <code>${escapeHtml(redirect.origin)}</code>) asks for <code>${escapeHtml(transaction.tx.scopes.join(" "))}</code>.</p>` +
        `<p>On your computer run <code>orcel remote pair</code>, confirm with Windows Hello, and enter the pairing code it shows. You will confirm this client again on the computer. Pairing grants no file, process, or workspace access by itself.</p>` +
        (error === null ? "" : `<p role="alert"><strong>${escapeHtml(error)}</strong></p>`) +
        `<form method="post" action="/oauth/authorize"><input type="hidden" name="transaction" value="${escapeHtml(transaction.id)}"><label for="code">Pairing code</label><input id="code" name="pairing_code" autocomplete="off" spellcheck="false" maxlength="64" required><button type="submit">Continue</button></form>`
    );
  }

  authorizePost(form: URLSearchParams): HttpReply {
    const now = this.clock();
    this.prune(now);
    const quota = this.quotas.authorizeAttempt();
    if (!quota.ok) {
      return page(429, "Try again later", "<p>The relay is at its configured limit.</p>");
    }
    const transaction = this.transactions.get(form.get("transaction") ?? "");
    if (transaction === undefined || transaction.state !== "awaiting_code") {
      return page(400, "Authorization expired", "<p>Start the connection again from your AI client.</p>");
    }
    transaction.attempts += 1;
    if (transaction.attempts > MAX_CODE_ATTEMPTS) {
      this.transactions.delete(transaction.id);
      return page(400, "Too many attempts", "<p>Start the connection again from your AI client.</p>");
    }
    const code = (form.get("pairing_code") ?? "").trim().toLowerCase();
    const hash = /^[0-9a-f]{64}$/.test(code) ? sha256Hex(code) : "";
    let match: Offer | undefined;
    for (const offer of this.offers.values()) {
      if (offer.state === "open" && now <= offer.expiresAtMs && hash !== "" && equalHex(hash, offer.codeHashHex)) {
        match = offer;
      }
    }
    if (match === undefined) {
      return this.codeForm(transaction, "That pairing code is not valid. Check it and try again.");
    }
    match.state = "matched";
    match.transactionId = transaction.id;
    match.principal = generateRemotePrincipalId();
    match.connection = generateRemoteConnectionId();
    transaction.state = "awaiting_device";
    transaction.offerId = match.id;
    return this.waitingPage(transaction);
  }

  private waitingPage(transaction: Transaction): HttpReply {
    return page(
      200,
      "Confirm on your computer",
      "<p>Approve this connection in the <code>orcel remote pair</code> window on your computer. This page continues automatically.</p>",
      `/oauth/authorize/status?transaction=${encodeURIComponent(transaction.id)}`
    );
  }

  authorizeStatus(query: URLSearchParams): HttpReply {
    this.prune(this.clock());
    const transaction = this.transactions.get(query.get("transaction") ?? "");
    if (transaction === undefined) {
      return page(400, "Authorization expired", "<p>Start the connection again from your AI client.</p>");
    }
    switch (transaction.state) {
      case "awaiting_code":
        return this.codeForm(transaction, null);
      case "awaiting_device":
        return this.waitingPage(transaction);
      case "approved": {
        const code = transaction.code ?? "";
        transaction.state = "delivered";
        transaction.code = null;
        return {
          status: 302,
          headers: { location: buildAuthorizationResponseUrl(transaction.tx, code, this.config.issuer), "cache-control": "no-store" },
          body: ""
        };
      }
      case "denied": {
        this.transactions.delete(transaction.id);
        const target = new URL(transaction.tx.redirectUri);
        target.searchParams.set("error", "access_denied");
        target.searchParams.set("state", transaction.tx.state);
        target.searchParams.set("iss", this.config.issuer);
        return { status: 302, headers: { location: target.toString(), "cache-control": "no-store" }, body: "" };
      }
      case "delivered":
        return page(400, "Already completed", "<p>This authorization was already completed.</p>");
    }
  }

  // ---- device enrollment and pairing (device-authenticated) -----------------

  registerDevice(body: unknown): HttpReply {
    const quota = limited(this.quotas.registration());
    if (quota !== null) {
      return quota;
    }
    if (!isPlainObject(body) || !isPlainObject(body.identity)) {
      return json(400, { error: "malformed" });
    }
    const identity = body.identity;
    if (
      typeof identity.deviceId !== "string" ||
      !isDeviceId(identity.deviceId) ||
      !isEd25519PublicJwkBase64(identity.publicKeyJwkBase64) ||
      typeof identity.epoch !== "number" ||
      !Number.isSafeInteger(identity.epoch) ||
      identity.epoch < 1 ||
      typeof identity.createdAtMs !== "number" ||
      !Number.isSafeInteger(identity.createdAtMs) ||
      Object.keys(identity).length !== 4
    ) {
      return json(400, { error: "malformed" });
    }
    if (this.store.device(identity.deviceId) === undefined && this.store.deviceCount() >= this.quotas.config.maxDevices) {
      return json(429, { error: "REMOTE_RATE_LIMITED" }, { "retry-after": "3600" });
    }
    const outcome = this.store.registerDevice(identity as unknown as DeviceIdentity);
    const status = { created: 201, unchanged: 200, conflict: 409, revoked: 403 }[outcome];
    return json(status, { result: outcome });
  }

  pairingChallenge(body: unknown): HttpReply {
    if (!isPlainObject(body) || typeof body.deviceId !== "string") {
      return json(401, { error: "device_denied" });
    }
    const record = this.store.device(body.deviceId);
    if (record === undefined || record.revoked) {
      return json(401, { error: "device_denied" });
    }
    const challenge = createDeviceChallenge(record.identity.deviceId, record.identity.epoch, this.clock());
    this.pairingChallenges.set(record.identity.deviceId, challenge);
    return json(200, { challenge });
  }

  private verifyDevice(response: unknown, challenge: DeviceChallenge | null | undefined): DeviceIdentity | null {
    if (!isPlainObject(response) || challenge === null || challenge === undefined) {
      return null;
    }
    const record = this.store.device(challenge.deviceId);
    if (record === undefined || record.revoked) {
      return null;
    }
    const check = verifyChallengeResponse(record.identity, challenge, response as unknown as ChallengeResponse, this.clock());
    return check.ok ? record.identity : null;
  }

  pairingOffer(body: unknown): HttpReply {
    const now = this.clock();
    this.prune(now);
    if (!isPlainObject(body) || !isPlainObject(body.response) || typeof body.response.deviceId !== "string") {
      return json(401, { error: "device_denied" });
    }
    const challenge = this.pairingChallenges.get(body.response.deviceId);
    this.pairingChallenges.delete(body.response.deviceId);
    const identity = this.verifyDevice(body.response, challenge);
    if (identity === null) {
      return json(401, { error: "device_denied" });
    }
    // SG-000135 OB-09 (tunnel only: an engineering choice,
    // 2026-11-22): the relay serves the core profile only, so an offer that
    // names any tool-surface profile is refused.
    if ("toolSurfaceProfile" in body) {
      return json(400, { error: "profile_unsupported" });
    }
    if (
      typeof body.codeHashHex !== "string" ||
      !/^[0-9a-f]{64}$/.test(body.codeHashHex) ||
      typeof body.expiresAtMs !== "number" ||
      body.expiresAtMs <= now ||
      body.expiresAtMs > now + PAIRING_OFFER_LIFETIME_MS
    ) {
      return json(400, { error: "malformed" });
    }
    for (const [id, offer] of this.offers) {
      if (offer.deviceId === identity.deviceId && offer.state !== "done") {
        this.offers.delete(id);
      }
    }
    if (this.offers.size >= MAX_OFFERS) {
      return json(429, { error: "REMOTE_RATE_LIMITED" }, { "retry-after": "60" });
    }
    const offer: Offer = {
      id: randomBytes(32).toString("base64url"),
      deviceId: identity.deviceId,
      codeHashHex: body.codeHashHex,
      expiresAtMs: body.expiresAtMs,
      state: "open",
      transactionId: null,
      principal: null,
      connection: null,
      confirmChallenge: null
    };
    this.offers.set(offer.id, offer);
    return json(201, { offerId: offer.id, expiresAtMs: offer.expiresAtMs });
  }

  pairingStatus(body: unknown): HttpReply {
    const now = this.clock();
    this.prune(now);
    const offer = isPlainObject(body) && typeof body.offerId === "string" ? this.offers.get(body.offerId) : undefined;
    if (offer === undefined) {
      return json(404, { state: "expired" });
    }
    if (offer.state === "open") {
      return json(200, { state: "waiting", expiresAtMs: offer.expiresAtMs });
    }
    if (offer.state === "done") {
      return json(200, { state: "done" });
    }
    const transaction = this.transactions.get(offer.transactionId ?? "");
    const record = this.store.device(offer.deviceId);
    if (transaction === undefined || record === undefined || record.revoked) {
      this.offers.delete(offer.id);
      return json(404, { state: "expired" });
    }
    offer.confirmChallenge = createDeviceChallenge(record.identity.deviceId, record.identity.epoch, now);
    return json(200, {
      state: "confirm",
      request: {
        clientId: transaction.tx.clientId,
        clientName: transaction.clientName,
        redirectOrigin: new URL(transaction.tx.redirectUri).origin,
        scopes: transaction.tx.scopes,
        principal: offer.principal,
        remoteConnectionId: offer.connection
      },
      challenge: offer.confirmChallenge
    });
  }

  pairingConfirm(body: unknown): HttpReply {
    const now = this.clock();
    this.prune(now);
    const offer = isPlainObject(body) && typeof body.offerId === "string" ? this.offers.get(body.offerId) : undefined;
    if (offer === undefined || offer.state !== "matched" || !isPlainObject(body)) {
      return json(404, { error: "expired" });
    }
    const challenge = offer.confirmChallenge;
    offer.confirmChallenge = null;
    const identity = this.verifyDevice(body.response, challenge);
    if (identity === null || identity.deviceId !== offer.deviceId) {
      return json(401, { error: "device_denied" });
    }
    const transaction = this.transactions.get(offer.transactionId ?? "");
    offer.state = "done";
    if (transaction === undefined || transaction.state !== "awaiting_device") {
      return json(404, { error: "expired" });
    }
    if (body.decision !== "approve") {
      transaction.state = "denied";
      return json(200, { result: "denied" });
    }
    const client = this.store.client(transaction.tx.clientId);
    if (client === undefined || offer.principal === null || offer.connection === null) {
      transaction.state = "denied";
      return json(404, { error: "expired" });
    }
    this.store.putConnection({
      principal: offer.principal,
      remoteConnectionId: offer.connection,
      deviceId: identity.deviceId,
      clientId: client.clientId,
      providerKind: client.providerKind,
      scopeCeiling: transaction.tx.scopes
    });
    const issued = issueAuthorizationCode(
      transaction.tx,
      { principal: offer.principal, connection: offer.connection, deviceId: identity.deviceId, epoch: identity.epoch },
      now
    );
    this.codes.set(issued.record.codeHashHex, { record: issued.record, familyId: null });
    transaction.code = issued.code;
    transaction.state = "approved";
    return json(200, {
      result: "approved",
      connection: {
        principal: offer.principal,
        remoteConnectionId: offer.connection,
        providerKind: client.providerKind,
        scopeCeiling: transaction.tx.scopes
      }
    });
  }

  // ---- token endpoint ------------------------------------------------------

  async token(form: URLSearchParams): Promise<HttpReply> {
    const now = this.clock();
    this.prune(now);
    const quota = limited(this.quotas.tokenRequest());
    if (quota !== null) {
      return quota;
    }
    const clientId = form.get("client_id") ?? "";
    const client = this.store.client(clientId);
    if (client === undefined) {
      return oauthError(401, "invalid_client", "unknown client");
    }
    const grant = form.get("grant_type");
    if (grant === "authorization_code") {
      const code = form.get("code") ?? "";
      const entry = this.codes.get(sha256Hex(code));
      if (entry === undefined) {
        return oauthError(400, "invalid_grant", "code_invalid");
      }
      const redeemed = redeemAuthorizationCode(
        entry.record,
        {
          grant_type: grant,
          code,
          client_id: clientId,
          redirect_uri: form.get("redirect_uri") ?? undefined,
          code_verifier: form.get("code_verifier") ?? undefined,
          resource: form.get("resource") ?? undefined
        },
        now
      );
      entry.record = redeemed.next;
      if (redeemed.revokeIssuedFamily && entry.familyId !== null) {
        this.store.revokeFamilyId(entry.familyId);
      }
      if (!redeemed.check.ok) {
        return oauthError(400, "invalid_grant", redeemed.check.reason);
      }
      const created = createRefreshFamily(redeemed.next, now);
      entry.familyId = created.family.familyId;
      this.store.saveFamily(created.family);
      return this.tokenResponse(created.family.familyId, created.refreshToken, created.family.scopes);
    }
    if (grant === "refresh_token") {
      const presented = form.get("refresh_token") ?? "";
      if (!REFRESH_TOKEN_PATTERN.test(presented)) {
        return oauthError(400, "invalid_grant", "refresh_invalid");
      }
      const familyId = presented.split(".")[1] ?? "";
      if (this.store.revokedFamilyIds().has(familyId)) {
        return oauthError(400, "invalid_grant", "family_revoked");
      }
      const family = this.store.family(familyId);
      if (family === undefined) {
        return oauthError(400, "invalid_grant", "refresh_invalid");
      }
      const device = this.store.device(family.binding.deviceId);
      const proofChallenge = createRefreshProofChallenge(family, now);
      const response = await this.hub.requestProof(proofChallenge.challenge, REFRESH_PROOF_WAIT_MS);
      const result = redeemRefreshToken(
        family,
        {
          grant_type: grant,
          refresh_token: presented,
          client_id: clientId,
          resource: form.get("resource") ?? undefined,
          scope: form.get("scope") ?? undefined
        },
        response === null ? null : { challenge: proofChallenge, response },
        {
          nowMs: this.clock(),
          device: device === undefined || device.revoked ? null : device.identity,
          revocations: this.store.revocations()
        }
      );
      this.store.saveFamily(result.next);
      if (!result.check.ok || result.refreshToken === null) {
        return oauthError(400, "invalid_grant", result.check.ok ? "refresh_invalid" : result.check.reason);
      }
      return this.tokenResponse(result.next.familyId, result.refreshToken, result.scopes);
    }
    return oauthError(400, "unsupported_grant_type", "only authorization_code and refresh_token are supported");
  }

  private tokenResponse(familyId: string, refreshToken: string, scopes: readonly OAuthScope[]): HttpReply {
    const family = this.store.family(familyId);
    if (family === undefined) {
      return oauthError(400, "invalid_grant", "family_revoked");
    }
    const claims = mintAccessTokenClaims(this.config.issuer, this.config.resource, family, scopes, this.clock());
    return json(200, {
      access_token: signAccessToken(claims, this.store.signingKey()),
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
      refresh_token: refreshToken,
      scope: scopes.join(" ")
    });
  }

  // ---- revocation (RFC 7009) ------------------------------------------------

  revoke(form: URLSearchParams): HttpReply {
    const token = form.get("token") ?? "";
    const clientId = form.get("client_id") ?? "";
    if (REFRESH_TOKEN_PATTERN.test(token)) {
      const family = this.store.family(token.split(".")[1] ?? "");
      if (family !== undefined && family.clientId === clientId) {
        const list = applyTokenRevocation({ tokenIds: new Set(), familyIds: new Set() }, { kind: "refresh_token", refreshToken: token });
        for (const familyId of list.familyIds) {
          this.store.revokeFamilyId(familyId);
        }
      }
      return json(200, {});
    }
    const verified = verifyAccessToken(token, {
      issuer: this.config.issuer,
      resource: this.config.resource,
      keys: this.store.verificationKeys(),
      nowMs: this.clock(),
      revokedTokenIds: new Set(),
      revokedFamilyIds: new Set(),
      revocations: [],
      deviceEpochs: this.store.deviceEpochs()
    });
    if (verified.ok && verified.identity.clientId === clientId) {
      this.store.revokeTokenId(verified.identity.tokenId, verified.identity.expiresAtMs);
    }
    return json(200, {});
  }
}
