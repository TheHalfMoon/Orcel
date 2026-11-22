/**
 * SG-000054 OAuth 2.1 authorization vocabulary and validation.
 *
 * Pure local logic only. This module performs no I/O, opens no sockets,
 * serves no HTTP, registers no MCP tools, changes no approval behavior,
 * and grants no workspace trust. It implements the OAuth 2.1 authorization
 * code flow with PKCE S256, protected-resource and authorization-server
 * metadata, resource binding, issuer, signature, audience, expiry,
 * not-before, scope, revocation, and refresh family checks authorized by
 * SG-000054 against the frozen SG-000052 relay contract and the SG-000053
 * device identity.
 *
 * OAuth proves remote principal identity and nothing else. A verified
 * access token never grants workspace trust, local approval, STRONG
 * presence, or any filesystem, process, browser, UI, or capability
 * authority. Scopes are an outer remote ceiling that default-deny unknown
 * scopes, tools, and profiles.
 *
 * Cryptography uses the maintained `node:crypto` primitives only: Ed25519
 * signatures over the JWS compact serialization, SHA-256 for PKCE and
 * token hashing, and constant-time comparison. The only accepted JWS
 * algorithm is `EdDSA`; `none`, symmetric, RSA, and embedded or remote key
 * headers are rejected.
 *
 * Failure codes used here are a strict subset of the frozen SG-000052
 * vocabulary. No new failure code is introduced.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
  type JsonWebKey
} from "node:crypto";
import {
  createDeviceChallenge,
  isDeviceId,
  isRouteRevoked,
  verifyChallengeResponse,
  type ChallengeResponse,
  type DeviceChallenge,
  type DeviceIdentity,
  type RevocationRecord
} from "./device_identity.js";
import { RELAY_FAILURE_CODES, type RelayFailureCode } from "./relay_contract.js";
import {
  BROWSER_FULL_CONTRACT,
  LOCAL_ONLY_TOOL_NAMES,
  REMOTE_BROWSER_FULL_TOOLS,
  REMOTE_TOOL_NAMES,
  TOOL_CONTRACT
} from "./tool_contract.js";

/** Initial remote OAuth scope vocabulary. Any other scope is unknown. */
export const OAUTH_SCOPES = ["orcel.read", "orcel.write", "orcel.execute"] as const;
export type OAuthScope = (typeof OAUTH_SCOPES)[number];

/** The only accepted JWS algorithm. */
export const ACCESS_TOKEN_ALGORITHM = "EdDSA";
/** RFC 9068 access token media type. */
export const ACCESS_TOKEN_TYPE = "at+jwt";

/** Short access token lifetime in seconds. */
export const ACCESS_TOKEN_LIFETIME_SECONDS = 300;
/** Hard maximum accepted access token lifetime in seconds. */
export const ACCESS_TOKEN_MAX_LIFETIME_SECONDS = 600;
/** Symmetric clock skew tolerance in seconds for exp, nbf, and iat. */
export const CLOCK_SKEW_SECONDS = 30;
/** Hard maximum accepted compact token length. */
export const ACCESS_TOKEN_MAX_CHARS = 8192;

/** Authorization transaction (CSRF state) lifetime in seconds. */
export const AUTHORIZATION_TRANSACTION_LIFETIME_SECONDS = 600;
/** Short one-shot authorization code lifetime in seconds. */
export const AUTHORIZATION_CODE_LIFETIME_SECONDS = 60;
/** Absolute refresh family lifetime in seconds regardless of rotation. */
export const REFRESH_FAMILY_MAX_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
/** Bounded memory of rotated refresh token hashes for reuse detection. */
export const REFRESH_HISTORY_MAX = 64;
/** Bounded memory of consumed device proof nonces per refresh family. */
export const DEVICE_PROOF_HISTORY_MAX = 64;

/** Opaque identifier shapes. None carries user, host, or hardware data. */
export const REMOTE_PRINCIPAL_PATTERN = /^rp-[0-9a-f]{32}$/;
export const REMOTE_CONNECTION_PATTERN = /^rc-[0-9a-f]{32}$/;
export const REFRESH_FAMILY_PATTERN = /^rf-[0-9a-f]{32}$/;
export const TOKEN_ID_PATTERN = /^at-[0-9a-f]{32}$/;
export const TRANSACTION_ID_PATTERN = /^tx-[0-9a-f]{32}$/;
export const AUTHORIZATION_CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const REFRESH_TOKEN_PATTERN = /^crt\.rf-[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/;
/** RFC 7636 verifier: 43 to 128 unreserved characters. */
export const PKCE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
/** base64url SHA-256 digest without padding. */
export const PKCE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const STATE_MIN_CHARS = 16;
const STATE_MAX_CHARS = 512;
const CLIENT_ID_MAX_CHARS = 512;
const B64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

/** Fixed endpoint paths below the issuer. */
export const OAUTH_ENDPOINT_PATHS = {
  authorization: "/oauth/authorize",
  token: "/oauth/token",
  revocation: "/oauth/revoke",
  registration: "/oauth/register"
} as const;

/**
 * Detailed denial reason for audit. A reason never carries token, code,
 * verifier, key, or payload material.
 */
export type OAuthDenialReason =
  | "token_missing"
  | "token_malformed"
  | "token_oversized"
  | "unsupported_algorithm"
  | "unsupported_header"
  | "unknown_key"
  | "signature_invalid"
  | "claims_invalid"
  | "wrong_issuer"
  | "wrong_audience"
  | "wrong_resource"
  | "token_expired"
  | "token_not_yet_valid"
  | "lifetime_exceeded"
  | "token_revoked"
  | "family_revoked"
  | "family_expired"
  | "family_mismatch"
  | "route_revoked"
  | "stale_epoch"
  | "scope_missing"
  | "scope_unknown"
  | "scope_not_permitted"
  | "scope_widening"
  | "tool_unmapped"
  | "profile_unmapped"
  | "tool_outside_profile"
  | "client_unknown"
  | "client_mismatch"
  | "client_identification_unavailable"
  | "client_identification_failed"
  | "redirect_mismatch"
  | "redirect_invalid"
  | "unsupported_response_type"
  | "unsupported_grant_type"
  | "pkce_method_unsupported"
  | "pkce_challenge_invalid"
  | "pkce_verifier_invalid"
  | "pkce_mismatch"
  | "state_missing"
  | "transaction_expired"
  | "binding_invalid"
  | "code_invalid"
  | "code_expired"
  | "code_replayed"
  | "refresh_invalid"
  | "refresh_replayed"
  | "device_proof_missing"
  | "device_proof_mismatch"
  | "device_proof_replayed"
  | "device_proof_invalid"
  | "metadata_invalid";

export interface OAuthOk {
  readonly ok: true;
}

export interface OAuthDenied {
  readonly ok: false;
  readonly failure: RelayFailureCode;
  readonly reason: OAuthDenialReason;
}

export type OAuthCheck = OAuthOk | OAuthDenied;

function deny(failure: RelayFailureCode, reason: OAuthDenialReason): OAuthDenied {
  return { ok: false, failure, reason };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function equalHex(leftHex: string, rightHex: string): boolean {
  if (leftHex.length !== rightHex.length) {
    return false;
  }
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  if (left.length !== right.length || left.length === 0) {
    return false;
  }
  return timingSafeEqual(left, right);
}

function equalAscii(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/** Strict canonical base64url decoding; non-canonical input is rejected. */
function decodeBase64Url(segment: string): Buffer | null {
  if (!B64URL_PATTERN.test(segment)) {
    return null;
  }
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) {
    return null;
  }
  return bytes;
}

function randomHexId(prefix: string): string {
  return prefix + randomBytes(16).toString("hex");
}

function nowSeconds(nowMs: number): number {
  return Math.floor(nowMs / 1000);
}

function isValidNow(nowMs: number): boolean {
  return Number.isSafeInteger(nowMs) && nowMs >= 0;
}

export function isOAuthScope(value: string): value is OAuthScope {
  return (OAUTH_SCOPES as readonly string[]).includes(value);
}

export function generateRemotePrincipalId(): string {
  return randomHexId("rp-");
}

export function generateRemoteConnectionId(): string {
  return randomHexId("rc-");
}

/**
 * Parse an OAuth space-delimited scope string. Unknown, duplicate, empty,
 * or irregularly separated scopes deny.
 */
export function parseScopeString(
  value: unknown
): { readonly ok: true; readonly scopes: readonly OAuthScope[] } | OAuthDenied {
  if (!isNonEmptyString(value)) {
    return deny("REMOTE_SCOPE_DENIED", "scope_missing");
  }
  const parts = value.split(" ");
  const scopes: OAuthScope[] = [];
  for (const part of parts) {
    if (!isOAuthScope(part)) {
      return deny("REMOTE_SCOPE_DENIED", "scope_unknown");
    }
    if (scopes.includes(part)) {
      return deny("REMOTE_SCOPE_DENIED", "scope_unknown");
    }
    scopes.push(part);
  }
  return { ok: true, scopes };
}

export function formatScopeString(scopes: readonly OAuthScope[]): string {
  return OAUTH_SCOPES.filter((scope) => scopes.includes(scope)).join(" ");
}

// ---------------------------------------------------------------------------
// URL shapes

function parseUrl(value: unknown): URL | null {
  if (!isNonEmptyString(value)) {
    return null;
  }
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

/**
 * https, or plain http only on an exact loopback IP literal (SG-000056) so a
 * self-hosted relay can serve on the same machine. Host names, including
 * `localhost`, never qualify for plain http.
 */
function isHttpsOrLoopbackHttp(url: URL): boolean {
  if (url.protocol === "https:") {
    return true;
  }
  return url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "[::1]");
}

/**
 * Issuer identifier: https (or exact-loopback http), no query, no fragment,
 * no credentials, and no trailing slash so exact comparison is unambiguous.
 */
export function isIssuerIdentifier(value: unknown): value is string {
  const url = parseUrl(value);
  if (url === null || !isHttpsOrLoopbackHttp(url)) {
    return false;
  }
  if (url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") {
    return false;
  }
  if ((value as string).endsWith("/") || (value as string).includes("#") || (value as string).includes("?")) {
    return false;
  }
  return url.href === value || url.href === `${value as string}/`;
}

/** Protected resource identifier: https (or exact-loopback http), no query, no fragment, no credentials. */
export function isResourceIdentifier(value: unknown): value is string {
  const url = parseUrl(value);
  if (url === null || !isHttpsOrLoopbackHttp(url)) {
    return false;
  }
  if (url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") {
    return false;
  }
  if ((value as string).includes("#") || (value as string).includes("?")) {
    return false;
  }
  return url.href === value;
}

/**
 * Redirect URI shape for registration: https, or http on an exact loopback
 * IP literal for native clients. No fragment and no credentials.
 */
export function isAcceptableRedirectUri(value: unknown): value is string {
  const url = parseUrl(value);
  if (url === null) {
    return false;
  }
  if (url.hash !== "" || (value as string).includes("#")) {
    return false;
  }
  if (url.username !== "" || url.password !== "") {
    return false;
  }
  if (url.protocol === "https:") {
    return true;
  }
  // SG-000068: native clients such as Claude Code listen on
  // http://localhost:<port>/callback. `localhost` is accepted for redirect
  // URIs only, never for issuer or resource identifiers.
  return url.protocol === "http:" && isLoopbackHostname(url.hostname);
}

/** Loopback hostnames a native client may use for its redirect listener. */
const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "[::1]", "localhost"]);

function isLoopbackHostname(hostname: string): boolean {
  return LOOPBACK_HOSTNAMES.has(hostname);
}

/**
 * SG-000068 redirect matching. A redirect matches a registered redirect
 * exactly, or, for a registered loopback `http` redirect used by a native
 * client such as Claude Code, it may differ only in the port, as RFC 8252
 * section 7.3 requires because the client binds an ephemeral port per
 * session. Scheme, hostname, path, and query must still match exactly, so
 * no non-loopback host, other scheme, or other path is ever accepted.
 */
export function redirectUriMatches(registered: readonly string[], requested: unknown): requested is string {
  if (!isNonEmptyString(requested) || !isAcceptableRedirectUri(requested)) {
    return false;
  }
  if (registered.includes(requested)) {
    return true;
  }
  const asked = parseUrl(requested);
  if (asked === null || asked.protocol !== "http:" || !isLoopbackHostname(asked.hostname)) {
    return false;
  }
  return registered.some((entry) => {
    const known = parseUrl(entry);
    return (
      known !== null &&
      known.protocol === "http:" &&
      isLoopbackHostname(known.hostname) &&
      known.hostname === asked.hostname &&
      known.pathname === asked.pathname &&
      known.search === asked.search
    );
  });
}

/**
 * Client ID Metadata Document identifier shape: https with a non-root path,
 * no query, no fragment, no credentials, and no dot segments.
 */
export function isClientIdMetadataDocumentUrl(value: unknown): value is string {
  const url = parseUrl(value);
  if (url === null || url.protocol !== "https:") {
    return false;
  }
  if (url.search !== "" || url.hash !== "" || url.username !== "" || url.password !== "") {
    return false;
  }
  if (url.pathname === "/" || url.pathname === "") {
    return false;
  }
  const raw = value as string;
  if (raw.includes("/./") || raw.includes("/../") || raw.endsWith("/.") || raw.endsWith("/..")) {
    return false;
  }
  return url.href === raw;
}

// ---------------------------------------------------------------------------
// Metadata (RFC 8414 and RFC 9728)

export interface AuthorizationServerMetadata {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly revocation_endpoint: string;
  readonly registration_endpoint: string;
  readonly response_types_supported: readonly string[];
  readonly response_modes_supported: readonly string[];
  readonly grant_types_supported: readonly string[];
  readonly code_challenge_methods_supported: readonly string[];
  readonly token_endpoint_auth_methods_supported: readonly string[];
  readonly revocation_endpoint_auth_methods_supported: readonly string[];
  readonly scopes_supported: readonly string[];
  readonly authorization_response_iss_parameter_supported: boolean;
  readonly client_id_metadata_document_supported: boolean;
}

export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorization_servers: readonly string[];
  readonly scopes_supported: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  readonly resource_name: string;
}

const CLIENT_AUTH_METHODS = ["none", "private_key_jwt"] as const;
const FORBIDDEN_GRANT_TYPES = [
  "password",
  "implicit",
  "client_credentials",
  "urn:ietf:params:oauth:grant-type:device_code"
] as const;

export function buildAuthorizationServerMetadata(issuer: string): AuthorizationServerMetadata {
  if (!isIssuerIdentifier(issuer)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid issuer identifier");
  }
  return {
    issuer,
    authorization_endpoint: issuer + OAUTH_ENDPOINT_PATHS.authorization,
    token_endpoint: issuer + OAUTH_ENDPOINT_PATHS.token,
    revocation_endpoint: issuer + OAUTH_ENDPOINT_PATHS.revocation,
    registration_endpoint: issuer + OAUTH_ENDPOINT_PATHS.registration,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: [...CLIENT_AUTH_METHODS],
    revocation_endpoint_auth_methods_supported: [...CLIENT_AUTH_METHODS],
    scopes_supported: [...OAUTH_SCOPES],
    authorization_response_iss_parameter_supported: true,
    // SG-000067: client ID metadata documents are not implemented by the
    // relay's authorization endpoint, so they are not advertised; clients
    // use dynamic client registration.
    client_id_metadata_document_supported: false
  };
}

export function buildProtectedResourceMetadata(
  resource: string,
  issuer: string
): ProtectedResourceMetadata {
  if (!isResourceIdentifier(resource)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid resource identifier");
  }
  if (!isIssuerIdentifier(issuer)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid issuer identifier");
  }
  return {
    resource,
    authorization_servers: [issuer],
    scopes_supported: [...OAUTH_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "Orcel"
  };
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function sameOrigin(endpoint: unknown, issuer: string): boolean {
  const url = parseUrl(endpoint);
  const base = parseUrl(issuer);
  return url !== null && base !== null && isHttpsOrLoopbackHttp(url) && url.origin === base.origin;
}

/**
 * Validate discovered authorization-server metadata. The issuer must match
 * exactly (mix-up defense), PKCE S256 must be supported, the code response
 * type must be present, RFC 9207 issuer identification must be advertised,
 * no forbidden grant may be advertised, and endpoints must share the
 * issuer origin.
 */
export function validateAuthorizationServerMetadata(
  doc: unknown,
  expectedIssuer: string
): OAuthCheck {
  if (!isPlainObject(doc)) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  if (doc.issuer !== expectedIssuer || !isIssuerIdentifier(doc.issuer)) {
    return deny("REMOTE_AUTH_INVALID", "wrong_issuer");
  }
  const methods = doc.code_challenge_methods_supported;
  if (!isStringArray(methods) || !methods.includes("S256") || methods.includes("plain")) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  const responseTypes = doc.response_types_supported;
  if (!isStringArray(responseTypes) || !responseTypes.includes("code")) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  if (responseTypes.some((type) => type !== "code")) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  const grants = doc.grant_types_supported;
  if (!isStringArray(grants) || grants.some((grant) => (FORBIDDEN_GRANT_TYPES as readonly string[]).includes(grant))) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  if (doc.authorization_response_iss_parameter_supported !== true) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  for (const field of ["authorization_endpoint", "token_endpoint", "revocation_endpoint"]) {
    if (!sameOrigin(doc[field], expectedIssuer)) {
      return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
    }
  }
  return { ok: true };
}

/**
 * Validate discovered protected-resource metadata. The resource must match
 * exactly and list exactly the expected authorization server.
 */
export function validateProtectedResourceMetadata(
  doc: unknown,
  expectedResource: string,
  expectedIssuer: string
): OAuthCheck {
  if (!isPlainObject(doc)) {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  if (doc.resource !== expectedResource || !isResourceIdentifier(doc.resource)) {
    return deny("REMOTE_AUTH_INVALID", "wrong_resource");
  }
  const servers = doc.authorization_servers;
  if (!isStringArray(servers) || servers.length !== 1 || servers[0] !== expectedIssuer) {
    return deny("REMOTE_AUTH_INVALID", "wrong_issuer");
  }
  const bearer = doc.bearer_methods_supported;
  if (!isStringArray(bearer) || bearer.length !== 1 || bearer[0] !== "header") {
    return deny("REMOTE_AUTH_INVALID", "metadata_invalid");
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// PKCE (RFC 7636, S256 only)

export function isPkceVerifier(value: unknown): value is string {
  return typeof value === "string" && PKCE_VERIFIER_PATTERN.test(value);
}

export function generatePkceVerifier(): string {
  return randomBytes(32).toString("base64url");
}

export function pkceS256Challenge(verifier: string): string {
  if (!isPkceVerifier(verifier)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid PKCE verifier");
  }
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

/** Verify a PKCE verifier against an S256 challenge. Plain is never accepted. */
export function verifyPkceS256(
  verifier: unknown,
  challenge: string,
  method: string
): OAuthCheck {
  if (method !== "S256") {
    return deny("REMOTE_AUTH_INVALID", "pkce_method_unsupported");
  }
  if (!PKCE_CHALLENGE_PATTERN.test(challenge)) {
    return deny("REMOTE_AUTH_INVALID", "pkce_challenge_invalid");
  }
  if (!isPkceVerifier(verifier)) {
    return deny("REMOTE_AUTH_INVALID", "pkce_verifier_invalid");
  }
  const computed = pkceS256Challenge(verifier);
  if (!equalAscii(computed, challenge)) {
    return deny("REMOTE_AUTH_INVALID", "pkce_mismatch");
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Client registration and provider client-identification hooks

export type ClientIdentificationMethod =
  | "client_id_metadata_document"
  | "dynamic_client_registration"
  | "preregistered"
  | "private_key_jwt";

export interface ClientRegistration {
  readonly clientId: string;
  /** Provider kind label; never authority. */
  readonly providerKind: string;
  readonly redirectUris: readonly string[];
  readonly identification: ClientIdentificationMethod;
  readonly allowedScopes: readonly OAuthScope[];
}

export interface ClientIdentificationEvidence {
  readonly method: ClientIdentificationMethod;
  readonly clientId: string;
  /** Opaque provider evidence such as a client assertion. Never logged. */
  readonly assertion: string | null;
}

/**
 * Provider client-identification hook. Provider-specific verification is
 * plugged in only after current provider requirements are reverified.
 * A hook must return exactly `true` to accept.
 */
export type ClientIdentificationHook = (
  registration: ClientRegistration,
  evidence: ClientIdentificationEvidence
) => boolean;

export type ClientIdentificationHooks = ReadonlyMap<
  ClientIdentificationMethod,
  ClientIdentificationHook
>;

/** Validate a client registration shape before it may be stored. */
export function validateClientRegistration(registration: ClientRegistration): OAuthCheck {
  if (!isNonEmptyString(registration.clientId) || registration.clientId.length > CLIENT_ID_MAX_CHARS) {
    return deny("REMOTE_AUTH_INVALID", "client_unknown");
  }
  if (
    registration.identification === "client_id_metadata_document" &&
    !isClientIdMetadataDocumentUrl(registration.clientId)
  ) {
    return deny("REMOTE_AUTH_INVALID", "client_unknown");
  }
  if (registration.redirectUris.length === 0) {
    return deny("REMOTE_AUTH_INVALID", "redirect_invalid");
  }
  for (const uri of registration.redirectUris) {
    if (!isAcceptableRedirectUri(uri)) {
      return deny("REMOTE_AUTH_INVALID", "redirect_invalid");
    }
  }
  if (registration.allowedScopes.length === 0) {
    return deny("REMOTE_SCOPE_DENIED", "scope_missing");
  }
  for (const scope of registration.allowedScopes) {
    if (!isOAuthScope(scope)) {
      return deny("REMOTE_SCOPE_DENIED", "scope_unknown");
    }
  }
  return { ok: true };
}

/**
 * Run the provider client-identification hook for a registration. A
 * missing hook, a method mismatch, a client mismatch, a throwing hook, or
 * any non-`true` result denies.
 */
export function verifyClientIdentification(
  registration: ClientRegistration,
  evidence: ClientIdentificationEvidence,
  hooks: ClientIdentificationHooks
): OAuthCheck {
  if (evidence.method !== registration.identification) {
    return deny("REMOTE_AUTH_INVALID", "client_identification_failed");
  }
  if (evidence.clientId !== registration.clientId) {
    return deny("REMOTE_AUTH_INVALID", "client_mismatch");
  }
  const hook = hooks.get(registration.identification);
  if (hook === undefined) {
    return deny("REMOTE_AUTH_INVALID", "client_identification_unavailable");
  }
  let accepted: unknown;
  try {
    accepted = hook(registration, evidence);
  } catch {
    return deny("REMOTE_AUTH_INVALID", "client_identification_failed");
  }
  if (accepted !== true) {
    return deny("REMOTE_AUTH_INVALID", "client_identification_failed");
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Authorization request, transaction, code, and response

export interface AuthorizationRequest {
  readonly response_type: unknown;
  readonly client_id: unknown;
  readonly redirect_uri: unknown;
  readonly code_challenge: unknown;
  readonly code_challenge_method: unknown;
  readonly resource: unknown;
  readonly scope: unknown;
  readonly state: unknown;
}

export interface AuthorizationTransaction {
  readonly transactionId: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly resource: string;
  readonly scopes: readonly OAuthScope[];
  readonly state: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}

export interface AuthorizationServerConfig {
  readonly issuer: string;
  readonly resource: string;
}

/**
 * Validate an authorization request. Unknown clients and mismatched
 * redirect URIs deny without any redirect. The resource must equal the one
 * configured protected resource exactly. Unknown or unpermitted scopes
 * deny. CSRF state is required.
 */
export function validateAuthorizationRequest(
  request: AuthorizationRequest,
  config: AuthorizationServerConfig,
  clients: ReadonlyMap<string, ClientRegistration>,
  nowMs: number
): { readonly ok: true; readonly transaction: AuthorizationTransaction } | OAuthDenied {
  if (!isValidNow(nowMs)) {
    return deny("REMOTE_AUTH_INVALID", "binding_invalid");
  }
  if (!isNonEmptyString(request.client_id)) {
    return deny("REMOTE_AUTH_INVALID", "client_unknown");
  }
  const client = clients.get(request.client_id);
  if (client === undefined || !validateClientRegistration(client).ok) {
    return deny("REMOTE_AUTH_INVALID", "client_unknown");
  }
  if (!redirectUriMatches(client.redirectUris, request.redirect_uri)) {
    return deny("REMOTE_AUTH_INVALID", "redirect_mismatch");
  }
  if (request.response_type !== "code") {
    return deny("REMOTE_AUTH_INVALID", "unsupported_response_type");
  }
  if (request.code_challenge_method !== "S256") {
    return deny("REMOTE_AUTH_INVALID", "pkce_method_unsupported");
  }
  if (typeof request.code_challenge !== "string" || !PKCE_CHALLENGE_PATTERN.test(request.code_challenge)) {
    return deny("REMOTE_AUTH_INVALID", "pkce_challenge_invalid");
  }
  if (request.resource !== config.resource || !isResourceIdentifier(request.resource)) {
    return deny("REMOTE_AUTH_INVALID", "wrong_resource");
  }
  const parsed = parseScopeString(request.scope);
  if (!parsed.ok) {
    return parsed;
  }
  if (!parsed.scopes.every((scope) => client.allowedScopes.includes(scope))) {
    return deny("REMOTE_SCOPE_DENIED", "scope_not_permitted");
  }
  if (
    typeof request.state !== "string" ||
    request.state.length < STATE_MIN_CHARS ||
    request.state.length > STATE_MAX_CHARS
  ) {
    return deny("REMOTE_AUTH_INVALID", "state_missing");
  }
  return {
    ok: true,
    transaction: {
      transactionId: randomHexId("tx-"),
      clientId: client.clientId,
      redirectUri: request.redirect_uri,
      codeChallenge: request.code_challenge,
      resource: request.resource,
      scopes: parsed.scopes,
      state: request.state,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + AUTHORIZATION_TRANSACTION_LIFETIME_SECONDS * 1000
    }
  };
}

/** Remote identity bound after successful SG-000053 device pairing and proof. */
export interface RemoteBinding {
  readonly principal: string;
  readonly connection: string;
  readonly deviceId: string;
  readonly epoch: number;
}

export interface AuthorizationCodeRecord {
  readonly codeHashHex: string;
  readonly transactionId: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly resource: string;
  readonly scopes: readonly OAuthScope[];
  readonly binding: RemoteBinding;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly consumed: boolean;
}

export function isRemoteBinding(binding: RemoteBinding): boolean {
  return (
    REMOTE_PRINCIPAL_PATTERN.test(binding.principal) &&
    REMOTE_CONNECTION_PATTERN.test(binding.connection) &&
    isDeviceId(binding.deviceId) &&
    Number.isSafeInteger(binding.epoch) &&
    binding.epoch >= 1
  );
}

/**
 * Issue a short-lived one-shot authorization code for one validated
 * transaction after device pairing bound the remote identity. Only the code
 * hash is stored.
 */
export function issueAuthorizationCode(
  transaction: AuthorizationTransaction,
  binding: RemoteBinding,
  nowMs: number
): { readonly code: string; readonly record: AuthorizationCodeRecord } {
  if (!isValidNow(nowMs) || !isRemoteBinding(binding)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid authorization binding");
  }
  if (nowMs > transaction.expiresAtMs) {
    throw new Error("REMOTE_AUTH_INVALID: authorization transaction expired");
  }
  const code = randomBytes(32).toString("base64url");
  return {
    code,
    record: {
      codeHashHex: sha256Hex(code),
      transactionId: transaction.transactionId,
      clientId: transaction.clientId,
      redirectUri: transaction.redirectUri,
      codeChallenge: transaction.codeChallenge,
      resource: transaction.resource,
      scopes: transaction.scopes,
      binding,
      createdAtMs: nowMs,
      expiresAtMs: nowMs + AUTHORIZATION_CODE_LIFETIME_SECONDS * 1000,
      consumed: false
    }
  };
}

/**
 * Build the authorization response redirect with the RFC 9207 `iss`
 * parameter so clients can detect authorization-server mix-up.
 */
export function buildAuthorizationResponseUrl(
  transaction: AuthorizationTransaction,
  code: string,
  issuer: string
): string {
  const url = new URL(transaction.redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", transaction.state);
  url.searchParams.set("iss", issuer);
  return url.toString();
}

/** Client-side RFC 9207 check: the response issuer and state must match exactly. */
export function verifyAuthorizationResponse(
  params: { readonly iss: unknown; readonly state: unknown; readonly code: unknown },
  expectedIssuer: string,
  expectedState: string
): OAuthCheck {
  if (params.iss !== expectedIssuer) {
    return deny("REMOTE_AUTH_INVALID", "wrong_issuer");
  }
  if (typeof params.state !== "string" || !equalAscii(params.state, expectedState)) {
    return deny("REMOTE_AUTH_INVALID", "state_missing");
  }
  if (typeof params.code !== "string" || !AUTHORIZATION_CODE_PATTERN.test(params.code)) {
    return deny("REMOTE_AUTH_INVALID", "code_invalid");
  }
  return { ok: true };
}

export interface AuthorizationCodeTokenRequest {
  readonly grant_type: unknown;
  readonly code: unknown;
  readonly client_id: unknown;
  readonly redirect_uri: unknown;
  readonly code_verifier: unknown;
  readonly resource: unknown;
}

/**
 * Redeem an authorization code exactly once. The updated record must
 * replace the stored record. A matching code is consumed even when a later
 * binding check fails. Replay of a consumed code reports
 * `revokeIssuedFamily` so tokens issued from it are revoked.
 */
export function redeemAuthorizationCode(
  record: AuthorizationCodeRecord,
  request: AuthorizationCodeTokenRequest,
  nowMs: number
): {
  readonly check: OAuthCheck;
  readonly next: AuthorizationCodeRecord;
  readonly revokeIssuedFamily: boolean;
} {
  const fail = (
    reason: OAuthDenialReason,
    next: AuthorizationCodeRecord,
    failure: RelayFailureCode = "REMOTE_AUTH_INVALID"
  ) => ({ check: deny(failure, reason), next, revokeIssuedFamily: false });
  if (!isValidNow(nowMs)) {
    return fail("binding_invalid", record);
  }
  if (request.grant_type !== "authorization_code") {
    return fail("unsupported_grant_type", record);
  }
  if (typeof request.code !== "string" || !AUTHORIZATION_CODE_PATTERN.test(request.code)) {
    return fail("code_invalid", record);
  }
  if (!equalHex(sha256Hex(request.code), record.codeHashHex)) {
    return fail("code_invalid", record);
  }
  const consumed: AuthorizationCodeRecord = { ...record, consumed: true };
  if (record.consumed) {
    return { check: deny("REMOTE_AUTH_INVALID", "code_replayed"), next: consumed, revokeIssuedFamily: true };
  }
  if (nowMs > record.expiresAtMs) {
    return fail("code_expired", consumed);
  }
  if (request.client_id !== record.clientId) {
    return fail("client_mismatch", consumed);
  }
  if (request.redirect_uri !== record.redirectUri) {
    return fail("redirect_mismatch", consumed);
  }
  if (request.resource !== record.resource) {
    return fail("wrong_resource", consumed);
  }
  const pkce = verifyPkceS256(request.code_verifier, record.codeChallenge, "S256");
  if (!pkce.ok) {
    return fail(pkce.reason, consumed);
  }
  return { check: { ok: true }, next: consumed, revokeIssuedFamily: false };
}

// ---------------------------------------------------------------------------
// Access tokens (JWS compact, EdDSA only)

export interface TokenSigningKey {
  readonly kid: string;
  readonly alg: typeof ACCESS_TOKEN_ALGORITHM;
  readonly publicJwk: JsonWebKey;
  readonly privateJwk: JsonWebKey;
}

export interface TokenVerificationKey {
  readonly kid: string;
  readonly alg: typeof ACCESS_TOKEN_ALGORITHM;
  readonly publicJwk: JsonWebKey;
}

export const SIGNING_KEY_ID_PATTERN = /^k-[0-9a-f]{16}$/;

/** Generate an Ed25519 token signing key. The private JWK stays server-side. */
export function generateTokenSigningKey(): TokenSigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    kid: "k-" + randomBytes(8).toString("hex"),
    alg: ACCESS_TOKEN_ALGORITHM,
    publicJwk: publicKey.export({ format: "jwk" }),
    privateJwk: privateKey.export({ format: "jwk" })
  };
}

/** Public verification projection; carries no private key material. */
export function verificationKeyOf(key: TokenSigningKey): TokenVerificationKey {
  return {
    kid: key.kid,
    alg: key.alg,
    publicJwk: { kty: key.publicJwk.kty, crv: key.publicJwk.crv, x: key.publicJwk.x } as JsonWebKey
  };
}

export interface AccessTokenClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly exp: number;
  readonly nbf: number;
  readonly iat: number;
  readonly jti: string;
  readonly scope: string;
  readonly client_id: string;
  readonly orcel_connection: string;
  readonly orcel_device: string;
  readonly orcel_epoch: number;
  readonly orcel_family: string;
}

const ACCESS_TOKEN_CLAIM_KEYS: readonly (keyof AccessTokenClaims)[] = [
  "iss",
  "sub",
  "aud",
  "exp",
  "nbf",
  "iat",
  "jti",
  "scope",
  "client_id",
  "orcel_connection",
  "orcel_device",
  "orcel_epoch",
  "orcel_family"
];

const ACCESS_TOKEN_HEADER_KEYS = ["alg", "typ", "kid"] as const;

/** Sign an access token. Callers mint claims only through `mintAccessTokenClaims`. */
export function signAccessToken(claims: AccessTokenClaims, key: TokenSigningKey): string {
  const header = { alg: ACCESS_TOKEN_ALGORITHM, typ: ACCESS_TOKEN_TYPE, kid: key.kid };
  const encodedHeader = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const privateKey = createPrivateKey({ key: key.privateJwk, format: "jwk" });
  const signature = cryptoSign(null, Buffer.from(signingInput, "ascii"), privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}

export function mintAccessTokenClaims(
  issuer: string,
  resource: string,
  family: RefreshFamily,
  scopes: readonly OAuthScope[],
  nowMs: number
): AccessTokenClaims {
  if (resource !== family.resource || family.revoked) {
    throw new Error("REMOTE_AUTH_INVALID: access token must bind the family resource");
  }
  if (scopes.length === 0 || !scopes.every((scope) => family.scopes.includes(scope))) {
    throw new Error("REMOTE_SCOPE_DENIED: access token scopes must not widen the family");
  }
  if (!isValidNow(nowMs)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid issue time");
  }
  const iat = nowSeconds(nowMs);
  return {
    iss: issuer,
    sub: family.binding.principal,
    aud: resource,
    exp: iat + ACCESS_TOKEN_LIFETIME_SECONDS,
    nbf: iat,
    iat,
    jti: randomHexId("at-"),
    scope: formatScopeString(scopes),
    client_id: family.clientId,
    orcel_connection: family.binding.connection,
    orcel_device: family.binding.deviceId,
    orcel_epoch: family.binding.epoch,
    orcel_family: family.familyId
  };
}

/** Verified remote principal identity. This is identity only, never local authority. */
export interface RemotePrincipalIdentity {
  readonly authority: "remote_identity_only";
  readonly principal: string;
  readonly connection: string;
  readonly deviceId: string;
  readonly epoch: number;
  readonly clientId: string;
  readonly scopes: readonly OAuthScope[];
  readonly familyId: string;
  readonly tokenId: string;
  readonly expiresAtMs: number;
}

export interface AccessTokenVerificationContext {
  readonly issuer: string;
  readonly resource: string;
  readonly keys: readonly TokenVerificationKey[];
  readonly nowMs: number;
  readonly revokedTokenIds: ReadonlySet<string>;
  readonly revokedFamilyIds: ReadonlySet<string>;
  readonly revocations: readonly RevocationRecord[];
  /** Current route epoch for each device as recorded by the device registry. */
  readonly deviceEpochs: ReadonlyMap<string, number>;
}

function parseJsonObject(bytes: Buffer): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(bytes.toString("utf8"));
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function isEd25519PublicJwk(jwk: JsonWebKey): boolean {
  return jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string" && jwk.d === undefined;
}

/**
 * Verify a bearer access token on every remote request: strict JWS shape,
 * pinned algorithm and key, signature, issuer, audience equal to the exact
 * resource, expiry, not-before, lifetime, scopes, token and family
 * revocation, route revocation, and current device epoch. A verified token
 * yields remote principal identity only.
 */
export function verifyAccessToken(
  token: unknown,
  context: AccessTokenVerificationContext
): { readonly ok: true; readonly identity: RemotePrincipalIdentity } | OAuthDenied {
  if (token === undefined || token === null || token === "") {
    return deny("REMOTE_AUTH_REQUIRED", "token_missing");
  }
  if (typeof token !== "string") {
    return deny("REMOTE_AUTH_INVALID", "token_malformed");
  }
  if (token.length > ACCESS_TOKEN_MAX_CHARS) {
    return deny("REMOTE_AUTH_INVALID", "token_oversized");
  }
  if (!isValidNow(context.nowMs)) {
    return deny("REMOTE_AUTH_INVALID", "claims_invalid");
  }
  const segments = token.split(".");
  if (segments.length !== 3) {
    return deny("REMOTE_AUTH_INVALID", "token_malformed");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];
  const headerBytes = decodeBase64Url(encodedHeader);
  const payloadBytes = decodeBase64Url(encodedPayload);
  const signature = decodeBase64Url(encodedSignature);
  if (headerBytes === null || payloadBytes === null || signature === null) {
    return deny("REMOTE_AUTH_INVALID", "token_malformed");
  }
  const header = parseJsonObject(headerBytes);
  if (header === null) {
    return deny("REMOTE_AUTH_INVALID", "token_malformed");
  }
  if (header.alg !== ACCESS_TOKEN_ALGORITHM) {
    return deny("REMOTE_AUTH_INVALID", "unsupported_algorithm");
  }
  if (!hasExactKeys(header, ACCESS_TOKEN_HEADER_KEYS) || header.typ !== ACCESS_TOKEN_TYPE) {
    return deny("REMOTE_AUTH_INVALID", "unsupported_header");
  }
  const key = context.keys.find((candidate) => candidate.kid === header.kid);
  if (key === undefined || key.alg !== ACCESS_TOKEN_ALGORITHM || !isEd25519PublicJwk(key.publicJwk)) {
    return deny("REMOTE_AUTH_INVALID", "unknown_key");
  }
  let valid = false;
  try {
    const publicKey = createPublicKey({ key: key.publicJwk, format: "jwk" });
    valid = cryptoVerify(
      null,
      Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
      publicKey,
      signature
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    return deny("REMOTE_AUTH_INVALID", "signature_invalid");
  }
  const claims = parseJsonObject(payloadBytes);
  if (claims === null || !hasExactKeys(claims, ACCESS_TOKEN_CLAIM_KEYS)) {
    return deny("REMOTE_AUTH_INVALID", "claims_invalid");
  }
  if (
    !isInteger(claims.exp) ||
    !isInteger(claims.nbf) ||
    !isInteger(claims.iat) ||
    !isInteger(claims.orcel_epoch) ||
    typeof claims.sub !== "string" ||
    !REMOTE_PRINCIPAL_PATTERN.test(claims.sub) ||
    typeof claims.orcel_connection !== "string" ||
    !REMOTE_CONNECTION_PATTERN.test(claims.orcel_connection) ||
    typeof claims.orcel_device !== "string" ||
    !isDeviceId(claims.orcel_device) ||
    typeof claims.orcel_family !== "string" ||
    !REFRESH_FAMILY_PATTERN.test(claims.orcel_family) ||
    typeof claims.jti !== "string" ||
    !TOKEN_ID_PATTERN.test(claims.jti) ||
    !isNonEmptyString(claims.client_id) ||
    claims.client_id.length > CLIENT_ID_MAX_CHARS
  ) {
    return deny("REMOTE_AUTH_INVALID", "claims_invalid");
  }
  if (claims.iss !== context.issuer) {
    return deny("REMOTE_AUTH_INVALID", "wrong_issuer");
  }
  if (claims.aud !== context.resource) {
    return deny("REMOTE_AUTH_INVALID", "wrong_audience");
  }
  const now = nowSeconds(context.nowMs);
  if (claims.exp <= claims.iat || claims.exp - claims.iat > ACCESS_TOKEN_MAX_LIFETIME_SECONDS) {
    return deny("REMOTE_AUTH_INVALID", "lifetime_exceeded");
  }
  if (claims.iat > now + CLOCK_SKEW_SECONDS) {
    return deny("REMOTE_AUTH_INVALID", "token_not_yet_valid");
  }
  if (claims.nbf > now + CLOCK_SKEW_SECONDS) {
    return deny("REMOTE_AUTH_INVALID", "token_not_yet_valid");
  }
  if (now >= claims.exp + CLOCK_SKEW_SECONDS) {
    return deny("REMOTE_AUTH_INVALID", "token_expired");
  }
  const scopes = parseScopeString(claims.scope);
  if (!scopes.ok) {
    return scopes;
  }
  if (context.revokedTokenIds.has(claims.jti)) {
    return deny("REMOTE_AUTH_INVALID", "token_revoked");
  }
  if (context.revokedFamilyIds.has(claims.orcel_family)) {
    return deny("REMOTE_AUTH_INVALID", "family_revoked");
  }
  const routeCheck = isRouteRevoked(
    {
      principal: claims.sub,
      stableConnectionId: claims.orcel_connection,
      deviceId: claims.orcel_device,
      epoch: claims.orcel_epoch
    },
    context.revocations
  );
  if (!routeCheck.ok) {
    return deny(routeCheck.failure, "route_revoked");
  }
  if (context.deviceEpochs.get(claims.orcel_device) !== claims.orcel_epoch) {
    return deny("REMOTE_AUTH_INVALID", "stale_epoch");
  }
  return {
    ok: true,
    identity: {
      authority: "remote_identity_only",
      principal: claims.sub,
      connection: claims.orcel_connection,
      deviceId: claims.orcel_device,
      epoch: claims.orcel_epoch,
      clientId: claims.client_id,
      scopes: scopes.scopes,
      familyId: claims.orcel_family,
      tokenId: claims.jti,
      expiresAtMs: claims.exp * 1000
    }
  };
}

// ---------------------------------------------------------------------------
// Refresh families with rotation, reuse detection, and fresh device proof

export interface RefreshFamily {
  readonly familyId: string;
  readonly binding: RemoteBinding;
  readonly clientId: string;
  readonly resource: string;
  readonly scopes: readonly OAuthScope[];
  readonly createdAtMs: number;
  readonly absoluteExpiresAtMs: number;
  readonly generation: number;
  readonly currentTokenHashHex: string;
  readonly previousTokenHashesHex: readonly string[];
  readonly usedProofNonces: readonly string[];
  readonly revoked: boolean;
}

/** A device challenge issued by the token endpoint for one refresh family. */
export interface RefreshProofChallenge {
  readonly familyId: string;
  readonly challenge: DeviceChallenge;
}

export interface RefreshDeviceProof {
  readonly challenge: RefreshProofChallenge;
  readonly response: ChallengeResponse;
}

function newRefreshToken(familyId: string): { readonly token: string; readonly hashHex: string } {
  const token = `crt.${familyId}.${randomBytes(32).toString("base64url")}`;
  return { token, hashHex: sha256Hex(token) };
}

function boundedPush(list: readonly string[], value: string, max: number): readonly string[] {
  const next = [...list, value];
  return next.length > max ? next.slice(next.length - max) : next;
}

/**
 * Start a refresh family from a redeemed authorization code. Returns the
 * first refresh token (shown once to the client) and the stored family,
 * which carries only token hashes.
 */
export function createRefreshFamily(
  record: AuthorizationCodeRecord,
  nowMs: number
): { readonly refreshToken: string; readonly family: RefreshFamily } {
  if (!record.consumed || !isValidNow(nowMs)) {
    throw new Error("REMOTE_AUTH_INVALID: refresh family requires a redeemed code");
  }
  const familyId = randomHexId("rf-");
  const first = newRefreshToken(familyId);
  return {
    refreshToken: first.token,
    family: {
      familyId,
      binding: record.binding,
      clientId: record.clientId,
      resource: record.resource,
      scopes: record.scopes,
      createdAtMs: nowMs,
      absoluteExpiresAtMs: nowMs + REFRESH_FAMILY_MAX_LIFETIME_SECONDS * 1000,
      generation: 1,
      currentTokenHashHex: first.hashHex,
      previousTokenHashesHex: [],
      usedProofNonces: [],
      revoked: false
    }
  };
}

/**
 * Issue a fresh device challenge for one refresh family. The device must
 * sign it with its SG-000053 key for the bound device and epoch. A device
 * that is offline cannot answer, so its refresh family cannot renew.
 */
export function createRefreshProofChallenge(
  family: RefreshFamily,
  nowMs: number
): RefreshProofChallenge {
  return {
    familyId: family.familyId,
    challenge: createDeviceChallenge(family.binding.deviceId, family.binding.epoch, nowMs)
  };
}

export function revokeRefreshFamily(family: RefreshFamily): RefreshFamily {
  return { ...family, revoked: true };
}

export interface RefreshTokenRequest {
  readonly grant_type: unknown;
  readonly refresh_token: unknown;
  readonly client_id: unknown;
  readonly resource: unknown;
  /** Optional narrowing; never widening. */
  readonly scope: unknown;
}

export interface RefreshContext {
  readonly nowMs: number;
  /** Current recorded public identity of the bound device, or null if unknown. */
  readonly device: DeviceIdentity | null;
  readonly revocations: readonly RevocationRecord[];
}

/**
 * Redeem a refresh token. Every renewal requires a fresh, family-bound,
 * one-shot device-key proof for the exact bound device and current epoch,
 * so a stolen refresh token cannot renew while the bound device is offline
 * or revoked. Rotation is mandatory; replay of a rotated token revokes the
 * family. Scope can only narrow. The updated family must replace the
 * stored family.
 */
export function redeemRefreshToken(
  family: RefreshFamily,
  request: RefreshTokenRequest,
  proof: RefreshDeviceProof | null,
  context: RefreshContext
): {
  readonly check: OAuthCheck;
  readonly next: RefreshFamily;
  readonly refreshToken: string | null;
  readonly scopes: readonly OAuthScope[];
} {
  const fail = (
    reason: OAuthDenialReason,
    next: RefreshFamily = family,
    failure: RelayFailureCode = "REMOTE_AUTH_INVALID"
  ) => ({ check: deny(failure, reason), next, refreshToken: null, scopes: [] as const });
  if (!isValidNow(context.nowMs)) {
    return fail("binding_invalid");
  }
  if (request.grant_type !== "refresh_token") {
    return fail("unsupported_grant_type");
  }
  if (typeof request.refresh_token !== "string" || !REFRESH_TOKEN_PATTERN.test(request.refresh_token)) {
    return fail("refresh_invalid");
  }
  const familyId = request.refresh_token.split(".")[1];
  if (familyId !== family.familyId) {
    return fail("family_mismatch");
  }
  if (family.revoked) {
    return fail("family_revoked");
  }
  if (context.nowMs > family.absoluteExpiresAtMs) {
    return fail("family_expired", revokeRefreshFamily(family));
  }
  const presentedHash = sha256Hex(request.refresh_token);
  if (!equalHex(presentedHash, family.currentTokenHashHex)) {
    if (family.previousTokenHashesHex.some((previous) => equalHex(presentedHash, previous))) {
      return fail("refresh_replayed", revokeRefreshFamily(family));
    }
    return fail("refresh_invalid");
  }
  if (request.client_id !== family.clientId) {
    return fail("client_mismatch");
  }
  if (request.resource !== family.resource) {
    return fail("wrong_resource");
  }
  let scopes: readonly OAuthScope[] = family.scopes;
  if (request.scope !== undefined && request.scope !== null) {
    const parsed = parseScopeString(request.scope);
    if (!parsed.ok) {
      return fail(parsed.reason, family, parsed.failure);
    }
    if (!parsed.scopes.every((scope) => family.scopes.includes(scope))) {
      return fail("scope_widening", family, "REMOTE_SCOPE_DENIED");
    }
    scopes = parsed.scopes;
  }
  const route = isRouteRevoked(
    {
      principal: family.binding.principal,
      stableConnectionId: family.binding.connection,
      deviceId: family.binding.deviceId,
      epoch: family.binding.epoch
    },
    context.revocations
  );
  if (!route.ok) {
    return fail("route_revoked", revokeRefreshFamily(family), route.failure);
  }
  if (context.device === null || context.device.deviceId !== family.binding.deviceId) {
    return fail("device_proof_invalid", family, "ROUTE_MISMATCH");
  }
  if (context.device.epoch !== family.binding.epoch) {
    return fail("stale_epoch", revokeRefreshFamily(family));
  }
  if (proof === null) {
    return fail("device_proof_missing");
  }
  if (
    proof.challenge.familyId !== family.familyId ||
    proof.challenge.challenge.deviceId !== family.binding.deviceId ||
    proof.challenge.challenge.epoch !== family.binding.epoch
  ) {
    return fail("device_proof_mismatch");
  }
  if (family.usedProofNonces.includes(proof.challenge.challenge.nonceBase64)) {
    return fail("device_proof_replayed", family, "RELAY_REPLAY_DETECTED");
  }
  const verified = verifyChallengeResponse(
    context.device,
    proof.challenge.challenge,
    proof.response,
    context.nowMs
  );
  if (!verified.ok) {
    return fail("device_proof_invalid", family, verified.failure);
  }
  const rotated = newRefreshToken(family.familyId);
  return {
    check: { ok: true },
    next: {
      ...family,
      generation: family.generation + 1,
      currentTokenHashHex: rotated.hashHex,
      previousTokenHashesHex: boundedPush(
        family.previousTokenHashesHex,
        family.currentTokenHashHex,
        REFRESH_HISTORY_MAX
      ),
      usedProofNonces: boundedPush(
        family.usedProofNonces,
        proof.challenge.challenge.nonceBase64,
        DEVICE_PROOF_HISTORY_MAX
      )
    },
    refreshToken: rotated.token,
    scopes
  };
}

// ---------------------------------------------------------------------------
// Token revocation (RFC 7009)

export interface TokenRevocationList {
  readonly tokenIds: ReadonlySet<string>;
  readonly familyIds: ReadonlySet<string>;
}

export type PresentedRevocation =
  | { readonly kind: "access_token"; readonly tokenId: string; readonly familyId: string }
  | { readonly kind: "refresh_token"; readonly refreshToken: string };

/**
 * Apply a revocation request. Revoking a refresh token revokes its whole
 * family, which also invalidates access tokens minted from it. Revoking an
 * access token revokes that token. Unrecognized input changes nothing, per
 * RFC 7009, and never reveals whether a token existed.
 */
export function applyTokenRevocation(
  list: TokenRevocationList,
  presented: PresentedRevocation
): TokenRevocationList {
  if (presented.kind === "refresh_token") {
    if (!REFRESH_TOKEN_PATTERN.test(presented.refreshToken)) {
      return list;
    }
    const familyId = presented.refreshToken.split(".")[1] ?? "";
    return { tokenIds: list.tokenIds, familyIds: new Set([...list.familyIds, familyId]) };
  }
  if (!TOKEN_ID_PATTERN.test(presented.tokenId) || !REFRESH_FAMILY_PATTERN.test(presented.familyId)) {
    return list;
  }
  return { tokenIds: new Set([...list.tokenIds, presented.tokenId]), familyIds: list.familyIds };
}

// ---------------------------------------------------------------------------
// Default-deny OAuth scope to tool and profile ceiling

/**
 * Normative scope requirements for every remotely mappable canonical tool,
 * derived from the SG-000065 tool contract. A tool absent from this matrix
 * is unmapped and denies. Preview tools that exist only to prepare a write
 * require the write scope. Process execution requires the execute scope.
 * Local-only tools (`LOCAL_ONLY_TOOL_NAMES`) are never mapped: SG-000063
 * desktop observation reads every application's window titles and control
 * trees, a remote clipboard read would hand a remote principal whatever the
 * user last copied, and a device-side fetch would make the user's machine an
 * egress point for a remote principal that can fetch public URLs itself.
 */
export const OAUTH_SCOPE_TOOL_MATRIX: Readonly<Record<string, readonly OAuthScope[]>> = Object.fromEntries(
  REMOTE_TOOL_NAMES.map((name) => {
    const remote = TOOL_CONTRACT[name]?.remote;
    return [name, Array.isArray(remote) ? [...remote] : []];
  })
);

export { LOCAL_ONLY_TOOL_NAMES };

/**
 * SG-000135 OB-09: the scope requirements of the remote `browser_full`
 * profile's tools, from their `browser_full` contract entries: reads of the
 * session's own page need `orcel.read`, browser actions `orcel.execute`.
 * Four names are shared with local-only `browser_structured` tools, so this
 * is its own matrix, used only for the `browser_full` profile.
 */
export const OAUTH_BROWSER_FULL_SCOPE_MATRIX: Readonly<Record<string, readonly OAuthScope[]>> = Object.fromEntries(
  REMOTE_BROWSER_FULL_TOOLS.map((name) => {
    const remote = BROWSER_FULL_CONTRACT[name]?.remote;
    return [name, Array.isArray(remote) ? [...remote] : []];
  })
);

/** SG-000135 OB-09: each remote profile's scope matrix. */
const OAUTH_PROFILE_SCOPE_MATRICES: Readonly<Record<string, Readonly<Record<string, readonly OAuthScope[]>>>> = {
  core: OAUTH_SCOPE_TOOL_MATRIX,
  browser_full: OAUTH_BROWSER_FULL_SCOPE_MATRIX
};

/**
 * Tool-surface profiles mapped for remote use: `core`, and since SG-000135
 * OB-09 `browser_full` (the remote-safe Orcel Browser tools only, for a
 * connection the owner set up for that profile). The `developer`,
 * `desktop_structured`, `browser_structured` and `coordinate_fallback`
 * profiles are unmapped until a later governed grain maps them, so they deny.
 */
export const OAUTH_PROFILE_TOOL_CEILINGS: Readonly<Record<string, readonly string[]>> = {
  core: Object.keys(OAUTH_SCOPE_TOOL_MATRIX),
  browser_full: Object.keys(OAUTH_BROWSER_FULL_SCOPE_MATRIX)
};

export const UNMAPPED_REMOTE_PROFILES = [
  "developer",
  "desktop_structured",
  "browser_structured",
  "coordinate_fallback"
] as const;

/**
 * Decide whether OAuth scopes permit a tool as an outer remote ceiling.
 * Every required scope must be present in both the current token scopes
 * and the leased OAuth scope ceiling. Unknown profiles, unmapped tools,
 * tools outside the profile, and unknown scopes deny. A positive result is
 * never sufficient: the local remote-session lease, local profile,
 * workspace policy, capability ceiling, and local approval still decide.
 */
export function authorizeToolByScopes(
  tool: string,
  profile: string,
  tokenScopes: readonly string[],
  leasedScopeCeiling: readonly string[]
): OAuthCheck {
  if (!Object.hasOwn(OAUTH_PROFILE_TOOL_CEILINGS, profile) || !Object.hasOwn(OAUTH_PROFILE_SCOPE_MATRICES, profile)) {
    return deny("TOOL_SURFACE_DENIED", "profile_unmapped");
  }
  const matrix = OAUTH_PROFILE_SCOPE_MATRICES[profile] ?? {};
  if (!Object.hasOwn(matrix, tool)) {
    return deny("TOOL_SURFACE_DENIED", "tool_unmapped");
  }
  const profileTools = OAUTH_PROFILE_TOOL_CEILINGS[profile] ?? [];
  if (!profileTools.includes(tool)) {
    return deny("TOOL_SURFACE_DENIED", "tool_outside_profile");
  }
  for (const scope of [...tokenScopes, ...leasedScopeCeiling]) {
    if (!isOAuthScope(scope)) {
      return deny("REMOTE_SCOPE_DENIED", "scope_unknown");
    }
  }
  const required = matrix[tool] ?? [];
  if (required.length === 0) {
    return deny("TOOL_SURFACE_DENIED", "tool_unmapped");
  }
  for (const scope of required) {
    if (!tokenScopes.includes(scope) || !leasedScopeCeiling.includes(scope)) {
      return deny("REMOTE_SCOPE_DENIED", "scope_missing");
    }
  }
  return { ok: true };
}

/**
 * OAuth grants none of these local authorities. This record is asserted by
 * contract tests and must never gain a `true` value.
 */
export const OAUTH_LOCAL_AUTHORITY_GRANTED = {
  workspaceTrust: false,
  localApproval: false,
  strongPresence: false,
  capability: false,
  filesystem: false,
  process: false,
  browser: false,
  ui: false,
  remoteSessionLease: false
} as const;

/**
 * Redacted identity summary for logs and evidence. It carries opaque
 * identifiers and scope names only, never token, code, or key material.
 */
export function redactedIdentitySummary(identity: RemotePrincipalIdentity): {
  readonly principal: string;
  readonly connection: string;
  readonly deviceId: string;
  readonly scopes: string;
} {
  return {
    principal: identity.principal,
    connection: identity.connection,
    deviceId: identity.deviceId,
    scopes: formatScopeString(identity.scopes)
  };
}

/** Assert that every failure code used here belongs to the frozen vocabulary. */
export function oauthFailuresAreFrozenSubset(): boolean {
  const used: RelayFailureCode[] = [
    "REMOTE_AUTH_REQUIRED",
    "REMOTE_AUTH_INVALID",
    "REMOTE_SCOPE_DENIED",
    "DEVICE_REVOKED",
    "ROUTE_MISMATCH",
    "RELAY_REPLAY_DETECTED",
    "TOOL_SURFACE_DENIED"
  ];
  const frozen = new Set<string>(RELAY_FAILURE_CODES as readonly string[]);
  return RELAY_FAILURE_CODES.length === 17 && used.every((code) => frozen.has(code));
}
