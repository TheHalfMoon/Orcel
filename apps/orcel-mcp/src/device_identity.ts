/**
 * SG-000053 device identity, pairing, and revocation vocabulary.
 *
 * Pure local logic only. This module performs no I/O, opens no sockets,
 * serves no HTTP, registers no MCP tools, changes no approval behavior,
 * and grants no workspace trust. It implements the device identity,
 * one-time pairing, key rotation, connection epochs, revocation, and
 * device-verifiable authorization envelope checks authorized by SG-000053
 * against the frozen SG-000052 relay contract in
 * `docs/security/RELAY_PROTOCOL_CONTRACT.md`.
 *
 * The private device key never leaves the device. Only the public device
 * identity leaves the machine. Pairing alone grants no workspace trust
 * and no action approval. Revocation invalidates active and refreshable
 * sessions, not only UI state.
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
  verify as cryptoVerify
} from "node:crypto";
import {
  RELAY_BOUNDS,
  RELAY_FAILURE_CODES,
  type RelayFailureCode
} from "./relay_contract.js";

export const DEVICE_ID_PREFIX = "dev-";
export const DEVICE_ID_HEX_CHARS = 32;
export const DEVICE_ID_PATTERN = /^dev-[0-9a-f]{32}$/;

/**
 * Relative location of the device key record under the Orcel state root.
 * Since XP-19 the record holds only the public identity
 * ({@link DeviceIdentity}); the private key lives in the OS secret store
 * behind `orceld` (`secret_store.ts`, name `device.key`).
 */
export const DEVICE_KEY_STORE_RELATIVE = "device/device_key.json";

/** Pairing code carries 256-bit entropy, encoded as 64 lowercase hex chars. */
export const PAIRING_CODE_ENTROPY_BYTES = 32;
export const PAIRING_CODE_HEX_CHARS = 64;
export const PAIRING_CODE_PATTERN = /^[0-9a-f]{64}$/;

/** Short pairing validity in seconds. */
export const PAIRING_CODE_EXPIRY_SECONDS = 300;

/** Maximum pairing verification attempts per code before invalidation. */
export const PAIRING_CODE_MAX_ATTEMPTS = 5;

/** Challenge nonce carries 256-bit entropy. */
export const CHALLENGE_NONCE_BYTES = 32;

/** Challenge validity in seconds, matching the frozen frame lifetime. */
export const CHALLENGE_EXPIRY_SECONDS = 120;

/** First valid route and connection epoch. */
export const INITIAL_EPOCH = 1;

/** SHA-256 hex digest length. */
export const REQUEST_DIGEST_HEX_CHARS = 64;
export const REQUEST_DIGEST_PATTERN = /^[0-9a-f]{64}$/;

export type RevocationKind =
  | "hard_device"
  | "principal_wide"
  | "all_route"
  | "emergency";

export interface DeviceKeyPair {
  readonly deviceId: string;
  readonly publicKeyJwkBase64: string;
  readonly privateKeyJwkBase64: string;
  readonly createdAtMs: number;
  readonly epoch: number;
}

export interface DeviceIdentity {
  readonly deviceId: string;
  readonly publicKeyJwkBase64: string;
  readonly createdAtMs: number;
  readonly epoch: number;
}

export interface DeviceChallenge {
  readonly deviceId: string;
  readonly epoch: number;
  readonly nonceBase64: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}

export interface ChallengeResponse {
  readonly deviceId: string;
  readonly epoch: number;
  readonly nonceBase64: string;
  readonly signatureBase64: string;
}

export interface PairingIssue {
  /** Plain pairing code shown once to the local user. Never persisted. */
  readonly code: string;
  readonly record: PairingRecord;
}

export interface PairingRecord {
  readonly codeId: string;
  readonly codeHashHex: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly attempts: number;
  readonly consumed: boolean;
  readonly invalidated: boolean;
}

export interface RevocationRecord {
  readonly kind: RevocationKind;
  readonly createdAtMs: number;
  readonly epoch: number;
  readonly deviceId: string | null;
  readonly principal: string | null;
  readonly reason: string;
}

export interface RouteBinding {
  readonly principal: string;
  readonly stableConnectionId: string;
  readonly deviceId: string;
  readonly epoch: number;
}

export interface AuthorizationEnvelopeCandidate {
  readonly principal: unknown;
  readonly connection: unknown;
  readonly device: unknown;
  readonly requestDigest: unknown;
  readonly epoch: unknown;
  readonly sessionContext: unknown;
}

export interface EnvelopeExpectation {
  readonly principal: string;
  readonly connection: string;
  readonly deviceId: string;
  readonly requestDigestHex: string;
  readonly epoch: number;
  readonly sessionContext: string;
}

export interface CheckOk {
  readonly ok: true;
}

export interface CheckFail {
  readonly ok: false;
  readonly failure: RelayFailureCode;
}

export type EnvelopeCheck = CheckOk | CheckFail;
export type ChallengeCheck = CheckOk | CheckFail;
export type PairingCheck = CheckOk | CheckFail;
export type RevocationCheck = CheckOk | CheckFail;

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

export function isDeviceId(value: string): boolean {
  return DEVICE_ID_PATTERN.test(value);
}

export function isPairingCode(value: string): boolean {
  return PAIRING_CODE_PATTERN.test(value);
}

export function isRequestDigestHex(value: string): boolean {
  return REQUEST_DIGEST_PATTERN.test(value);
}

function encodeJwkBase64(jwk: object): string {
  return Buffer.from(JSON.stringify(jwk), "utf8").toString("base64");
}

function decodeJwkBase64(encoded: string): Record<string, unknown> {
  const raw = Buffer.from(encoded, "base64").toString("utf8");
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("PAIRING_DENIED: malformed device key encoding");
  }
  return parsed as Record<string, unknown>;
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function equalHexHex(leftHex: string, rightHex: string): boolean {
  if (leftHex.length !== rightHex.length) {
    return false;
  }
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

function challengeBytes(challenge: DeviceChallenge): Buffer {
  const canonical = [
    challenge.deviceId,
    String(challenge.epoch),
    challenge.nonceBase64,
    String(challenge.expiresAtMs)
  ].join("|");
  return Buffer.from(canonical, "utf8");
}

/**
 * Create a fresh protected device key pair for one device route.
 * The caller holds the private key under the protected state boundary
 * and never transmits, logs, or returns it through any tool.
 */
export function generateDeviceKeyPair(
  deviceId: string,
  createdAtMs: number,
  epoch: number = INITIAL_EPOCH
): DeviceKeyPair {
  if (!isDeviceId(deviceId)) {
    throw new Error("PAIRING_DENIED: invalid device identity format");
  }
  if (!Number.isInteger(createdAtMs) || createdAtMs < 0) {
    throw new Error("PAIRING_DENIED: invalid device key creation time");
  }
  if (!Number.isInteger(epoch) || epoch < INITIAL_EPOCH) {
    throw new Error("PAIRING_DENIED: invalid device epoch");
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const privateJwk = privateKey.export({ format: "jwk" });
  return {
    deviceId,
    publicKeyJwkBase64: encodeJwkBase64(publicJwk),
    privateKeyJwkBase64: encodeJwkBase64(privateJwk),
    createdAtMs,
    epoch
  };
}

/** Create a random tenant-scoped opaque device route identifier. */
export function generateDeviceId(): string {
  return DEVICE_ID_PREFIX + randomBytes(16).toString("hex");
}

/**
 * Project the public device identity. The result carries no private key
 * material and is the only key shape that may leave the device.
 */
export function publicDeviceIdentity(pair: DeviceKeyPair): DeviceIdentity {
  return {
    deviceId: pair.deviceId,
    publicKeyJwkBase64: pair.publicKeyJwkBase64,
    createdAtMs: pair.createdAtMs,
    epoch: pair.epoch
  };
}

/**
 * Rotate the device key. The new key uses the next epoch. The prior key
 * must be discarded by the holder. Signatures from the prior epoch fail
 * verification against the new epoch.
 */
export function rotateDeviceKeyPair(
  current: DeviceKeyPair,
  rotatedAtMs: number
): DeviceKeyPair {
  if (!Number.isInteger(rotatedAtMs) || rotatedAtMs < 0) {
    throw new Error("PAIRING_DENIED: invalid key rotation time");
  }
  return generateDeviceKeyPair(current.deviceId, rotatedAtMs, current.epoch + 1);
}

/**
 * True when the private JWK is the Ed25519 key whose public half the
 * identity records. A key from another device, a damaged key or a key of
 * another type is refused before it signs anything.
 */
export function privateKeyMatchesIdentity(
  privateKeyJwkBase64: string,
  publicKeyJwkBase64: string
): boolean {
  try {
    const privateJwk = decodeJwkBase64(privateKeyJwkBase64);
    const publicJwk = decodeJwkBase64(publicKeyJwkBase64);
    if (
      privateJwk.kty !== "OKP" ||
      privateJwk.crv !== "Ed25519" ||
      typeof privateJwk.d !== "string" ||
      publicJwk.kty !== "OKP" ||
      publicJwk.crv !== "Ed25519" ||
      typeof publicJwk.x !== "string"
    ) {
      return false;
    }
    const derived = createPublicKey(createPrivateKey({ key: privateJwk as never, format: "jwk" })).export({
      format: "jwk"
    });
    return derived.x === publicJwk.x;
  } catch {
    return false;
  }
}

/** Create a short-lived challenge for one device and epoch. */
export function createDeviceChallenge(
  deviceId: string,
  epoch: number,
  nowMs: number
): DeviceChallenge {
  if (!isDeviceId(deviceId)) {
    throw new Error("REMOTE_AUTH_INVALID: invalid device identity format");
  }
  if (!Number.isInteger(epoch) || epoch < INITIAL_EPOCH) {
    throw new Error("REMOTE_AUTH_INVALID: invalid device epoch");
  }
  if (!Number.isInteger(nowMs) || nowMs < 0) {
    throw new Error("REMOTE_AUTH_INVALID: invalid challenge time");
  }
  return {
    deviceId,
    epoch,
    nonceBase64: randomBytes(CHALLENGE_NONCE_BYTES).toString("base64"),
    createdAtMs: nowMs,
    expiresAtMs: nowMs + CHALLENGE_EXPIRY_SECONDS * 1000
  };
}

/** Sign a challenge with the local private key. The private key is input only. */
export function signDeviceChallenge(
  privateKeyJwkBase64: string,
  challenge: DeviceChallenge
): ChallengeResponse {
  const jwk = decodeJwkBase64(privateKeyJwkBase64);
  const privateKey = createPrivateKey({ key: jwk as never, format: "jwk" });
  const signature = cryptoSign(null, challengeBytes(challenge), privateKey);
  return {
    deviceId: challenge.deviceId,
    epoch: challenge.epoch,
    nonceBase64: challenge.nonceBase64,
    signatureBase64: signature.toString("base64")
  };
}

/**
 * Verify a challenge response against the recorded public identity.
 * Any mismatch fails closed without distinguishing secrets from identity.
 */
export function verifyChallengeResponse(
  identity: DeviceIdentity,
  challenge: DeviceChallenge,
  response: ChallengeResponse,
  nowMs: number
): ChallengeCheck {
  if (!Number.isInteger(nowMs) || nowMs < 0) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  if (
    response.deviceId !== identity.deviceId ||
    response.deviceId !== challenge.deviceId
  ) {
    return { ok: false, failure: "ROUTE_MISMATCH" };
  }
  if (
    response.epoch !== identity.epoch ||
    response.epoch !== challenge.epoch
  ) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  if (response.nonceBase64 !== challenge.nonceBase64) {
    return { ok: false, failure: "RELAY_REPLAY_DETECTED" };
  }
  if (nowMs > challenge.expiresAtMs) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  try {
    const jwk = decodeJwkBase64(identity.publicKeyJwkBase64);
    const publicKey = createPublicKey({ key: jwk as never, format: "jwk" });
    const valid = cryptoVerify(
      null,
      challengeBytes(challenge),
      publicKey,
      Buffer.from(response.signatureBase64, "base64")
    );
    if (!valid) {
      return { ok: false, failure: "REMOTE_AUTH_INVALID" };
    }
  } catch {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  return { ok: true };
}

/** Issue one high-entropy short-lived one-time pairing code. */
export function issuePairingCode(nowMs: number, codeId: string): PairingIssue {
  if (!isNonEmptyString(codeId)) {
    throw new Error("PAIRING_DENIED: invalid pairing code identity");
  }
  if (!Number.isInteger(nowMs) || nowMs < 0) {
    throw new Error("PAIRING_DENIED: invalid pairing issue time");
  }
  const code = randomBytes(PAIRING_CODE_ENTROPY_BYTES).toString("hex");
  return {
    code,
    record: {
      codeId,
      codeHashHex: sha256Hex(code),
      createdAtMs: nowMs,
      expiresAtMs: nowMs + PAIRING_CODE_EXPIRY_SECONDS * 1000,
      attempts: 0,
      consumed: false,
      invalidated: false
    }
  };
}

/**
 * Verify one pairing attempt. The updated record must replace the stored
 * record. Success consumes the code. Five failures invalidate it. Expiry,
 * consumption, and invalidation fail closed. A successful pairing returns
 * only acceptance; it grants no workspace trust, no profile, and no
 * approval.
 */
export function verifyPairingAttempt(
  record: PairingRecord,
  candidateCode: string,
  nowMs: number
): { readonly check: PairingCheck; readonly next: PairingRecord } {
  if (!Number.isInteger(nowMs) || nowMs < 0) {
    return {
      check: { ok: false, failure: "PAIRING_DENIED" },
      next: { ...record, invalidated: true }
    };
  }
  if (record.consumed || record.invalidated) {
    return {
      check: { ok: false, failure: "PAIRING_DENIED" },
      next: record
    };
  }
  if (nowMs > record.expiresAtMs) {
    return {
      check: { ok: false, failure: "PAIRING_EXPIRED" },
      next: { ...record, invalidated: true }
    };
  }
  if (record.attempts >= PAIRING_CODE_MAX_ATTEMPTS) {
    return {
      check: { ok: false, failure: "PAIRING_DENIED" },
      next: { ...record, invalidated: true }
    };
  }
  if (!PAIRING_CODE_PATTERN.test(candidateCode)) {
    const attempts = record.attempts + 1;
    const invalidated = attempts >= PAIRING_CODE_MAX_ATTEMPTS;
    return {
      check: { ok: false, failure: "PAIRING_DENIED" },
      next: { ...record, attempts, invalidated }
    };
  }
  const candidateHash = sha256Hex(candidateCode);
  if (!equalHexHex(candidateHash, record.codeHashHex)) {
    const attempts = record.attempts + 1;
    const invalidated = attempts >= PAIRING_CODE_MAX_ATTEMPTS;
    return {
      check: { ok: false, failure: "PAIRING_DENIED" },
      next: { ...record, attempts, invalidated }
    };
  }
  return {
    check: { ok: true },
    next: { ...record, attempts: record.attempts + 1, consumed: true }
  };
}

export function revokeDevice(
  deviceId: string,
  epoch: number,
  createdAtMs: number,
  reason: string
): RevocationRecord {
  if (!isDeviceId(deviceId)) {
    throw new Error("DEVICE_REVOKED: invalid device identity format");
  }
  return {
    kind: "hard_device",
    createdAtMs,
    epoch,
    deviceId,
    principal: null,
    reason
  };
}

export function revokePrincipal(
  principal: string,
  epoch: number,
  createdAtMs: number,
  reason: string
): RevocationRecord {
  if (!isNonEmptyString(principal)) {
    throw new Error("DEVICE_REVOKED: invalid remote principal");
  }
  return {
    kind: "principal_wide",
    createdAtMs,
    epoch,
    deviceId: null,
    principal,
    reason
  };
}

export function revokeAllRoutes(
  epoch: number,
  createdAtMs: number,
  reason: string
): RevocationRecord {
  return {
    kind: "all_route",
    createdAtMs,
    epoch,
    deviceId: null,
    principal: null,
    reason
  };
}

export function emergencyRevoke(
  epoch: number,
  createdAtMs: number,
  reason: string
): RevocationRecord {
  return {
    kind: "emergency",
    createdAtMs,
    epoch,
    deviceId: null,
    principal: null,
    reason
  };
}

/**
 * Decide whether a route remains usable under a revocation set.
 * Any applicable revocation wins. Emergency and all-route revocation
 * invalidate every route. A hard device revocation invalidates its
 * device. A principal-wide revocation invalidates its principal.
 */
export function isRouteRevoked(
  route: RouteBinding,
  revocations: readonly RevocationRecord[]
): RevocationCheck {
  for (const revocation of revocations) {
    switch (revocation.kind) {
      case "emergency":
      case "all_route":
        return { ok: false, failure: "DEVICE_REVOKED" };
      case "hard_device":
        if (revocation.deviceId === route.deviceId) {
          return { ok: false, failure: "DEVICE_REVOKED" };
        }
        break;
      case "principal_wide":
        if (revocation.principal === route.principal) {
          return { ok: false, failure: "DEVICE_REVOKED" };
        }
        break;
    }
  }
  return { ok: true };
}

/**
 * Verify the device-verifiable authorization envelope against the exact
 * expected route. A compromised relay must not remap principal A onto
 * device B: any principal, connection, device, digest, epoch, or session
 * mismatch fails closed before workspace policy, lease, profile, and
 * approval checks.
 */
export function verifyAuthorizationEnvelope(
  candidate: AuthorizationEnvelopeCandidate,
  expected: EnvelopeExpectation,
  revocations: readonly RevocationRecord[]
): EnvelopeCheck {
  if (
    !isNonEmptyString(candidate.principal) ||
    !isNonEmptyString(candidate.connection) ||
    !isNonEmptyString(candidate.device) ||
    !isNonEmptyString(candidate.requestDigest) ||
    !isNonEmptyString(candidate.sessionContext)
  ) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  if (typeof candidate.epoch !== "number" || !Number.isInteger(candidate.epoch)) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  if (
    candidate.principal !== expected.principal ||
    candidate.connection !== expected.connection ||
    candidate.device !== expected.deviceId
  ) {
    return { ok: false, failure: "ROUTE_MISMATCH" };
  }
  if (
    !isRequestDigestHex(candidate.requestDigest) ||
    !isRequestDigestHex(expected.requestDigestHex) ||
    !equalHexHex(candidate.requestDigest, expected.requestDigestHex)
  ) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  if (candidate.epoch !== expected.epoch) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  if (candidate.sessionContext !== expected.sessionContext) {
    return { ok: false, failure: "REMOTE_AUTH_INVALID" };
  }
  const route: RouteBinding = {
    principal: expected.principal,
    stableConnectionId: expected.connection,
    deviceId: expected.deviceId,
    epoch: expected.epoch
  };
  const revoked = isRouteRevoked(route, revocations);
  if (!revoked.ok) {
    return revoked;
  }
  return { ok: true };
}

/**
 * Redacted pairing summary for logs and evidence. It carries the code
 * identity and class only, never the code, its hash, or key material.
 */
export function redactedPairingSummary(record: PairingRecord): {
  readonly codeId: string;
  readonly consumed: boolean;
  readonly invalidated: boolean;
} {
  return {
    codeId: record.codeId,
    consumed: record.consumed,
    invalidated: record.invalidated
  };
}

/**
 * Redacted device summary for logs and evidence. It carries identity and
 * epoch only, never private key material.
 */
export function redactedDeviceSummary(identity: DeviceIdentity): {
  readonly deviceId: string;
  readonly epoch: number;
} {
  return { deviceId: identity.deviceId, epoch: identity.epoch };
}

/** Assert that every failure code used here belongs to the frozen vocabulary. */
export function deviceIdentityFailuresAreFrozenSubset(): boolean {
  const used: RelayFailureCode[] = [
    "REMOTE_AUTH_REQUIRED",
    "REMOTE_AUTH_INVALID",
    "DEVICE_REVOKED",
    "PAIRING_REQUIRED",
    "PAIRING_EXPIRED",
    "PAIRING_DENIED",
    "ROUTE_MISMATCH",
    "RELAY_REPLAY_DETECTED",
    "DEVICE_OFFLINE",
    "REMOTE_SESSION_INACTIVE"
  ];
  const frozen = new Set<string>(RELAY_FAILURE_CODES as readonly string[]);
  if (RELAY_FAILURE_CODES.length !== 17) {
    return false;
  }
  if (RELAY_BOUNDS.maxPairingAttemptsPerCode !== PAIRING_CODE_MAX_ATTEMPTS) {
    return false;
  }
  return used.every((code) => frozen.has(code));
}
