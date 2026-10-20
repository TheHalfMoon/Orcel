/**
 * SG-000055 protected uplink state loading.
 *
 * Reads the SG-000053 device key record and the local route revocation list
 * from protected Orcel state. A missing or malformed device key fails
 * closed with PAIRING_REQUIRED. A missing revocation list means no
 * revocation; an unreadable or malformed one fails closed as an emergency
 * revocation so no route stays usable on corrupt state.
 *
 * XP-19: the record holds the public identity only; the private key comes
 * from the `orceld` secret store. A record that still carries a private key
 * (written before XP-19) is refused until the user runs
 * `orcel remote migrate-secrets`: it is never read as a key here.
 */
import { existsSync, readFileSync } from "node:fs";
import {
  emergencyRevoke,
  isDeviceId,
  privateKeyMatchesIdentity,
  type DeviceIdentity,
  type DeviceKeyPair,
  type RevocationKind,
  type RevocationRecord
} from "./device_identity.js";
import { DEVICE_KEY_SECRET, type SecretStore } from "./secret_store.js";

const REVOCATION_KINDS: readonly RevocationKind[] = [
  "hard_device",
  "principal_wide",
  "all_route",
  "emergency"
];

export const LEGACY_PLAINTEXT_KEY_MESSAGE =
  "PAIRING_REQUIRED: this device key record still holds a plaintext private key from an earlier version; run `orcel remote migrate-secrets` to move it into the OS secret store";

/** The public device identity from the device key record. */
export function loadDeviceRecord(path: string): DeviceIdentity {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("PAIRING_REQUIRED: device key is missing or unreadable");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("PAIRING_REQUIRED: device key record is malformed");
  }
  const record = parsed as Record<string, unknown>;
  if ("privateKeyJwkBase64" in record) {
    throw new Error(LEGACY_PLAINTEXT_KEY_MESSAGE);
  }
  if (
    typeof record.deviceId !== "string" ||
    !isDeviceId(record.deviceId) ||
    typeof record.publicKeyJwkBase64 !== "string" ||
    record.publicKeyJwkBase64.length === 0 ||
    typeof record.createdAtMs !== "number" ||
    !Number.isSafeInteger(record.createdAtMs) ||
    typeof record.epoch !== "number" ||
    !Number.isSafeInteger(record.epoch) ||
    record.epoch < 1
  ) {
    throw new Error("PAIRING_REQUIRED: device key record is malformed");
  }
  return {
    deviceId: record.deviceId,
    publicKeyJwkBase64: record.publicKeyJwkBase64,
    createdAtMs: record.createdAtMs,
    epoch: record.epoch
  };
}

/**
 * The device key pair: the public record plus the private key from the
 * secret store, which must be the private half of the recorded public key.
 */
export async function loadDeviceKey(path: string, secrets: SecretStore): Promise<DeviceKeyPair> {
  const identity = loadDeviceRecord(path);
  const privateKeyJwkBase64 = await secrets.get(DEVICE_KEY_SECRET);
  if (privateKeyJwkBase64 === null) {
    throw new Error("PAIRING_REQUIRED: the device private key is not in the secret store; run `orcel remote enable` again");
  }
  if (!privateKeyMatchesIdentity(privateKeyJwkBase64, identity.publicKeyJwkBase64)) {
    throw new Error("PAIRING_REQUIRED: the stored device private key does not match the device identity");
  }
  return { ...identity, privateKeyJwkBase64 };
}

function isRevocationRecord(value: unknown): value is RevocationRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.kind === "string" &&
    (REVOCATION_KINDS as readonly string[]).includes(record.kind) &&
    typeof record.createdAtMs === "number" &&
    typeof record.epoch === "number" &&
    (record.deviceId === null || typeof record.deviceId === "string") &&
    (record.principal === null || typeof record.principal === "string") &&
    typeof record.reason === "string"
  );
}

export function loadRevocations(path: string): readonly RevocationRecord[] {
  if (!existsSync(path)) {
    return [];
  }
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (Array.isArray(parsed) && parsed.length <= 1024 && parsed.every(isRevocationRecord)) {
      return parsed;
    }
  } catch {
    // fall through to fail closed
  }
  return [emergencyRevoke(0, Date.now(), "revocation list unreadable; failing closed")];
}
