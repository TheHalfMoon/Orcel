/**
 * SG-000057 device-side remote enrollment and pairing.
 *
 * `enable` creates the protected Ed25519 device key (if absent), writes the
 * uplink configuration for one relay origin, and registers only the public
 * device identity with the relay. `pair` creates one SG-000053 one-time
 * pairing code, registers only its hash with the relay as a short-lived
 * offer authenticated by a fresh device signature, shows the code to the
 * local user, and records a paired connection only after the user confirms
 * the exact client, redirect origin, and scopes locally. Pairing grants no
 * workspace trust, no approval, and no remote-session lease.
 *
 * Both run from the local lifecycle CLI after STRONG presence; neither is an
 * MCP tool. The private key never leaves this machine.
 *
 * XP-19: the private key goes to the `orceld` secret store; the device key
 * record on disk holds only the public identity.
 */
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import {
  generateDeviceId,
  generateDeviceKeyPair,
  issuePairingCode,
  publicDeviceIdentity,
  signDeviceChallenge,
  type DeviceChallenge,
  type DeviceKeyPair
} from "./device_identity.js";
import { isPairedConnection, isRelayOrigin, readBoundedJson, type FetchLike, type PairedConnection } from "./device_uplink.js";
import { DEVICE_KEY_SECRET, type SecretStore } from "./secret_store.js";
import { loadDeviceKey } from "./uplink_state.js";

export const UPLINK_SCHEMA = "orcel-uplink/1";
export const ENROLLMENT_PATHS = {
  register: "/device/v1/register",
  challenge: "/device/v1/pairing/challenge",
  offer: "/device/v1/pairing/offer",
  status: "/device/v1/pairing/status",
  confirm: "/device/v1/pairing/confirm"
} as const;
export const DEFAULT_CLIENT_PROFILE = "remote-default";
const MAX_REPLY_BYTES = 65_536;

export interface UplinkDocument {
  schema: string;
  relayOrigin: string;
  defaultWorkspace: string;
  connections: PairedConnection[];
}

export interface PairingRequest {
  readonly clientId: string;
  readonly clientName: string;
  readonly redirectOrigin: string;
  readonly scopes: readonly string[];
  readonly principal: string;
  readonly remoteConnectionId: string;
}

function writeAtomic(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  writeFileSync(temp, text, { mode: 0o600 });
  renameSync(temp, path);
}

async function post(fetchImpl: FetchLike, origin: string, path: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const response = await fetchImpl(origin + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    credentials: "omit",
    signal: AbortSignal.timeout(15_000)
  });
  const parsed = await readBoundedJson(response, MAX_REPLY_BYTES);
  return {
    status: response.status,
    json: typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {}
  };
}

export function readUplinkDocument(path: string): UplinkDocument | null {
  if (!existsSync(path)) {
    return null;
  }
  const parsed = JSON.parse(readFileSync(path, "utf8")) as UplinkDocument;
  if (
    parsed.schema !== UPLINK_SCHEMA ||
    !isRelayOrigin(parsed.relayOrigin) ||
    !Array.isArray(parsed.connections) ||
    !parsed.connections.every(isPairedConnection)
  ) {
    throw new Error("PAIRING_REQUIRED: existing uplink configuration is malformed");
  }
  return parsed;
}

/** Create or reuse the device key, write the uplink configuration, register the public identity. */
export async function enableRemote(options: {
  readonly relayOrigin: string;
  readonly defaultWorkspace: string;
  readonly deviceKeyPath: string;
  readonly uplinkPath: string;
  readonly secrets: SecretStore;
  readonly fetch: FetchLike;
  readonly nowMs: number;
}): Promise<{ readonly deviceId: string; readonly created: boolean }> {
  if (!isRelayOrigin(options.relayOrigin)) {
    throw new Error("TRANSPORT_UNAVAILABLE: relay origin must be https or an exact loopback origin");
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(options.defaultWorkspace)) {
    throw new Error("PAIRING_REQUIRED: default workspace is invalid");
  }
  let pair: DeviceKeyPair;
  let created = false;
  if (existsSync(options.deviceKeyPath)) {
    pair = await loadDeviceKey(options.deviceKeyPath, options.secrets);
  } else {
    pair = generateDeviceKeyPair(generateDeviceId(), options.nowMs, 1);
    // The secret store first: a record is written only for a stored key.
    await options.secrets.put(DEVICE_KEY_SECRET, pair.privateKeyJwkBase64);
    writeAtomic(options.deviceKeyPath, JSON.stringify(publicDeviceIdentity(pair)));
    created = true;
  }
  const existing = readUplinkDocument(options.uplinkPath);
  if (existing !== null && existing.relayOrigin !== options.relayOrigin && existing.connections.length > 0) {
    throw new Error("PAIRING_REQUIRED: this device is paired with another relay; revoke those connections first");
  }
  const document: UplinkDocument = {
    schema: UPLINK_SCHEMA,
    relayOrigin: options.relayOrigin,
    defaultWorkspace: options.defaultWorkspace,
    connections: existing?.relayOrigin === options.relayOrigin ? existing.connections : []
  };
  writeAtomic(options.uplinkPath, JSON.stringify(document, null, 2));
  const reply = await post(options.fetch, options.relayOrigin, ENROLLMENT_PATHS.register, {
    identity: publicDeviceIdentity(pair)
  });
  if (reply.status !== 200 && reply.status !== 201) {
    throw new Error(`PAIRING_DENIED: the relay refused the device registration (${reply.status})`);
  }
  return { deviceId: pair.deviceId, created };
}

async function signedChallenge(fetchImpl: FetchLike, origin: string, pair: DeviceKeyPair): Promise<ReturnType<typeof signDeviceChallenge>> {
  const reply = await post(fetchImpl, origin, ENROLLMENT_PATHS.challenge, { deviceId: pair.deviceId });
  const challenge = reply.json.challenge as DeviceChallenge | undefined;
  if (reply.status !== 200 || challenge === undefined || challenge.deviceId !== pair.deviceId || challenge.epoch !== pair.epoch) {
    throw new Error("PAIRING_DENIED: the relay did not issue a challenge for this device");
  }
  return signDeviceChallenge(pair.privateKeyJwkBase64, challenge);
}

function isPairingRequest(value: unknown): value is PairingRequest {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.clientId === "string" &&
    typeof record.clientName === "string" &&
    typeof record.redirectOrigin === "string" &&
    Array.isArray(record.scopes) &&
    typeof record.principal === "string" &&
    typeof record.remoteConnectionId === "string"
  );
}

/**
 * Pair one remote provider connection. `display` shows the code; `confirm`
 * asks the local user to approve the exact request. Returns the recorded
 * connection, or null when the user declined or the offer expired.
 */
export async function pairRemote(options: {
  readonly deviceKeyPath: string;
  readonly uplinkPath: string;
  readonly secrets: SecretStore;
  readonly fetch: FetchLike;
  readonly now: () => number;
  readonly display: (code: string, expiresAtMs: number) => void;
  readonly confirm: (request: PairingRequest) => Promise<boolean>;
  readonly sleep: (ms: number) => Promise<void>;
  readonly pollIntervalMs?: number;
}): Promise<PairedConnection | null> {
  const pair = await loadDeviceKey(options.deviceKeyPath, options.secrets);
  const uplink = readUplinkDocument(options.uplinkPath);
  if (uplink === null) {
    throw new Error("PAIRING_REQUIRED: run `orcel remote enable` first");
  }
  const registered = await post(options.fetch, uplink.relayOrigin, ENROLLMENT_PATHS.register, {
    identity: publicDeviceIdentity(pair)
  });
  if (registered.status !== 200 && registered.status !== 201) {
    throw new Error("PAIRING_DENIED: the relay does not accept this device");
  }
  const issued = issuePairingCode(options.now(), "pc-" + randomBytes(8).toString("hex"));
  const offer = await post(options.fetch, uplink.relayOrigin, ENROLLMENT_PATHS.offer, {
    response: await signedChallenge(options.fetch, uplink.relayOrigin, pair),
    codeHashHex: issued.record.codeHashHex,
    expiresAtMs: issued.record.expiresAtMs
  });
  const offerId = offer.json.offerId;
  if (offer.status !== 201 || typeof offerId !== "string") {
    throw new Error("PAIRING_DENIED: the relay refused the pairing offer");
  }
  options.display(issued.code, issued.record.expiresAtMs);
  while (options.now() <= issued.record.expiresAtMs) {
    const status = await post(options.fetch, uplink.relayOrigin, ENROLLMENT_PATHS.status, { offerId });
    if (status.status === 404 || status.json.state === "expired" || status.json.state === "done") {
      return null;
    }
    if (status.json.state === "confirm") {
      const request = status.json.request;
      const challenge = status.json.challenge as DeviceChallenge | undefined;
      if (!isPairingRequest(request) || challenge === undefined || challenge.deviceId !== pair.deviceId) {
        throw new Error("PAIRING_DENIED: malformed pairing request from the relay");
      }
      const approved = await options.confirm(request);
      const decision = await post(options.fetch, uplink.relayOrigin, ENROLLMENT_PATHS.confirm, {
        offerId,
        decision: approved ? "approve" : "deny",
        response: signDeviceChallenge(pair.privateKeyJwkBase64, challenge)
      });
      if (!approved) {
        return null;
      }
      const connection = decision.json.connection as Record<string, unknown> | undefined;
      const paired: PairedConnection = {
        principal: String(connection?.principal ?? ""),
        remoteConnectionId: String(connection?.remoteConnectionId ?? ""),
        providerKind: String(connection?.providerKind ?? ""),
        clientProfileId: DEFAULT_CLIENT_PROFILE,
        clientProfileRevision: 1,
        toolSurfaceProfile: "core",
        scopeCeiling: (Array.isArray(connection?.scopeCeiling) ? connection.scopeCeiling : []) as PairedConnection["scopeCeiling"]
      };
      if (
        decision.status !== 200 ||
        decision.json.result !== "approved" ||
        !isPairedConnection(paired) ||
        paired.principal !== request.principal ||
        paired.remoteConnectionId !== request.remoteConnectionId ||
        paired.scopeCeiling.join(" ") !== request.scopes.join(" ")
      ) {
        throw new Error("PAIRING_DENIED: the relay did not complete the approved pairing");
      }
      const current = readUplinkDocument(options.uplinkPath) ?? uplink;
      current.connections = [...current.connections.filter((c) => c.remoteConnectionId !== paired.remoteConnectionId), paired];
      if (current.connections.length > 8) {
        throw new Error("PAIRING_DENIED: at most 8 paired connections per device");
      }
      writeAtomic(options.uplinkPath, JSON.stringify(current, null, 2));
      return paired;
    }
    await options.sleep(options.pollIntervalMs ?? 2_000);
  }
  return null;
}
