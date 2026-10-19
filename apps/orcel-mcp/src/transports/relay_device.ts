/**
 * Relay device transport (ORCEL-P15, SG-000055).
 *
 * Starts the outbound-only device uplink from protected local state: the
 * uplink configuration (relay origin, default workspace, locally paired
 * connections), the SG-000053 device key, and the local route revocation
 * list. It opens no listener and registers no tools; every MCP message is
 * served by the authoritative builder with a remote-context kernel, so
 * `orceld` enforces the local remote-session lease on each request.
 * Missing or malformed state fails closed with PAIRING_REQUIRED.
 */
import { readFileSync } from "node:fs";
import {
  createMcpFrameDispatcher,
  isPairedConnection,
  isRelayOrigin,
  runDeviceUplink,
  type UplinkConfig
} from "../device_uplink.js";
import { withKernelSecretStore } from "../secret_store.js";
import { loadDeviceKey, loadDeviceRecord, loadRevocations } from "../uplink_state.js";

export const RELAY_TRANSPORT_RESERVED = "ORCEL-P15";

const UPLINK_SCHEMA = "orcel-uplink/1";

export interface UplinkFile {
  readonly relayOrigin: string;
  readonly defaultWorkspace: string;
  readonly connections: UplinkConfig["connections"];
}

export function parseUplinkFile(text: string): UplinkFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("PAIRING_REQUIRED: uplink configuration is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("PAIRING_REQUIRED: uplink configuration must be an object");
  }
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (keys !== "connections,defaultWorkspace,relayOrigin,schema" || record.schema !== UPLINK_SCHEMA) {
    throw new Error("PAIRING_REQUIRED: uplink configuration has an unexpected shape");
  }
  if (!isRelayOrigin(record.relayOrigin)) {
    throw new Error("PAIRING_REQUIRED: relay origin must be https or an exact loopback origin");
  }
  if (typeof record.defaultWorkspace !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(record.defaultWorkspace)) {
    throw new Error("PAIRING_REQUIRED: default workspace is invalid");
  }
  const connections = record.connections;
  if (
    !Array.isArray(connections) ||
    connections.length === 0 ||
    connections.length > 8 ||
    !connections.every(isPairedConnection)
  ) {
    throw new Error("PAIRING_REQUIRED: no valid paired remote connection");
  }
  return {
    relayOrigin: record.relayOrigin,
    defaultWorkspace: record.defaultWorkspace,
    connections
  };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`PAIRING_REQUIRED: ${name} is not configured`);
  }
  return value;
}

function readUplinkFile(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    throw new Error("PAIRING_REQUIRED: uplink configuration is missing or unreadable");
  }
}

export async function startRelayTransport(): Promise<void> {
  const uplink = parseUplinkFile(readUplinkFile(requiredEnv("ORCEL_UPLINK_CONFIG")));
  const deviceKeyPath = requiredEnv("ORCEL_DEVICE_KEY_PATH");
  loadDeviceRecord(deviceKeyPath);
  // XP-19: the private key comes from the orceld secret store, once.
  const device = await withKernelSecretStore(uplink.defaultWorkspace, (secrets) =>
    loadDeviceKey(deviceKeyPath, secrets)
  );
  const revocationsPath = requiredEnv("ORCEL_DEVICE_REVOCATIONS_PATH");
  const controller = new AbortController();
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => controller.abort());
  }
  const config: UplinkConfig = {
    relayOrigin: uplink.relayOrigin,
    identity: { deviceId: device.deviceId, deviceEpoch: device.epoch },
    privateKeyJwkBase64: device.privateKeyJwkBase64,
    connections: uplink.connections
  };
  void runDeviceUplink(config, {
    fetch: (url, init) => fetch(url, init),
    dispatcher: createMcpFrameDispatcher({ defaultWorkspace: uplink.defaultWorkspace }),
    revocations: () => loadRevocations(revocationsPath),
    signal: controller.signal,
    log: (event) => process.stderr.write(`[orcel-uplink] ${event}\n`)
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message.split(":")[0] : "TRANSPORT_UNAVAILABLE";
    process.stderr.write(`[orcel-uplink] stopped: ${message}\n`);
    process.exitCode = 1;
  });
}
