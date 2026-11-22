/**
 * SG-000056 relay state interface and in-memory implementation.
 *
 * The relay stores only opaque route identifiers, device public keys, token
 * verification keys, and revocation state. It never stores MCP payloads,
 * tool arguments, results, device private keys, or bearer tokens. Durable
 * storage and enrollment are added by SG-000057 behind this interface.
 */
import type { DeviceIdentity, RevocationRecord } from "@orcel/mcp/dist/device_identity.js";
import type { OAuthScope, TokenVerificationKey } from "@orcel/mcp/dist/oauth_authorization.js";

export interface RelayDeviceRecord {
  readonly identity: DeviceIdentity;
  readonly revoked: boolean;
}

/** One paired provider connection: one principal, one device, one client. */
export interface RelayConnectionRecord {
  readonly principal: string;
  readonly remoteConnectionId: string;
  readonly deviceId: string;
  readonly clientId: string;
  readonly providerKind: string;
  readonly scopeCeiling: readonly OAuthScope[];
  readonly revoked: boolean;
}

export interface RelayStore {
  device(deviceId: string): RelayDeviceRecord | undefined;
  connection(remoteConnectionId: string): RelayConnectionRecord | undefined;
  verificationKeys(): readonly TokenVerificationKey[];
  revokedTokenIds(): ReadonlySet<string>;
  revokedFamilyIds(): ReadonlySet<string>;
  revocations(): readonly RevocationRecord[];
  deviceEpochs(): ReadonlyMap<string, number>;
}

export class MemoryRelayStore implements RelayStore {
  private readonly devices = new Map<string, RelayDeviceRecord>();
  private readonly connections = new Map<string, RelayConnectionRecord>();
  private readonly keys: TokenVerificationKey[] = [];
  private readonly tokenIds = new Set<string>();
  private readonly familyIds = new Set<string>();
  private readonly routeRevocations: RevocationRecord[] = [];

  putDevice(identity: DeviceIdentity): void {
    this.devices.set(identity.deviceId, { identity, revoked: false });
  }

  revokeDevice(deviceId: string): void {
    const record = this.devices.get(deviceId);
    if (record !== undefined) {
      this.devices.set(deviceId, { ...record, revoked: true });
    }
  }

  putConnection(record: Omit<RelayConnectionRecord, "revoked">): void {
    this.connections.set(record.remoteConnectionId, { ...record, revoked: false });
  }

  revokeConnection(remoteConnectionId: string): void {
    const record = this.connections.get(remoteConnectionId);
    if (record !== undefined) {
      this.connections.set(remoteConnectionId, { ...record, revoked: true });
    }
  }

  addVerificationKey(key: TokenVerificationKey): void {
    this.keys.push(key);
  }

  revokeTokenId(tokenId: string): void {
    this.tokenIds.add(tokenId);
  }

  revokeFamilyId(familyId: string): void {
    this.familyIds.add(familyId);
  }

  addRevocation(record: RevocationRecord): void {
    this.routeRevocations.push(record);
  }

  device(deviceId: string): RelayDeviceRecord | undefined {
    return this.devices.get(deviceId);
  }

  connection(remoteConnectionId: string): RelayConnectionRecord | undefined {
    return this.connections.get(remoteConnectionId);
  }

  verificationKeys(): readonly TokenVerificationKey[] {
    return this.keys;
  }

  revokedTokenIds(): ReadonlySet<string> {
    return this.tokenIds;
  }

  revokedFamilyIds(): ReadonlySet<string> {
    return this.familyIds;
  }

  revocations(): readonly RevocationRecord[] {
    return this.routeRevocations;
  }

  deviceEpochs(): ReadonlyMap<string, number> {
    const epochs = new Map<string, number>();
    for (const [id, record] of this.devices) {
      if (!record.revoked) {
        epochs.set(id, record.identity.epoch);
      }
    }
    return epochs;
  }
}
