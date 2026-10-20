/**
 * #395: the ChatGPT Secure MCP Tunnel is a remote transport.
 *
 * The tunnel host, the only command the tunnel client runs, starts this app
 * with `ORCEL_MCP_TRANSPORT=tunnel` and the tunnel's remote route, derived
 * from the locally configured tunnel id. The stdio transport then serves the
 * remote `core` profile through `allowedToolsFor`, exactly like the relay,
 * and every `orceld` request carries an SG-000055 remote context, so
 * `orceld` requires an active local remote-session lease and the remote
 * scope map. In tunnel mode no environment variable selects a local profile.
 */
import { randomBytes } from "node:crypto";
import { isPairedConnection, type PairedConnection } from "./device_uplink.js";
import type { RemoteDispatchContext } from "./kernel.js";

export const TRANSPORT_ENV = "ORCEL_MCP_TRANSPORT";
export const TUNNEL_TRANSPORT = "tunnel";
export const TUNNEL_ROUTE_ENV = "ORCEL_TUNNEL_ROUTE_JSON";

const DEVICE_PATTERN = /^dev-[0-9a-f]{32}$/;

export interface TunnelRoute {
  readonly paired: PairedConnection;
  readonly deviceId: string;
  readonly deviceEpoch: number;
}

/** Parse the route the tunnel host supplies. Anything else fails closed. */
export function parseTunnelRoute(text: string | undefined): TunnelRoute {
  if (text === undefined || text.length === 0) {
    throw new Error("TRANSPORT_UNAVAILABLE: the tunnel route is not configured");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("TRANSPORT_UNAVAILABLE: the tunnel route is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("TRANSPORT_UNAVAILABLE: the tunnel route must be an object");
  }
  const { deviceId, deviceEpoch, ...paired } = parsed as Record<string, unknown>;
  if (
    typeof deviceId !== "string" ||
    !DEVICE_PATTERN.test(deviceId) ||
    typeof deviceEpoch !== "number" ||
    !Number.isSafeInteger(deviceEpoch) ||
    deviceEpoch < 1 ||
    !isPairedConnection(paired)
  ) {
    throw new Error("TRANSPORT_UNAVAILABLE: the tunnel route is malformed");
  }
  return { paired, deviceId, deviceEpoch };
}

/**
 * The remote context for one tunnel host process. The connection id is
 * fresh per process: a lease pins the first connection that uses it, so a
 * restarted host needs a new lease, as a relay reconnect does.
 */
export function tunnelRemoteContext(
  route: TunnelRoute,
  connectionId = `tunnel-${randomBytes(16).toString("hex")}`
): RemoteDispatchContext {
  return {
    principal: route.paired.principal,
    remoteConnectionId: route.paired.remoteConnectionId,
    connectionId,
    deviceId: route.deviceId,
    deviceEpoch: route.deviceEpoch,
    providerKind: route.paired.providerKind,
    clientProfileId: route.paired.clientProfileId,
    clientProfileRevision: route.paired.clientProfileRevision,
    toolSurfaceProfile: "core",
    scopes: [...route.paired.scopeCeiling]
  };
}
