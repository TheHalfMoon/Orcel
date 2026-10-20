// Adapted from BuilderIO/agent-native@9c277b79cb87eb27da538e572dd710986e2fa06d
// packages/agentkit/src/protocol/version.ts (MIT, Builder.io; notice in
// docs/orcel/notices/agent-native-MIT.txt; transplant row T-AN-01).
// Orcel changes: the version is orceld's string tag `orcel-app-api/1`
// instead of AgentKit's numeric version 2, and the frame limit of
// ORCEL_APP_API_1.md section 3 lives next to it.

export const APP_API_PROTOCOL = "orcel-app-api/1" as const;
export const APP_API_SUPPORTED_PROTOCOLS = [APP_API_PROTOCOL] as const;

/** At most 65,536 bytes per frame, newline included, in both directions. */
export const MAX_FRAME_BYTES = 65_536;

export type AppApiProtocol = (typeof APP_API_SUPPORTED_PROTOCOLS)[number];

export function isAppApiProtocol(value: unknown): value is AppApiProtocol {
  return (APP_API_SUPPORTED_PROTOCOLS as readonly unknown[]).includes(value);
}
