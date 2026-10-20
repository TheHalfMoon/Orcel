import { startRelayTransport } from "../transports/relay_device.js";

/**
 * Relay device entrypoint (SG-000055): outbound-only device uplink.
 * Fails closed with PAIRING_REQUIRED when no protected pairing state exists.
 */
startRelayTransport().catch((error: unknown) => {
  const code = error instanceof Error ? error.message.split(":")[0] : "TRANSPORT_UNAVAILABLE";
  process.stderr.write(`[orcel-uplink] ${code}\n`);
  process.exitCode = 1;
});
