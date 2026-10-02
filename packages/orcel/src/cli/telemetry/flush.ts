const DEFAULT_ENDPOINT = "https://telemetry.vercel.com/api/orcel-cli/v1/events";
const REQUEST_TIMEOUT_MS = 1_000;

type TelemetryEvent = {
  readonly id: string;
  readonly event_time: number;
  readonly key: string;
  readonly value: string;
};

type FlushPayload = {
  readonly events: TelemetryEvent[];
  readonly sessionId: string;
};

function isFlushPayload(value: unknown): value is FlushPayload {
  if (!value || typeof value !== "object") return false;
  const payload = value as Partial<FlushPayload>;
  return typeof payload.sessionId === "string" && Array.isArray(payload.events);
}

/** Sends a telemetry batch from the telemetry-disabled child CLI process. */
export async function flushOrcelCliTelemetry(payloadJson: string): Promise<void> {
  let payload: FlushPayload;
  try {
    const parsed = JSON.parse(payloadJson) as unknown;
    if (!isFlushPayload(parsed)) return;
    payload = parsed;
  } catch {
    return;
  }

  try {
    await fetch(process.env.ORCEL_TELEMETRY_ENDPOINT ?? DEFAULT_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "client-id": "orcel-cli",
        "x-orcel-cli-topic-id": "generic",
        "x-orcel-cli-session-id": payload.sessionId,
      },
      body: JSON.stringify(payload.events),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    // Telemetry must never affect command output or exit status.
  }
}
