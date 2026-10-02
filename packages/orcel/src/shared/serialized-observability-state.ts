export const SERIALIZED_INSTRUMENTATION_STATE_KEYS = {
  activeChannelDeliveries: "orcel.activeChannelDeliveries",
  actionScopes: "orcel.harness.instrumentationActionScopes",
  inputScopes: "orcel.harness.instrumentationInputScopes",
  providerState: "orcel.harness.instrumentationState",
} as const;

/** Keeps instrumentation state needed to settle operations opened by a discarded step. */
export function preserveSerializedInstrumentationState(
  original: Record<string, unknown>,
  interrupted: Record<string, unknown>,
): Record<string, unknown> {
  let preserved = original;
  for (const key of Object.values(SERIALIZED_INSTRUMENTATION_STATE_KEYS)) {
    const state = interrupted[key];
    if (state !== undefined) preserved = { ...preserved, [key]: state };
  }
  return preserved;
}
