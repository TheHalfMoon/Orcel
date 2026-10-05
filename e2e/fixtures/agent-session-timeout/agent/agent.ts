import { e2eAgentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";
import { mockModel } from "@orcel/orcel/evals";

const ACTIVE_TURN_DELAY_MS = 1_500;

export default defineAgent({
  // Harness config wires the workflow world; the model is always this
  // fixture's scripted mock.
  ...e2eAgentConfig(),
  model: mockModel(async ({ lastUserMessage }) => {
    if (lastUserMessage?.includes("SLOW-TURN") === true) {
      await new Promise((resolve) => setTimeout(resolve, ACTIVE_TURN_DELAY_MS));
    }

    return `timeout-ack:${lastUserMessage ?? ""}`;
  }),
  modelContextWindowTokens: 1_000_000,
  limits: {
    sessionTimeoutMs: 750,
  },
});
