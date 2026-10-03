import { e2eAgentConfig } from "@orcel-e2e/config";
import { defineAgent } from "orcel";

const config = e2eAgentConfig();

export default defineAgent({
  ...config,
  // Measure Anthropic cache reuse through its native provider.
  ...(typeof config.model === "string" && config.model.startsWith("anthropic/")
    ? {
        modelOptions: {
          providerOptions: { gateway: { only: ["anthropic"] } },
        },
      }
    : {}),
  reasoning: "high",
  limits: { maxInputTokensPerSession: 300_000 },
});
