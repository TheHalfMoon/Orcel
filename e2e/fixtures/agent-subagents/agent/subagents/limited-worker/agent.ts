import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description:
    "Test-only child for session-limit propagation. Call it exactly when the user asks for the limited-worker subagent.",
  limits: {
    maxInputTokensPerSession: 1,
  },
  ...e2eSubagentConfig(),
  reasoning: "high",
});
