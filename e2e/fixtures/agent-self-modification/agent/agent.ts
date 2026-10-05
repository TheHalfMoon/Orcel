import { e2eAgentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  ...e2eAgentConfig(),
  reasoning: "high",
});
