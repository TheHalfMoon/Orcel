import { e2eAgentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";
import { mockModel } from "@orcel/orcel/evals";

export default defineAgent({
  ...e2eAgentConfig(),
  model: mockModel(),
  modelContextWindowTokens: 1_000_000,
});
