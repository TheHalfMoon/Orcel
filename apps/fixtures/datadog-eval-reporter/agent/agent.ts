import { e2eAgentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";
import { mockModel } from "kaf/evals";

export default defineAgent({
  ...e2eAgentConfig(),
  model: mockModel(),
  modelContextWindowTokens: 1_000_000,
});
