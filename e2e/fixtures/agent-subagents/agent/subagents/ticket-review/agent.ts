import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description:
    "Software-factory backlog reviewer. Give this agent a synthetic ticket batch to produce an independent review summary before reproduction planning.",
  ...e2eSubagentConfig(),
  reasoning: "high",
});
