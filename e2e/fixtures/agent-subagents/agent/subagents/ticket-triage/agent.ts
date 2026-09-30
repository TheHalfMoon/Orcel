import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description:
    "Software-factory ticket triage specialist. Give this agent a synthetic ticket batch to classify before review or reproduction planning.",
  ...e2eSubagentConfig(),
  reasoning: "high",
});
