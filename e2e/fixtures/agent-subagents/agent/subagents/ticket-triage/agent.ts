import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "orcel";

export default defineAgent({
  description:
    "Software-factory ticket triage specialist. Give this agent a synthetic ticket batch to classify before review or reproduction planning.",
  ...e2eSubagentConfig(),
  reasoning: "high",
});
