import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description:
    "Software-factory reproduction planner. Give this agent completed triage and review results to produce a concrete reproduction artifact.",
  ...e2eSubagentConfig(),
  reasoning: "high",
});
