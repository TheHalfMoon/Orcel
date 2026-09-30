import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description:
    "Software-factory reproduction planner. Give this agent completed triage and review results to produce a concrete reproduction artifact.",
  ...e2eSubagentConfig(),
  reasoning: "high",
});
