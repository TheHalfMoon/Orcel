import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description: "Investigate, analyze, and explain questions without changing systems.",
  ...e2eSubagentConfig({ mock: "AUTO-ROUTER-RESEARCHER" }),
  tool: false,
});
