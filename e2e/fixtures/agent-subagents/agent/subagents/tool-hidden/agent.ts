import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description: "Internal specialist hidden by its agent definition.",
  ...e2eSubagentConfig({ mock: "TOOL-FALSE-SUBAGENT-OK" }),
  tool: false,
});
