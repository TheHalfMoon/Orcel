import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Internal specialist hidden by its agent definition.",
  ...e2eSubagentConfig({ mock: "TOOL-FALSE-SUBAGENT-OK" }),
  tool: false,
});
