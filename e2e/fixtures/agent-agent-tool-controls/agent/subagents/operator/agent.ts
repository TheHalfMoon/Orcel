import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Execute operational changes to systems and deployments.",
  ...e2eSubagentConfig({ mock: "AUTO-ROUTER-OPERATOR" }),
  tool: false,
});
