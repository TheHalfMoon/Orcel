import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description: "Execute operational changes to systems and deployments.",
  ...e2eSubagentConfig({ mock: "AUTO-ROUTER-OPERATOR" }),
  tool: false,
});
