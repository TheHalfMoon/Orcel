import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description: "Internal specialist hidden by a same-named disabled tool.",
  ...e2eSubagentConfig({ mock: "DISABLED-SUBAGENT-OK" }),
});
