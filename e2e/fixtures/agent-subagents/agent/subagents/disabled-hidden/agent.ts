import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Internal specialist hidden by a same-named disabled tool.",
  ...e2eSubagentConfig({ mock: "DISABLED-SUBAGENT-OK" }),
});
