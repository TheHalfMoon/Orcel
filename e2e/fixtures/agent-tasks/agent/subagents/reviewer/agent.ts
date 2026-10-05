import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Reviews a release summary and approves it or requests changes.",
  ...e2eSubagentConfig(),
});
