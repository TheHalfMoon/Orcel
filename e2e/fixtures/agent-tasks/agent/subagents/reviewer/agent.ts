import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description: "Reviews a release summary and approves it or requests changes.",
  ...e2eSubagentConfig(),
});
