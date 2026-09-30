import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description: "Return the marker from the request without calling any tools.",
  ...e2eSubagentConfig(),
});
