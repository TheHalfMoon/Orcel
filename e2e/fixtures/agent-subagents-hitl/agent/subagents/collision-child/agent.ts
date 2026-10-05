import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Return the marker from the request without calling any tools.",
  ...e2eSubagentConfig(),
});
