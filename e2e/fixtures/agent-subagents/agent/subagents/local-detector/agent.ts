import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description:
    "Coordinates Alice's release checklist sign-off by handing it to verification-worker.",
  ...e2eSubagentConfig(),
});
