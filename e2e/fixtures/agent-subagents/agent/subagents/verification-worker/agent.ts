import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "orcel";

export default defineAgent({
  description:
    "Collects Alice's release checklist sign-off with verification_gate and reports its sign-off code.",
  ...e2eSubagentConfig(),
});
