import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  description:
    "Coordinates Alice's release checklist sign-off by handing it to verification-worker.",
  ...e2eSubagentConfig(),
});
