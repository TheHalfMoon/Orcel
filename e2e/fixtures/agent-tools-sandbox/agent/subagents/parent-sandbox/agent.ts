import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

import { respond } from "../../lib/mock-responder.js";

export default defineAgent({
  description: "Runs sandbox commands in the root agent's inherited workspace.",
  ...e2eSubagentConfig({ mock: respond }),
});
