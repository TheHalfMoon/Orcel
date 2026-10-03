import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "orcel";

import { respond } from "../../lib/mock-responder.js";

export default defineAgent({
  description: "Runs sandbox commands in the root agent's inherited workspace.",
  ...e2eSubagentConfig({ mock: respond }),
});
