import { e2eAgentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";

import { respond } from "./mock-responder.js";

export default defineAgent({
  ...e2eAgentConfig({ mock: respond }),
});
