import { e2eAgentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

import { respond } from "./mock-responder.js";

export default defineAgent({
  ...e2eAgentConfig({ mock: respond }),
});
