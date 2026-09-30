import { e2eAgentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";
import { respond } from "./lib/mock-responder.js";

export default defineAgent({
  ...e2eAgentConfig({ mock: respond }),
  reasoning: "high",
});
