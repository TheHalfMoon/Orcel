import { e2eAgentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";

export default defineAgent({
  ...e2eAgentConfig({
    mock: ({ lastUserMessage }) => `Mock reply: ${lastUserMessage ?? ""}`,
  }),
  reasoning: "high",
});
