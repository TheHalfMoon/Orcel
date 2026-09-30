import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent, defineDynamic } from "kaf";

const mockMode = process.env.KAF_E2E_MODEL === "mock";

export default defineDynamic({
  events: {
    "session.started": () =>
      defineAgent({
        description: "Return the dynamic-subagent availability marker.",
        model: mockMode
          ? "kaf-mock/dynamic-subagent"
          : e2eSubagentConfig({ mock: "DYNAMIC_SUBAGENT_ENABLED" }).model,
        modelContextWindowTokens: 1_000_000,
      }),
  },
});
