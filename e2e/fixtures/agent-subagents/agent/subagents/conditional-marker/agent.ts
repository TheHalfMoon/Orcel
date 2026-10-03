import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent, defineDynamic } from "@orcel/orcel";

const mockMode = process.env.ORCEL_E2E_MODEL === "mock";

export default defineDynamic({
  events: {
    "session.started": () =>
      defineAgent({
        description: "Return the dynamic-subagent availability marker.",
        model: mockMode
          ? "orcel-mock/dynamic-subagent"
          : e2eSubagentConfig({ mock: "DYNAMIC_SUBAGENT_ENABLED" }).model,
        modelContextWindowTokens: 1_000_000,
      }),
  },
});
