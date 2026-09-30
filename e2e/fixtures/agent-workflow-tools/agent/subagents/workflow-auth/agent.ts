import { defineAgent } from "kaf";
import { mockModel } from "kaf/evals";

export default defineAgent({
  description: "Exercise a deterministic interactive-authorization child tool.",
  model: mockModel(({ toolResults }) => {
    const result = toolResults.find((entry) => entry.name === "auth-gate");
    return result === undefined
      ? { toolCalls: [{ input: { marker: "authorized" }, name: "auth-gate" }] }
      : String(result.output);
  }),
  modelContextWindowTokens: 1_000_000,
});
