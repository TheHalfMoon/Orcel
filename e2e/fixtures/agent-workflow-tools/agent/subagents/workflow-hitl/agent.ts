import { defineAgent } from "kaf";
import { mockModel } from "kaf/evals";

export default defineAgent({
  description: "Exercise a deterministic approval-gated child tool.",
  model: mockModel(({ toolResults }) => {
    const result = toolResults.find((entry) => entry.name === "approval-gate");
    return result === undefined
      ? { toolCalls: [{ input: { marker: "approved" }, name: "approval-gate" }] }
      : String(result.output);
  }),
  modelContextWindowTokens: 1_000_000,
});
