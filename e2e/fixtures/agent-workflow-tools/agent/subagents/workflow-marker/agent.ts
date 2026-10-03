import { defineAgent } from "orcel";
import { mockModel } from "orcel/evals";

export default defineAgent({
  description: "Return deterministic markers for workflow-subagent e2e coverage.",
  model: mockModel(({ lastUserMessage }) => `WORKFLOW-CHILD:${lastUserMessage ?? ""}`),
  modelContextWindowTokens: 1_000_000,
});
