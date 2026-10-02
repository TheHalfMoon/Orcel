import { e2eAgentConfig } from "@orcel-e2e/config";
import { defineAgent } from "orcel";
import { mockModel } from "orcel/evals";
import { respond } from "./lib/mock-responder";

const base = e2eAgentConfig({ mock: respond });

export default defineAgent({
  ...base,
  model: mockModel(respond),
  modelContextWindowTokens: base.modelContextWindowTokens ?? 1_000_000,
});
