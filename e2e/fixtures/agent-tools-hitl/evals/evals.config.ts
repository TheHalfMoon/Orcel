import { e2eJudgeModel } from "@orcel-e2e/config";
import { defineEvalConfig } from "@orcel/orcel/evals";

export default defineEvalConfig({
  maxConcurrency: 4,
  judge: { model: e2eJudgeModel() },
});
