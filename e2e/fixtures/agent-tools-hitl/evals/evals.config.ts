import { e2eJudgeModel } from "@kaf-e2e/config";
import { defineEvalConfig } from "kaf/evals";

export default defineEvalConfig({
  maxConcurrency: 4,
  judge: { model: e2eJudgeModel() },
});
