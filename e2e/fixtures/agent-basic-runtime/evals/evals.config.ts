import { e2eJudgeModel } from "@kaf-e2e/config";
import { defineEvalConfig } from "kaf/evals";
import { evalLifecycleReporter } from "./reporter.js";

export default defineEvalConfig({
  judge: { model: e2eJudgeModel() },
  reporters: [evalLifecycleReporter],
});
