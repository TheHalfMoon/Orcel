import { e2eJudgeModel } from "@orcel-e2e/config";
import { defineEvalConfig } from "orcel/evals";
import { evalLifecycleReporter } from "./reporter.js";

export default defineEvalConfig({
  judge: { model: e2eJudgeModel() },
  reporters: [evalLifecycleReporter],
});
