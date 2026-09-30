import { e2eJudgeModel } from "@kaf-e2e/config";
import { defineEvalConfig } from "kaf/evals";

export default defineEvalConfig({
  judge: { model: e2eJudgeModel() },
  // Evals run without a bound otherwise, so a missed turn would hold CI until its job limit.
  timeoutMs: 60_000,
});
