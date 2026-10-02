import { defineEvalConfig } from "orcel/evals";

export default defineEvalConfig({
  maxConcurrency: 1,
  timeoutMs: 600_000,
});
