import { defineEvalConfig } from "@orcel/orcel/evals";

export default defineEvalConfig({
  maxConcurrency: 1,
  timeoutMs: 180_000,
});
