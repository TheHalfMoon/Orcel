import { defineEvalConfig } from "orcel/evals";

export default defineEvalConfig({
  // Workflow tools dispatch durable runs; serialize so the runs are never
  // starved past the per-eval timeout.
  maxConcurrency: 1,
  timeoutMs: 120_000,
});
