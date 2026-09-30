import { defineEvalConfig } from "kaf/evals";

export default defineEvalConfig({ maxConcurrency: 1, timeoutMs: 240_000 });
