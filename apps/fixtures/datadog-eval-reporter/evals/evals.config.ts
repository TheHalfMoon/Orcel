import { defineEvalConfig } from "kaf/evals";
import { Datadog } from "kaf/evals/reporters";

const hasDatadogCredentials = Boolean(process.env.DD_API_KEY && process.env.DD_APP_KEY);

export default defineEvalConfig({
  reporters: hasDatadogCredentials ? [Datadog({ recordInputs: true })] : [],
});
