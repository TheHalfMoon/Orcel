import { defineEvalConfig } from "@orcel/orcel/evals";
import { Datadog } from "@orcel/orcel/evals/reporters";

const hasDatadogCredentials = Boolean(process.env.DD_API_KEY && process.env.DD_APP_KEY);

export default defineEvalConfig({
  reporters: hasDatadogCredentials ? [Datadog({ recordInputs: true })] : [],
});
