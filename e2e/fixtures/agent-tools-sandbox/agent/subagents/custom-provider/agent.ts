import { e2eSubagentConfig } from "@orcel-e2e/config";
import { defineAgent } from "@orcel/orcel";
import type { MockModelRequest, MockModelResponse } from "@orcel/orcel/evals";

export default defineAgent({
  description: "Verifies custom sandbox provider session capabilities.",
  ...e2eSubagentConfig({ mock: respond }),
});

function respond(request: MockModelRequest): MockModelResponse | string {
  const result = request.toolResults.find((entry) => entry.name === "verify-provider-session");
  return result === undefined
    ? { toolCalls: [{ input: {}, name: "verify-provider-session" }] }
    : String(result.output);
}
