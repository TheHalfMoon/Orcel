import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";
import type { MockModelRequest, MockModelResponse } from "kaf/evals";

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
