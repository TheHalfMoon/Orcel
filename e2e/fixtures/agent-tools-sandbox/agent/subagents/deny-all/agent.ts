import { e2eSubagentConfig } from "@kaf-e2e/config";
import { defineAgent } from "kaf";
import type { MockModelRequest, MockModelResponse } from "kaf/evals";

import { respond as respondToDirective } from "../../lib/mock-responder.js";

export default defineAgent({
  description: "Runs commands in an independent sandbox opened with deny-all networking.",
  ...e2eSubagentConfig({ mock: respond }),
});

function respond(request: MockModelRequest): MockModelResponse | string {
  if (!request.lastUserMessage?.includes("configured environment")) {
    return respondToDirective(request);
  }
  const result = request.toolResults.find((entry) => entry.name === "verify-typed-sandbox");
  return result === undefined
    ? { toolCalls: [{ input: {}, name: "verify-typed-sandbox" }] }
    : JSON.stringify(result.output);
}
