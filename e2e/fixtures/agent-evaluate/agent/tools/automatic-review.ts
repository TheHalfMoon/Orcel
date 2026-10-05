import { defineTool } from "@orcel/orcel/tools";
import { auto } from "@orcel/orcel/tools/approval";

import { permissionEvaluationModel } from "../testing";

export default defineTool({
  description: "Exercise evaluation-model approval.",
  inputSchema: {
    type: "object",
    properties: { effect: { type: "string", enum: ["safe", "malicious"] } },
    required: ["effect"],
    additionalProperties: false,
  },
  approval: auto({ model: permissionEvaluationModel }),
  execute({ effect }) {
    return { effect, executed: true };
  },
});
