import { defineTool } from "@orcel/orcel/tools";
import { once } from "@orcel/orcel/tools/approval";
import { z } from "zod";

export default defineTool({
  description: "Return a deterministic marker after human approval.",
  approval: once(),
  inputSchema: z.strictObject({ marker: z.string() }),
  execute({ marker }) {
    return `WORKFLOW-HITL:${marker}`;
  },
});
