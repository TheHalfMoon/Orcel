import { defineTool } from "kaf/tools";
import { once } from "kaf/tools/approval";
import { z } from "zod";

export default defineTool({
  description: "Return a deterministic marker after human approval.",
  approval: once(),
  inputSchema: z.strictObject({ marker: z.string() }),
  execute({ marker }) {
    return `WORKFLOW-HITL:${marker}`;
  },
});
