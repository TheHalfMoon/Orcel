import { defineTool } from "kaf/tools";
import { once } from "kaf/tools/approval";
import { z } from "zod";

export default defineTool({
  description: "Ask Alice to approve her release checklist in the remote agent.",
  inputSchema: z.object({}),
  approval: once(),
  execute: async () => "Alice approved the release checklist.",
});
