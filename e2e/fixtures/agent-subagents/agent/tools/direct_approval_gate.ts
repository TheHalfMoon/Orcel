import { defineTool } from "@orcel/orcel/tools";
import { once } from "@orcel/orcel/tools/approval";
import { z } from "zod";

export default defineTool({
  description: "Ask Alice to approve her release checklist in the remote agent.",
  inputSchema: z.object({}),
  approval: once(),
  execute: async () => "Alice approved the release checklist.",
});
