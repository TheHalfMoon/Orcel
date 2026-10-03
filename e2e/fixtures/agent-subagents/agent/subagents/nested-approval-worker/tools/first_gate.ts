import { defineTool } from "@orcel/orcel/tools";
import { once } from "@orcel/orcel/tools/approval";
import { z } from "zod";

export default defineTool({
  description: "Ask Alice to approve the first release checklist gate.",
  inputSchema: z.object({}),
  approval: once(),
  execute: async () => "first gate approved",
});
