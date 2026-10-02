import { defineWorkflowTool } from "orcel/tools";

import {
  executeWorkflowAgentProbe,
  workflowAgentProbeInputSchema,
} from "../lib/workflow-agent-probe.ts";

export default defineWorkflowTool({
  description: "Run a blocking local or remote subagent HITL/authorization probe.",
  inputSchema: workflowAgentProbeInputSchema,
  async execute(input, ctx) {
    "use workflow";

    return await executeWorkflowAgentProbe(input, ctx);
  },
});
