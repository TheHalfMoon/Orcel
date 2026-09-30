import { defineTool } from "kaf/tools";
import { always } from "kaf/tools/approval";
import { defineState } from "kaf/context";
import { z } from "zod";

const executions = defineState("change-b.executions", () => 0);

export default defineTool({
  description: "Apply fixture change B after approval.",
  inputSchema: z.object({}),
  approval: always(),
  async execute() {
    executions.update((count) => count + 1);
    return { change: "B", executions: executions.get() };
  },
});
