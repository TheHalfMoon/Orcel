import { defineTool } from "@orcel/orcel/tools";
import { always } from "@orcel/orcel/tools/approval";
import { defineState } from "@orcel/orcel/context";
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
