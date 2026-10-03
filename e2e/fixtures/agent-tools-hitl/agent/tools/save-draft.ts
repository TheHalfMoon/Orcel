import { defineState } from "@orcel/orcel/context";
import { defineTool } from "@orcel/orcel/tools";
import { z } from "zod";

const writes = defineState("draft.writes", () => 0);

export default defineTool({
  description: "Save the fixture draft and return the number of writes in this session.",
  inputSchema: z.object({}),
  async execute() {
    writes.update((count) => count + 1);
    return { writes: writes.get() };
  },
});
