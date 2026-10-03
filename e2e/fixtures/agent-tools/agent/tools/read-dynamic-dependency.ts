import { readDynamicImportMarker } from "@orcel-e2e/dynamic-import-dependency";
import { defineTool } from "@orcel/orcel/tools";
import { z } from "zod";

export default defineTool({
  description:
    "Loads the dynamic dependency marker. Only call when the user explicitly asks to use `read-dynamic-dependency`.",
  inputSchema: z.object({}),
  async execute() {
    const [{ marker: authoredMarker }, dependencyMarker] = await Promise.all([
      import("../lib/dynamic-import-marker"),
      readDynamicImportMarker(),
    ]);

    return { authoredMarker, dependencyMarker };
  },
});
