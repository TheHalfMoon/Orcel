import { defineEval } from "kaf/evals";

export default defineEval({
  tags: ["real-model"],
  description:
    "A dist-only extension installed with a registry-style store layout loads and its tool runs.",
  async test(t) {
    await t.send("Call `gizmo__gizmo_search` with query 'kaf'. Report the output.");

    t.succeeded();
    t.calledTool("gizmo__gizmo_search", {
      output: { query: "kaf", result: "gizmo-result-for:kaf" },
    });
  },
});
