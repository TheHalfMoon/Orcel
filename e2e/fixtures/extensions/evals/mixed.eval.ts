import { defineEval } from "kaf/evals";

export default defineEval({
  tags: ["real-model"],
  description: "Consumer-authored and mounted-extension tools coexist and both run in one turn.",
  async test(t) {
    await t.send(
      "First call `local_ping`, then call `gizmo__gizmo_search` with query 'kaf'. Report both outputs.",
    );

    t.succeeded();
    t.calledTool("local_ping", { output: { reply: "local-ping" } });
    t.calledTool("gizmo__gizmo_search", {
      output: { query: "kaf", result: "gizmo-result-for:kaf" },
    });
  },
});
