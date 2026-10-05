import { defineEval } from "@orcel/orcel/evals";

export default defineEval({
  description: "Datadog reporter smoke eval.",

  async test(t) {
    await t.send("Say hello.");
    t.succeeded();
  },
});
