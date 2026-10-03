import { defineEval } from "@orcel/orcel/evals";

export default defineEval({
  tags: ["real-model"],
  description:
    "An agent-shaped dist extension with a registry-style store layout loads and its tool runs.",
  async test(t) {
    await t.send("Call `gadget__gadget_echo` with message 'orcel'. Report the output.");

    t.succeeded();
    t.calledTool("gadget__gadget_echo", {
      output: { message: "orcel", reply: "gadget-reply:orcel" },
    });
  },
});
