import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Independently answer the user's prompt with Anthropic Claude Opus 5.",
  model: "anthropic/claude-opus-5",
});
