import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  model: "anthropic/claude-opus-5",
  limits: {
    maxOutputTokensPerSession: 4_000,
  },
});
