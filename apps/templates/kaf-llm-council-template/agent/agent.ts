import { defineAgent } from "kaf";

export default defineAgent({
  model: "anthropic/claude-opus-5",
  limits: {
    maxOutputTokensPerSession: 4_000,
  },
});
