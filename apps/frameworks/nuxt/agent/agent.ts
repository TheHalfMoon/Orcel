import { defineAgent } from "kaf";

export default defineAgent({
  model: "anthropic/claude-opus-4.7",
  modelOptions: {
    providerOptions: {
      anthropic: {
        thinking: { type: "adaptive", display: "summarized" },
        effort: "high",
      },
    },
  },
});
