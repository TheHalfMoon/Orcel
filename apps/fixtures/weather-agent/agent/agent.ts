import { defineAgent } from "orcel";

export default defineAgent({
  model: "openai/gpt-5.6-luna-fast",
  modelOptions: {
    providerOptions: {
      openai: {
        reasoningEffort: "high",
        reasoningSummary: "auto",
      },
    },
  },
});
