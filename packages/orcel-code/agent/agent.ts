import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  model: process.env.E0_MODEL ?? "openai/gpt-5.6-terra",
});
