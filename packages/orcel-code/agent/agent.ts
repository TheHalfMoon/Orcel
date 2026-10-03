import { defineAgent } from "orcel";

export default defineAgent({
  model: process.env.E0_MODEL ?? "openai/gpt-5.6-terra",
});
