import { defineAgent } from "@orcel/orcel";

export default defineAgent({
  description: "Independently answer the user's prompt with Moonshot AI Kimi K3.",
  model: "moonshotai/kimi-k3",
});
