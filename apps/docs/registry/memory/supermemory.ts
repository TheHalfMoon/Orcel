import supermemory from "@supermemory/eve";
import { defineMemory } from "@orcel/orcel/memory";
import { byPrincipal } from "@orcel/orcel/memory/scope";

export default defineMemory({
  description: "Recall and manage durable context for the current user.",
  provider: supermemory({
    apiKey: process.env.SUPERMEMORY_API_KEY!,
  }),
  scope: byPrincipal,
});
