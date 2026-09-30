import supermemory from "@supermemory/kaf";
import { defineMemory } from "kaf/memory";
import { byPrincipal } from "kaf/memory/scope";

export default defineMemory({
  description: "Recall and manage durable context for the current user.",
  provider: supermemory({
    apiKey: process.env.SUPERMEMORY_API_KEY!,
  }),
  scope: byPrincipal,
});
