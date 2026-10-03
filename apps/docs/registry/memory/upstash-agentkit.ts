import { redisMemory } from "@upstash/agentkit-eve/memory";
import { defineMemory } from "@orcel/orcel/memory";
import { byPrincipal } from "@orcel/orcel/memory/scope";

export default defineMemory({
  description: "Recall and manage durable context for the current user.",
  provider: redisMemory({ topK: 5 }),
  scope: byPrincipal,
});
