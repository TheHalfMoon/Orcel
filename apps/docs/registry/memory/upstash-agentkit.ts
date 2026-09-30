import { redisMemory } from "@upstash/agentkit-eve/memory";
import { defineMemory } from "kaf/memory";
import { byPrincipal } from "kaf/memory/scope";

export default defineMemory({
  description: "Recall and manage durable context for the current user.",
  provider: redisMemory({ topK: 5 }),
  scope: byPrincipal,
});
