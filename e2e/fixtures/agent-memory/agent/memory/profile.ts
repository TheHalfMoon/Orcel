import { defineMemory } from "kaf/memory";
import { inMemory, type MemoryDocumentBackend } from "kaf/memory/file";
import { vercelBlob } from "kaf/memory/file/vercel";
import { byPrincipal } from "kaf/memory/scope";
import { defineTool } from "kaf/tools";
import { z } from "zod";

const profiles: MemoryDocumentBackend = process.env.VERCEL
  ? vercelBlob({ prefix: "kaf/e2e/agent-memory/profile" })
  : inMemory();

export default defineMemory({
  description: "Update the durable profile value for this caller.",
  provider: {
    recall: {
      async "turn.started"(ctx) {
        const document = await profiles.read({
          key: ctx.memory.scope.key,
          signal: ctx.abortSignal,
        });
        const value = document?.content ?? "OLD_PROFILE_VALUE";
        return { messages: [{ content: `PROFILE_VALUE=${value}`, id: "profile" }] };
      },
    },
    async tools(ctx) {
      return {
        save: defineTool({
          description: "Save the caller's profile value.",
          inputSchema: z.object({ value: z.string() }),
          async execute({ value }, toolContext) {
            const current = await profiles.read({
              key: ctx.memory.scope.key,
              signal: toolContext.abortSignal,
            });
            await profiles.write({
              content: value,
              expectedVersion: current?.version ?? null,
              key: ctx.memory.scope.key,
              signal: toolContext.abortSignal,
            });
            return { saved: true };
          },
        }),
      };
    },
  },
  scope: byPrincipal,
});
