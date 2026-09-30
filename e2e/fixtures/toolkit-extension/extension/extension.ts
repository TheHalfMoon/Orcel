import { defineExtension } from "kaf/extension";
import { z } from "zod";

export default defineExtension({
  config: z.object({
    apiKey: z.string(),
    tier: z.string().default("free"),
  }),
});
