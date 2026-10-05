import { defineMemory } from "@orcel/orcel/memory";
import { fileMemory, inMemory } from "@orcel/orcel/memory/file";

const provider = process.env.VERCEL
  ? fileMemory()
  : fileMemory({
      backend: inMemory(),
    });

export default defineMemory({
  description: "Remember stable facts with the bounded file provider.",
  provider,
  scope: () =>
    process.env.VERCEL_DEPLOYMENT_ID?.trim() ||
    process.env.VERCEL_URL?.trim() ||
    "local-file-memory-e2e",
});
