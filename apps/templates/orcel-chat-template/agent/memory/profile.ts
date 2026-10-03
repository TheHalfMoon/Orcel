import { defineMemory } from "@orcel/orcel/memory";
import { fileMemory } from "@orcel/orcel/memory/file";
import { byPrincipal } from "@orcel/orcel/memory/scope";

// Only the ORCEL_MEMORY_BLOB_* namespace enables memory on Vercel. orcel also
// accepts generic BLOB_* variables, but this template ignores them so memory
// never silently takes over an application's own Blob store.
const MEMORY_BLOB_ENV_KEYS = [
  "ORCEL_MEMORY_BLOB_STORE_ID",
  "ORCEL_MEMORY_BLOB_READ_WRITE_TOKEN",
] as const;

function hasMemoryBlobStorage() {
  return MEMORY_BLOB_ENV_KEYS.some((key) => process.env[key]?.trim());
}

export default defineMemory({
  description: "Remember stable facts and preferences about the caller.",
  provider: fileMemory(),
  scope(context) {
    // Do not expose memory tools until the deployed app has durable storage.
    if (process.env.VERCEL && !hasMemoryBlobStorage()) {
      return null;
    }

    return byPrincipal(context);
  },
});
