import { fileMemory } from "@orcel/orcel/memory/file";
import { defineMemory } from "@orcel/orcel/memory";
import { byPrincipal } from "@orcel/orcel/memory/scope";

export default defineMemory({
  description: "Remember stable facts and preferences about the caller.",
  provider: fileMemory(),
  scope: byPrincipal,
});
