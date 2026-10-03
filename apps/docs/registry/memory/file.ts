import { fileMemory } from "orcel/memory/file";
import { defineMemory } from "orcel/memory";
import { byPrincipal } from "orcel/memory/scope";

export default defineMemory({
  description: "Remember stable facts and preferences about the caller.",
  provider: fileMemory(),
  scope: byPrincipal,
});
