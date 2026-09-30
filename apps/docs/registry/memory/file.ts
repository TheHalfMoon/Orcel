import { fileMemory } from "kaf/memory/file";
import { defineMemory } from "kaf/memory";
import { byPrincipal } from "kaf/memory/scope";

export default defineMemory({
  description: "Remember stable facts and preferences about the caller.",
  provider: fileMemory(),
  scope: byPrincipal,
});
