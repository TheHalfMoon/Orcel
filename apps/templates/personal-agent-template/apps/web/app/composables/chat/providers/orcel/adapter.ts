import type { UIMessage } from "ai";
import type { OrcelMessage } from "@orcel/orcel/vue";

export function toUIMessages(messages: readonly OrcelMessage[]): UIMessage[] {
  return [...messages] as UIMessage[];
}
