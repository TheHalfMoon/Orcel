import type { UIMessage } from "ai";
import type { KafMessage } from "kaf/vue";

export function toUIMessages(messages: readonly KafMessage[]): UIMessage[] {
  return [...messages] as UIMessage[];
}
