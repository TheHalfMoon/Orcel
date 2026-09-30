import type { MaybeRefOrGetter } from "vue";
import type { ChatSession, ChatSessionOptions } from "~/composables/chat/types";
import { createKafChatSession } from "~/composables/chat/providers/kaf/session";

export function useChatSession(
  chatId: MaybeRefOrGetter<string> = "default",
  options?: MaybeRefOrGetter<ChatSessionOptions | undefined>,
): ChatSession {
  return createKafChatSession(chatId, options);
}
