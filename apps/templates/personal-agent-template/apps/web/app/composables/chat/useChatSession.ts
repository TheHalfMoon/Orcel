import type { MaybeRefOrGetter } from "vue";
import type { ChatSession, ChatSessionOptions } from "~/composables/chat/types";
import { createOrcelChatSession } from "~/composables/chat/providers/orcel/session";

export function useChatSession(
  chatId: MaybeRefOrGetter<string> = "default",
  options?: MaybeRefOrGetter<ChatSessionOptions | undefined>,
): ChatSession {
  return createOrcelChatSession(chatId, options);
}
