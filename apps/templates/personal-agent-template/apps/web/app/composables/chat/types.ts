import type { ComputedRef, Ref } from "vue";
import type { KafMessageData, UseKafAgentOptions } from "kaf/vue";
import type { KafSessionCursor } from "#kaf/types/thread";
import type { UIMessage } from "ai";
import type { AgentInputResponse } from "~/components/AgentInputRequest.vue";

export type KafStreamEvent = NonNullable<
  UseKafAgentOptions<KafMessageData>["initialEvents"]
>[number];

export type ChatStatus = "ready" | "submitted" | "streaming" | "error";

export interface ChatSessionOptions {
  initialSession?: KafSessionCursor;
  initialEvents?: readonly KafStreamEvent[];
}

export interface ChatSession {
  messages: ComputedRef<UIMessage[]>;
  status: Ref<ChatStatus> | ComputedRef<ChatStatus>;
  error: Ref<Error | undefined> | ComputedRef<Error | undefined>;
  isBusy: ComputedRef<boolean>;
  sendMessage: (text: string) => Promise<void>;
  sendInputResponses: (responses: AgentInputResponse[]) => Promise<void>;
  stop: () => void;
  reset: () => void;
  retry: () => Promise<void>;
}
