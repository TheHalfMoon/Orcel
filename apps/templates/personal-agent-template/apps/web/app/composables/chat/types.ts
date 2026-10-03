import type { ComputedRef, Ref } from "vue";
import type { OrcelMessageData, UseOrcelAgentOptions } from "@orcel/orcel/vue";
import type { OrcelSessionCursor } from "#orcel/types/thread";
import type { UIMessage } from "ai";
import type { AgentInputResponse } from "~/components/AgentInputRequest.vue";

export type OrcelStreamEvent = NonNullable<
  UseOrcelAgentOptions<OrcelMessageData>["initialEvents"]
>[number];

export type ChatStatus = "ready" | "submitted" | "streaming" | "error";

export interface ChatSessionOptions {
  initialSession?: OrcelSessionCursor;
  initialEvents?: readonly OrcelStreamEvent[];
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
