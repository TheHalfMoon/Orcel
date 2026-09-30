import { type KafMessageData, type UseKafAgentReturn, useKafAgent } from "kaf/vue";
import type { ChatSessionOptions } from "~/composables/chat/types";
import { recordAuthorizationEvent } from "~/composables/chat/useAuthorizationChallenges";
import { persistThreadState } from "./thread-state";
import { recordStreamEvent } from "./stream-log";

const agentsByChatId = new Map<string, UseKafAgentReturn<KafMessageData>>();

export function getOrCreateKafAgent(chatId: string, options?: ChatSessionOptions) {
  let agent = agentsByChatId.get(chatId);
  if (!agent) {
    agent = useKafAgent({
      initialSession: options?.initialSession,
      initialEvents: options?.initialEvents,
      onFinish: (snapshot) => {
        void persistThreadState(chatId, snapshot);
      },
      onEvent: (event) => {
        if (event.type === "authorization.required" || event.type === "authorization.completed") {
          recordAuthorizationEvent(event);
        }

        if (!import.meta.dev) return;
        recordStreamEvent(event.type);
      },
    });
    agentsByChatId.set(chatId, agent);
  }
  return agent;
}

export function removeKafAgent(chatId: string) {
  agentsByChatId.delete(chatId);
}

export function resetAllKafAgents() {
  for (const agent of agentsByChatId.values()) {
    agent.reset();
  }
  agentsByChatId.clear();
}
