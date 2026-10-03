import type { OrcelMessageData, UseOrcelAgentSnapshot } from "orcel/vue";
import type { ThreadRecord, ThreadState } from "#orcel/types/thread";
import type { ChatSessionOptions, OrcelStreamEvent } from "~/composables/chat/types";
import { refreshThreadList } from "~/composables/chat/navigation";

export function resumeOptionsFromThread(thread: ThreadRecord): ChatSessionOptions {
  const events = thread.state?.events;
  if (!events?.length) {
    return {};
  }

  const session = thread.state?.session;

  return {
    initialSession: session?.sessionId
      ? {
          sessionId: session.sessionId,
          streamIndex: Math.max(session.streamIndex ?? 0, events.length),
        }
      : undefined,
    initialEvents: events as readonly OrcelStreamEvent[],
  };
}

export async function persistThreadState(
  threadId: string,
  snapshot: UseOrcelAgentSnapshot<OrcelMessageData>,
) {
  if (!snapshot.events.length || !snapshot.session) {
    return;
  }

  const state: ThreadState = {
    session: {
      sessionId: snapshot.session.sessionId,
      streamIndex: snapshot.session.streamIndex,
    },
    events: [...snapshot.events],
  };

  await $fetch(`/api/threads/${threadId}`, {
    method: "PATCH",
    body: { state },
  });

  void refreshThreadList();
}
