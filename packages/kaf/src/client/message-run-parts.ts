import type { KafMessage, KafMessagePart } from "#client/message-reducer-types.js";

type KafAssistantMessage = KafMessage & { readonly role: "assistant" };
type KafRunPart = Extract<KafMessagePart, { readonly type: "text" | "reasoning" }>;

function append(
  message: KafAssistantMessage,
  append: {
    readonly delta: string;
    readonly stepIndex: number;
    readonly type: KafRunPart["type"];
  },
): KafAssistantMessage {
  const current = latestStreamingRun(message, append.type, append.stepIndex);
  return upsert(message, {
    state: "streaming",
    stepIndex: append.stepIndex,
    text: (current?.text ?? "") + append.delta,
    type: append.type,
  });
}

function latestStreamingRun(
  message: KafAssistantMessage,
  type: KafRunPart["type"],
  stepIndex: number,
): KafRunPart | undefined {
  for (let index = message.parts.length - 1; index >= 0; index -= 1) {
    const part = message.parts[index];
    if (part?.type === type && part.stepIndex === stepIndex) {
      return part.state === "streaming" ? part : undefined;
    }
  }
  return undefined;
}

// One step can produce text, call tools, then produce more text. Replace its
// open run in place; after completion, append a new run in arrival order.
function upsert(message: KafAssistantMessage, next: KafRunPart): KafAssistantMessage {
  let lastIndex = -1;
  for (let index = message.parts.length - 1; index >= 0; index -= 1) {
    const part = message.parts[index];
    if (part?.type === next.type && part.stepIndex === next.stepIndex) {
      lastIndex = index;
      break;
    }
  }

  const openRun =
    lastIndex !== -1 && (message.parts[lastIndex] as KafRunPart).state === "streaming";
  const parts = openRun
    ? [...message.parts.slice(0, lastIndex), next, ...message.parts.slice(lastIndex + 1)]
    : [...message.parts, next];

  return {
    ...message,
    metadata: {
      ...message.metadata,
      status: next.type === "text" && next.state === "done" ? "complete" : "streaming",
    },
    parts,
  };
}

export const messageRun = { append, upsert } as const;
