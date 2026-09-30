import { isDynamicToolUIPart, isTextUIPart, isToolUIPart } from "ai";
import type { UIMessage } from "ai";
import type { KafDynamicToolPart } from "kaf/vue";

export function hasVisibleParts(parts: UIMessage["parts"]): boolean {
  return parts.some((part) => {
    if (part.type === "text" || part.type === "reasoning") return true;
    return isToolUIPart(part) || isDynamicToolUIPart(part);
  });
}

export function normalizeKafParts(parts: UIMessage["parts"]): UIMessage["parts"] {
  return parts.filter((part) => part.type !== "step-start");
}

export function shouldShowToolInput(part: KafDynamicToolPart): boolean {
  const request = part.toolMetadata?.kaf?.inputRequest;
  if (!request) {
    return true;
  }
  return request.display === "confirmation";
}

export function getToolDisplayName(part: KafDynamicToolPart): string {
  if (part.toolName === "ask_question") {
    return part.toolMetadata?.kaf?.inputRequest?.prompt ?? "Question";
  }
  return part.toolName;
}
