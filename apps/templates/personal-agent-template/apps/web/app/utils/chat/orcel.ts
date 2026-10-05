import { isDynamicToolUIPart, isTextUIPart, isToolUIPart } from "ai";
import type { UIMessage } from "ai";
import type { OrcelDynamicToolPart } from "@orcel/orcel/vue";

export function hasVisibleParts(parts: UIMessage["parts"]): boolean {
  return parts.some((part) => {
    if (part.type === "text" || part.type === "reasoning") return true;
    return isToolUIPart(part) || isDynamicToolUIPart(part);
  });
}

export function normalizeOrcelParts(parts: UIMessage["parts"]): UIMessage["parts"] {
  return parts.filter((part) => part.type !== "step-start");
}

export function shouldShowToolInput(part: OrcelDynamicToolPart): boolean {
  const request = part.toolMetadata?.orcel?.inputRequest;
  if (!request) {
    return true;
  }
  return request.display === "confirmation";
}

export function getToolDisplayName(part: OrcelDynamicToolPart): string {
  if (part.toolName === "ask_question") {
    return part.toolMetadata?.orcel?.inputRequest?.prompt ?? "Question";
  }
  return part.toolName;
}
