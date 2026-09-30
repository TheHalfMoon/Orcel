import type { RuntimeActionRequest, RuntimeActionResult } from "#shared/action-types.js";
import type { InputRequest } from "#shared/input.js";
import type {
  KafDynamicToolPart,
  KafMessageInputRequest,
  KafMessageToolMetadata,
} from "#client/message-reducer-types.js";

/**
 * Normalized tool descriptor derived from a runtime action request or result.
 *
 * The default message reducer projects load-skill, subagent, remote-agent, and
 * plain tool calls onto a single `dynamic-tool` UI part; this descriptor is the
 * shared shape those variants collapse to before rendering.
 */
interface ActionDescriptor {
  readonly kind: "load-skill" | "subagent-call" | "tool-call";
  readonly name: string;
  readonly toolName: string;
}

/** Projects a runtime input request onto its UI-facing subset. */
export function toMessageInputRequest(request: InputRequest): KafMessageInputRequest {
  return {
    allowFreeform: request.allowFreeform,
    display: request.display,
    kind: request.kind,
    options: request.options,
    prompt: request.prompt,
    requestId: request.requestId,
  };
}

/** Builds tool metadata for a freshly projected tool part. */
export function createToolMetadata(
  descriptor: ActionDescriptor,
  extra?: { readonly inputRequest?: KafMessageInputRequest },
): KafMessageToolMetadata {
  return {
    kaf: {
      inputRequest: extra?.inputRequest,
      kind: descriptor.kind,
      name: descriptor.name,
    },
  };
}

/**
 * Merges freshly derived tool metadata over any metadata already attached to a
 * tool part, preferring the new values while preserving earlier request and
 * response context.
 */
export function mergeToolMetadata(
  current: KafMessageToolMetadata | undefined,
  next: KafMessageToolMetadata,
): KafMessageToolMetadata {
  const kind = next.kaf?.kind ?? current?.kaf?.kind ?? "unknown";
  const name = next.kaf?.name ?? current?.kaf?.name ?? "unknown";

  return {
    kaf: {
      ...current?.kaf,
      ...next.kaf,
      inputRequest: next.kaf?.inputRequest ?? current?.kaf?.inputRequest,
      inputResponse: next.kaf?.inputResponse ?? current?.kaf?.inputResponse,
      kind,
      name,
    },
  };
}

/**
 * Derives the approved-approval descriptor a resolved tool result carries
 * forward, or `undefined` when the tool part never had an approval.
 */
export function approvedApproval(part: KafDynamicToolPart | undefined):
  | {
      readonly id: string;
      readonly approved: true;
      readonly reason?: string;
      readonly isAutomatic?: boolean;
    }
  | undefined {
  if (!part?.approval?.id) {
    return undefined;
  }
  return {
    approved: true,
    id: part.approval.id,
    isAutomatic: part.approval.isAutomatic,
    reason: part.approval.reason,
  };
}

/** Maps a runtime action request onto its normalized tool descriptor. */
export function normalizeActionRequest(action: RuntimeActionRequest): ActionDescriptor {
  switch (action.kind) {
    case "load-skill":
      return {
        kind: "load-skill",
        name: "load_skill",
        toolName: "kaf:load-skill",
      };
    case "tool-call":
    case "workflow-tool-call":
      return {
        kind: "tool-call",
        name: action.toolName,
        toolName: action.toolName,
      };
    case "subagent-call":
      return {
        kind: "subagent-call",
        name: action.subagentName,
        toolName: `kaf:subagent:${action.subagentName}`,
      };
    case "remote-agent-call":
      return {
        kind: "subagent-call",
        name: action.remoteAgentName,
        toolName: `kaf:subagent:${action.remoteAgentName}`,
      };
  }
}

/** Maps a runtime action result onto its normalized tool descriptor. */
export function normalizeActionResult(result: RuntimeActionResult): ActionDescriptor {
  switch (result.kind) {
    case "load-skill-result":
      return {
        kind: "load-skill",
        name: result.name ?? "load_skill",
        toolName: "kaf:load-skill",
      };
    case "tool-result":
      return {
        kind: "tool-call",
        name: result.toolName,
        toolName: result.toolName,
      };
    case "subagent-result":
      return {
        kind: "subagent-call",
        name: result.subagentName,
        toolName: `kaf:subagent:${result.subagentName}`,
      };
  }
}

/** Best-effort string rendering of an unknown tool output for error display. */
export function stringifyUnknown(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return "Action failed.";
  }
}
