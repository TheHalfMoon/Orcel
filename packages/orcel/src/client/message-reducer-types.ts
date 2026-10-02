import type { InputRequest, InputResponse } from "#shared/input.js";
import type { AuthorizationOutcome } from "#protocol/message.js";

/**
 * UIMessage-compatible orcel message projection for chat and agent UIs.
 */
export interface OrcelMessageData {
  readonly messages: readonly OrcelMessage[];
}

/**
 * orcel-owned message shape that follows the AI SDK UIMessage convention.
 */
export interface OrcelMessage {
  readonly id: string;
  readonly metadata?: OrcelMessageMetadata;
  readonly parts: readonly OrcelMessagePart[];
  readonly role: "assistant" | "user";
}

/**
 * Per-message metadata attached by the default projection.
 *
 * `status` tracks this message's own lifecycle (distinct from session-level
 * status): user messages use `"submitted"` or `"failed"`, assistant messages
 * use `"streaming"` or `"complete"`. `optimistic` is set only while a
 * client-projected user message awaits server confirmation. `turnId` links the
 * message to its runtime turn; `result` holds the harness structured result
 * once the turn finalizes.
 */
export interface OrcelMessageMetadata {
  readonly optimistic?: true;
  readonly result?: unknown;
  readonly status?: "complete" | "failed" | "streaming" | "submitted";
  readonly turnId?: string;
}

/**
 * One renderable part of an {@link OrcelMessage}, discriminated by `type`.
 *
 * `text` and `reasoning` store streamed content with a `state` of `"streaming"`
 * or `"done"`; `file` carries user-attachment metadata; `step-start` marks the
 * boundary of an agent step; and `dynamic-tool` ({@link OrcelDynamicToolPart})
 * holds the tool call and its lifecycle state. `stepIndex` ties a part to the
 * agent step that produced it.
 */
export type OrcelMessagePart =
  | {
      readonly providerMetadata?: Record<string, unknown>;
      readonly state?: "done" | "streaming";
      readonly stepIndex?: number;
      readonly text: string;
      readonly type: "text";
    }
  | {
      readonly providerMetadata?: Record<string, unknown>;
      readonly state?: "done" | "streaming";
      readonly stepIndex?: number;
      readonly text: string;
      readonly type: "reasoning";
    }
  | {
      readonly filename?: string;
      readonly mediaType: string;
      readonly size?: number;
      readonly stepIndex?: number;
      readonly type: "file";
      readonly url?: string;
    }
  | {
      readonly type: "step-start";
    }
  | OrcelAuthorizationPart
  | OrcelDynamicToolPart;

/**
 * User-facing authorization challenge projected from an
 * `authorization.required` stream event. These fields are safe to render in a
 * browser UI; the model-facing tool output never receives the URL or code.
 */
export interface OrcelAuthorizationChallenge {
  readonly displayName?: string;
  readonly expiresAt?: string;
  readonly instructions?: string;
  readonly url?: string;
  readonly userCode?: string;
}

/**
 * Outcome of a completed user authorization flow.
 */
export type OrcelAuthorizationOutcome = AuthorizationOutcome;

/**
 * An authorization prompt or result. The default reducer projects
 * `authorization.required` into a pending part so browser chat UIs can render a
 * sign-in affordance, then updates it when `authorization.completed` arrives.
 */
export type OrcelAuthorizationPart = {
  readonly authorization?: OrcelAuthorizationChallenge;
  readonly description: string;
  readonly displayName: string;
  readonly name: string;
  readonly stepIndex: number;
  readonly turnId: string;
  readonly type: "authorization";
} & (
  | {
      readonly outcome?: never;
      readonly reason?: never;
      readonly state: "required";
    }
  | {
      readonly outcome: OrcelAuthorizationOutcome;
      readonly reason?: string;
      readonly state: "completed";
    }
);

/**
 * A tool-call part of an assistant message, following the AI SDK `dynamic-tool`
 * convention. `state` advances through the lifecycle: `"input-streaming"` and
 * `"input-available"` (arguments arriving or complete), `"approval-requested"` and
 * `"approval-responded"` (HITL approval pending or answered), then a terminal
 * `"output-available"`, `"output-error"` (`errorText` set), or `"output-denied"`
 * (`approval.approved` is `false`). Which of `input`, `output`, `errorText`, and
 * `approval` are present depends on `state`, so narrow on `state` before reading them.
 * Preliminary generator output uses `"output-available"` with `partial: true`;
 * the terminal tool result clears that flag.
 * `toolName` and `toolMetadata.orcel` ({@link OrcelMessageToolMetadata}) record call identity.
 */
export type OrcelDynamicToolPart = {
  readonly stepIndex?: number;
  readonly toolCallId: string;
  readonly toolMetadata?: OrcelMessageToolMetadata;
  readonly toolName: string;
  readonly type: "dynamic-tool";
} & (
  | {
      readonly approval?: never;
      readonly errorText?: never;
      readonly input: unknown | undefined;
      /** Accumulated raw tool input, which may be incomplete JSON. */
      readonly inputText: string;
      readonly output?: never;
      readonly state: "input-streaming";
    }
  | {
      readonly approval?: never;
      readonly errorText?: never;
      readonly input: unknown;
      readonly output?: never;
      readonly state: "input-available";
    }
  | {
      readonly approval: {
        readonly id: string;
        readonly approved?: never;
        readonly reason?: never;
        readonly isAutomatic?: boolean;
      };
      readonly errorText?: never;
      readonly input: unknown;
      readonly output?: never;
      readonly state: "approval-requested";
    }
  | {
      readonly approval: {
        readonly id: string;
        readonly approved?: boolean;
        readonly reason?: string;
        readonly isAutomatic?: boolean;
      };
      readonly errorText?: never;
      readonly input: unknown;
      readonly output?: never;
      readonly state: "approval-responded";
    }
  | {
      readonly approval?: {
        readonly id: string;
        readonly approved: true;
        readonly reason?: string;
        readonly isAutomatic?: boolean;
      };
      readonly errorText?: never;
      readonly input: unknown;
      readonly output: unknown;
      readonly partial?: true;
      readonly state: "output-available";
    }
  | {
      readonly approval?: {
        readonly id: string;
        readonly approved: true;
        readonly reason?: string;
        readonly isAutomatic?: boolean;
      };
      readonly errorText: string;
      readonly input: unknown | undefined;
      readonly output?: never;
      readonly state: "output-error";
    }
  | {
      readonly approval: {
        readonly id: string;
        readonly approved: false;
        readonly reason?: string;
        readonly isAutomatic?: boolean;
      };
      readonly errorText?: never;
      readonly input: unknown;
      readonly output?: never;
      readonly state: "output-denied";
    }
);

/**
 * orcel-specific metadata attached to an {@link OrcelDynamicToolPart}. `orcel.kind`
 * classifies the action (`"tool-call"`, `"subagent-call"`, `"load-skill"`, or
 * `"unknown"`), `orcel.name` is the resolved action name, and `orcel.inputRequest`
 * and `orcel.inputResponse` store the HITL prompt and submitted response when the
 * call required approval.
 */
export interface OrcelMessageToolMetadata {
  readonly orcel?: {
    readonly inputRequest?: OrcelMessageInputRequest;
    readonly inputResponse?: InputResponse;
    readonly kind: "load-skill" | "subagent-call" | "tool-call" | "unknown";
    readonly name: string;
  };
}

/**
 * UI-facing projection of a pending HITL input request on a tool part. `prompt`
 * is the question, `display` selects the control (`"confirmation"`, `"select"`,
 * or `"text"`), `options` lists selectable choices (each with a `label` and
 * optional `style`), and `allowFreeform` permits a typed response alongside the
 * options. `kind` identifies the framework-owned request source. `requestId`
 * is the stable identifier the client returns in the responding
 * {@link InputResponse}.
 */
export interface OrcelMessageInputRequest {
  readonly allowFreeform?: boolean;
  readonly display?: "confirmation" | "select" | "text";
  readonly kind: InputRequest["kind"];
  readonly options?: readonly {
    readonly description?: string;
    readonly id: string;
    readonly label: string;
    readonly style?: "danger" | "default" | "primary";
  }[];
  readonly prompt: string;
  readonly requestId: string;
}
