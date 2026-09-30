import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildSessionAttributes,
  buildSubagentRootAttributes,
  deriveSessionTitle,
  KAF_SESSION_TITLE_MAX_CHARS,
  isWorkflowTraceContentVisible,
  readChannelKind,
  readChannelRequestId,
  readParentLineage,
  readParentSessionId,
  readRootSessionId,
  readScheduleId,
  readSessionTraceId,
} from "#execution/kaf-workflow-attributes.js";
import {
  ChannelInstrumentationKey,
  ChannelRequestIdKey,
  ScheduleIdKey,
  SessionTitleKey,
  SessionTraceSeedKey,
} from "#context/keys.js";
import { CHANNEL_CONTEXT_KEY_NAME } from "#context/key-names.js";
import { ConversationContextKey } from "#shared/conversation-context.js";

const publicConversation = {
  audience: "public",
  channel: { kind: "channel:slack", name: "slack" },
  environment: "production",
  principalType: "anonymous",
} as const;

const unknownConversation = {
  audience: "unknown",
  channel: { kind: "http" },
  environment: "production",
  principalType: "anonymous",
} as const;

const slackChannelCtx = {
  "kaf.channel": { kind: "slack", state: { team: "T1" } },
  [ConversationContextKey.name]: publicConversation,
  [SessionTitleKey.name]: "ship the thing please",
} satisfies Record<string, unknown>;

const subagentChainCtx = {
  "kaf.channel": { kind: "slack", state: {} },
  [ConversationContextKey.name]: publicConversation,
  "kaf.parentSession": {
    callId: "call_subagent_0",
    sessionId: "wrun_parent_subagent",
    rootSessionId: "wrun_top_level_session",
    turn: { id: "turn_0", sequence: 0 },
  },
} satisfies Record<string, unknown>;

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("readChannelKind", () => {
  it("returns the channel kind when the slot is well-formed", () => {
    expect(readChannelKind(slackChannelCtx)).toBe("slack");
  });

  it("returns undefined when the slot is missing or malformed", () => {
    expect(readChannelKind({})).toBeUndefined();
    expect(readChannelKind({ "kaf.channel": { kind: "" } })).toBeUndefined();
    expect(readChannelKind({ "kaf.channel": { kind: 42 } })).toBeUndefined();
  });
});

describe("readScheduleId", () => {
  it("reads only a non-empty schedule name", () => {
    expect(readScheduleId({ [ScheduleIdKey.name]: "dynamic-tasks" })).toBe("dynamic-tasks");
    expect(readScheduleId({ [ScheduleIdKey.name]: "" })).toBeUndefined();
    expect(readScheduleId({ [ScheduleIdKey.name]: 42 })).toBeUndefined();
  });
});

describe("isWorkflowTraceContentVisible", () => {
  it("reads audience from the shared serialized conversation slot", () => {
    expect(
      isWorkflowTraceContentVisible({ [ConversationContextKey.name]: publicConversation }),
    ).toBe(true);
  });

  it("uses the effective decision from a forwarded trace seed", () => {
    const serializedContext = {
      [ConversationContextKey.name]: unknownConversation,
      [SessionTraceSeedKey.name]: {
        decision: { action: "record", recordInputs: true, recordOutputs: true },
        forwardedTracePolicy: {
          ceiling: { recordInputs: true, recordOutputs: true },
          originAudience: "public",
        },
        spanId: "1".repeat(16),
        traceFlags: 1,
        traceId: "2".repeat(32),
      },
      [ChannelInstrumentationKey.name]: { kind: "kaf", metadata: {} },
    };

    expect(isWorkflowTraceContentVisible(serializedContext)).toBe(true);
    expect(buildSessionAttributes({ serializedContext })).toMatchObject({
      "$kaf.is_trace_content_visible": true,
    });
  });

  it("uses the inherited decision for a verified local subagent", () => {
    const serializedContext = {
      [CHANNEL_CONTEXT_KEY_NAME]: { audience: "unknown", kind: "agent/local" },
      [SessionTraceSeedKey.name]: {
        decision: { action: "record", recordInputs: true, recordOutputs: true },
        spanId: "1".repeat(16),
        traceFlags: 1,
        traceId: "2".repeat(32),
      },
      "kaf.parentSession": {
        callId: "call-1",
        rootSessionId: "root-session",
        sessionId: "parent-session",
        turn: { id: "turn-1", sequence: 0 },
      },
    };

    expect(isWorkflowTraceContentVisible(serializedContext)).toBe(true);
    expect(
      buildSubagentRootAttributes({
        identity: { nodeId: "subagents/general" },
        parentCallId: "call-1",
        parentSessionId: "parent-session",
        parentTurnId: "turn-1",
        rootSessionId: "root-session",
        serializedContext,
      }),
    ).toMatchObject({
      "$kaf.is_trace_content_visible": true,
    });
  });

  it("does not trust an unbound serialized trace decision", () => {
    expect(
      isWorkflowTraceContentVisible({
        [CHANNEL_CONTEXT_KEY_NAME]: { audience: "unknown", kind: "http" },
        [SessionTraceSeedKey.name]: {
          decision: { action: "record", recordInputs: true, recordOutputs: true },
          spanId: "1".repeat(16),
          traceFlags: 1,
          traceId: "2".repeat(32),
        },
      }),
    ).toBe(false);
  });

  it("does not infer forwarded acceptance from projected metadata", () => {
    const serializedContext = {
      [ConversationContextKey.name]: unknownConversation,
      [ChannelInstrumentationKey.name]: { kind: "kaf", metadata: {} },
    };

    expect(isWorkflowTraceContentVisible(serializedContext)).toBe(false);
    expect(buildSessionAttributes({ serializedContext })).toMatchObject({
      "$kaf.is_trace_content_visible": false,
    });
  });

  it("keeps workflow content hidden for a directional forwarded ceiling", () => {
    const serializedContext = {
      [CHANNEL_CONTEXT_KEY_NAME]: { audience: "private", kind: "kaf" },
      [SessionTraceSeedKey.name]: {
        decision: { action: "record", recordInputs: false, recordOutputs: true },
        forwardedTracePolicy: {
          ceiling: { recordInputs: false, recordOutputs: true },
          originAudience: "private",
        },
        spanId: "1".repeat(16),
        traceFlags: 1,
        traceId: "2".repeat(32),
      },
    };

    expect(isWorkflowTraceContentVisible(serializedContext)).toBe(false);
    expect(buildSessionAttributes({ serializedContext })).toMatchObject({
      "$kaf.is_trace_content_visible": false,
    });
  });

  it("keeps workflow content hidden for malformed forwarded seed state", () => {
    expect(
      isWorkflowTraceContentVisible({
        [CHANNEL_CONTEXT_KEY_NAME]: { audience: "public", kind: "kaf" },
        [SessionTraceSeedKey.name]: {
          decision: { action: "record", recordInputs: true, recordOutputs: true },
          forwardedTracePolicy: { originAudience: "public" },
          spanId: "1".repeat(16),
          traceFlags: 1,
          traceId: "2".repeat(32),
        },
      }),
    ).toBe(false);
  });
});

describe("readParentSessionId", () => {
  it("returns the immediate parent's session id", () => {
    expect(readParentSessionId(subagentChainCtx)).toBe("wrun_parent_subagent");
  });

  it("returns undefined for top-level runs", () => {
    expect(readParentSessionId({})).toBeUndefined();
  });
});

describe("readParentLineage", () => {
  it("returns the parent session, call, turn, and root ids", () => {
    expect(readParentLineage(subagentChainCtx)).toEqual({
      callId: "call_subagent_0",
      rootSessionId: "wrun_top_level_session",
      sessionId: "wrun_parent_subagent",
      turnId: "turn_0",
    });
  });

  it("returns an empty object for top-level runs", () => {
    expect(readParentLineage({})).toEqual({});
  });
});

describe("readRootSessionId", () => {
  it("reads the denormalized rootSessionId the parent carries", () => {
    expect(readRootSessionId(subagentChainCtx)).toBe("wrun_top_level_session");
  });

  it("returns undefined for top-level runs", () => {
    expect(readRootSessionId({})).toBeUndefined();
  });

  it("returns undefined when a malformed parent omits the root", () => {
    expect(
      readRootSessionId({
        "kaf.parentSession": {
          sessionId: "wrun_parent",
          turn: { id: "turn_0", sequence: 0 },
        },
      }),
    ).toBeUndefined();
  });
});

describe("readChannelRequestId", () => {
  it("returns the channel request id when the context slot is well-formed", () => {
    expect(
      readChannelRequestId({
        [ChannelRequestIdKey.name]: "req_123",
      }),
    ).toBe("req_123");
  });

  it("returns undefined when the slot is missing or malformed", () => {
    expect(readChannelRequestId({})).toBeUndefined();
    expect(readChannelRequestId({ [ChannelRequestIdKey.name]: "" })).toBeUndefined();
    expect(readChannelRequestId({ [ChannelRequestIdKey.name]: 42 })).toBeUndefined();
  });
});

describe("deriveSessionTitle", () => {
  it("collapses whitespace and trims plain string messages", () => {
    expect(deriveSessionTitle("  hello\n\nworld   ")).toBe("hello world");
  });

  it("joins the text parts of a multimodal UserContent array", () => {
    const message = [
      { type: "text", text: "look at" },
      { type: "image", image: "https://example.com/a.png" },
      { type: "text", text: "this" },
    ];
    expect(deriveSessionTitle(message)).toBe("look at this");
  });

  it("returns undefined when no plain-text content is available", () => {
    expect(deriveSessionTitle(undefined)).toBeUndefined();
    expect(deriveSessionTitle("")).toBeUndefined();
    expect(deriveSessionTitle([{ type: "image", image: "https://x" }])).toBeUndefined();
  });

  it("truncates long titles to the max code points with a trailing ellipsis", () => {
    const title = deriveSessionTitle("x".repeat(KAF_SESSION_TITLE_MAX_CHARS + 120));
    expect(title).toBeDefined();
    expect(Array.from(title!).length).toBe(KAF_SESSION_TITLE_MAX_CHARS);
    expect(title!.endsWith("…")).toBe(true);
  });

  it("never splits a surrogate pair at the truncation boundary", () => {
    // (max - 1) leading chars + an emoji that would land on the last slot.
    const leading = "x".repeat(KAF_SESSION_TITLE_MAX_CHARS - 1);
    const title = deriveSessionTitle(`${leading}🚀tail`);
    expect(title).toBe(`${leading}…`);
  });
});

describe("buildSessionAttributes", () => {
  it("emits type=session with trigger and stored title", () => {
    const attrs = buildSessionAttributes({
      serializedContext: slackChannelCtx,
    });

    expect(attrs).toEqual({
      "$kaf.channel_request_id": undefined,
      "$kaf.is_otel_trace_enabled": false,
      "$kaf.is_trace_content_visible": true,
      "$kaf.schedule": undefined,
      "$kaf.trace_id": undefined,
      "$kaf.type": "session",
      "$kaf.trigger": "slack",
      "$kaf.title": "ship the thing please",
    });
  });

  it("omits the title when the root context has none", () => {
    expect(buildSessionAttributes({ serializedContext: {} })["$kaf.title"]).toBeUndefined();
  });

  it("marks unknown sessions denied while retaining their stored title", () => {
    const attrs = buildSessionAttributes({
      serializedContext: { [SessionTitleKey.name]: "hi" },
    });

    expect(attrs["$kaf.trigger"]).toBeUndefined();
    expect(attrs["$kaf.is_trace_content_visible"]).toBe(false);
    expect(attrs["$kaf.is_otel_trace_enabled"]).toBe(false);
    expect(attrs["$kaf.title"]).toBe("hi");
  });

  it("stamps hosted OTEL enablement without suppressing the stored title", () => {
    const attrs = buildSessionAttributes({
      serializedContext: {
        "kaf.otelTraceEnabled": true,
        [SessionTitleKey.name]: "private prompt",
      },
    });

    expect(attrs["$kaf.is_otel_trace_enabled"]).toBe(true);
    expect(attrs["$kaf.is_trace_content_visible"]).toBe(false);
    expect(attrs["$kaf.title"]).toBe("private prompt");
  });

  it("allows unknown session content in development", () => {
    const attrs = buildSessionAttributes({
      serializedContext: {
        [ConversationContextKey.name]: { ...unknownConversation, environment: "development" },
        [SessionTitleKey.name]: "local prompt",
      },
    });

    expect(attrs["$kaf.is_trace_content_visible"]).toBe(true);
    expect(attrs["$kaf.title"]).toBe("local prompt");
  });

  it("emits the channel request id when present", () => {
    const attrs = buildSessionAttributes({
      serializedContext: {
        ...slackChannelCtx,
        [ChannelRequestIdKey.name]: "req_session",
      },
    });

    expect(attrs["$kaf.channel_request_id"]).toBe("req_session");
  });

  it("emits the schedule while retaining the target channel trigger", () => {
    const attrs = buildSessionAttributes({
      serializedContext: {
        ...slackChannelCtx,
        [ScheduleIdKey.name]: "dynamic-tasks",
      },
    });

    expect(attrs["$kaf.schedule"]).toBe("dynamic-tasks");
    expect(attrs["$kaf.trigger"]).toBe("slack");
  });

  it("emits $kaf.trace_id from a sampled trace seed", () => {
    const attrs = buildSessionAttributes({
      serializedContext: {
        ...slackChannelCtx,
        "kaf.sessionTraceSeed": { spanId: "a".repeat(16), traceFlags: 1, traceId: "b".repeat(32) },
      },
    });

    expect(attrs["$kaf.trace_id"]).toBe("b".repeat(32));
  });

  it("withholds $kaf.trace_id from an unsampled trace seed", () => {
    const attrs = buildSessionAttributes({
      serializedContext: {
        ...slackChannelCtx,
        "kaf.sessionTraceSeed": { spanId: "a".repeat(16), traceFlags: 0, traceId: "b".repeat(32) },
      },
    });

    expect(attrs["$kaf.trace_id"]).toBeUndefined();
  });
});

describe("buildSubagentRootAttributes", () => {
  it("emits type=subagent with parent, root session, subagent node, and trigger", () => {
    const attrs = buildSubagentRootAttributes({
      identity: { nodeId: "subagents/linear" },
      parentCallId: "call_subagent_0",
      parentSessionId: "wrun_parent_subagent",
      parentTurnId: "turn_0",
      rootSessionId: "wrun_top_level_session",
      serializedContext: subagentChainCtx,
    });

    expect(attrs).toEqual({
      "$kaf.channel_request_id": undefined,
      "$kaf.is_otel_trace_enabled": false,
      "$kaf.is_trace_content_visible": true,
      "$kaf.trace_id": undefined,
      "$kaf.type": "subagent",
      "$kaf.parent": "wrun_parent_subagent",
      "$kaf.parent_call": "call_subagent_0",
      "$kaf.parent_turn": "turn_0",
      "$kaf.root": "wrun_top_level_session",
      "$kaf.subagent": "subagents/linear",
      "$kaf.trigger": "slack",
    });
  });

  it("emits the channel request id when present", () => {
    const attrs = buildSubagentRootAttributes({
      identity: { nodeId: "subagents/linear" },
      parentSessionId: "wrun_parent_subagent",
      rootSessionId: "wrun_top_level_session",
      serializedContext: {
        ...subagentChainCtx,
        [ChannelRequestIdKey.name]: "req_subagent",
      },
    });

    expect(attrs["$kaf.channel_request_id"]).toBe("req_subagent");
  });

  it("emits $kaf.trace_id from a sampled trace seed", () => {
    const attrs = buildSubagentRootAttributes({
      identity: { nodeId: "subagents/linear" },
      parentCallId: "call_subagent_0",
      parentSessionId: "wrun_parent_subagent",
      parentTurnId: "turn_0",
      rootSessionId: "wrun_top_level_session",
      serializedContext: {
        ...subagentChainCtx,
        "kaf.sessionTraceSeed": { spanId: "e".repeat(16), traceFlags: 1, traceId: "f".repeat(32) },
      },
    });

    expect(attrs["$kaf.trace_id"]).toBe("f".repeat(32));
  });
});

describe("readSessionTraceId", () => {
  it("returns the trace id from a sampled seed", () => {
    expect(
      readSessionTraceId({
        "kaf.sessionTraceSeed": { spanId: "a".repeat(16), traceFlags: 1, traceId: "b".repeat(32) },
      }),
    ).toBe("b".repeat(32));
  });

  it("returns undefined for an unsampled seed", () => {
    expect(
      readSessionTraceId({
        "kaf.sessionTraceSeed": { spanId: "a".repeat(16), traceFlags: 0, traceId: "b".repeat(32) },
      }),
    ).toBeUndefined();
  });

  it("returns undefined when a malformed durable decision resolves to drop", () => {
    expect(
      readSessionTraceId({
        "kaf.sessionTraceSeed": {
          decision: { action: "record", recordInputs: "yes", recordOutputs: true },
          spanId: "a".repeat(16),
          traceFlags: 1,
          traceId: "b".repeat(32),
        },
      }),
    ).toBeUndefined();
  });

  it("returns undefined when no seed is present", () => {
    expect(readSessionTraceId({})).toBeUndefined();
  });
});
