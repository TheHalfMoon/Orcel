import { describe, expect, it } from "vitest";
import { ContextContainer, contextStorage } from "#context/container.js";
import { ConversationIdKey } from "#context/keys.js";
import { readConversationId, resolveConversationId } from "#shared/conversation-identity.js";
import {
  readConversationBaggage,
  writeConversationBaggage,
} from "#tracing/conversation-context.js";

describe("conversation correlation", () => {
  it("round-trips correlation independently of policy baggage", () => {
    const baggage = writeConversationBaggage("orcel.audience=private;ceiling=i0o0", "root/session");
    expect(readConversationBaggage(baggage!)).toBe("root/session");
    expect(baggage).toContain("orcel.audience=private;ceiling=i0o0");
  });

  it("rejects malformed, duplicate, oversized, and unsafe identifiers", () => {
    expect(readConversationBaggage("orcel.conversation.id")).toBeUndefined();
    expect(readConversationBaggage("orcel.conversation.id=%ZZ")).toBeUndefined();
    expect(readConversationBaggage("orcel.conversation.id=a,orcel.conversation.id=b")).toBeUndefined();
    expect(readConversationId("a".repeat(1025))).toBeUndefined();
    expect(readConversationId("a\nb")).toBeUndefined();
    expect(readConversationId("\ud800")).toBeUndefined();
  });

  it.each(["\u0000", "\u001f", "\u007f", "\u0080", "\u009f", "\u2028", "\u2029"])(
    "rejects control or line-separator %j even when percent-encoded",
    (character) => {
      expect(readConversationId(`before${character}after`)).toBeUndefined();
      expect(
        readConversationBaggage(`orcel.conversation.id=${encodeURIComponent(character)}`),
      ).toBeUndefined();
    },
  );

  it("leaves configured baggage unchanged when no valid replacement is available", () => {
    const baggage = "vendor=value, orcel.conversation.id=operator";
    expect(writeConversationBaggage(baggage, undefined)).toBe(baggage);
    expect(writeConversationBaggage(baggage, "\n")).toBe(baggage);
    expect(writeConversationBaggage(baggage, "session")).toBe(
      "vendor=value,orcel.conversation.id=session",
    );
  });

  it("does not derive an established conversation from privileged lineage", () => {
    const ctx = new ContextContainer();
    ctx.set(ConversationIdKey, "original-conversation");
    contextStorage.run(ctx, () => {
      expect(resolveConversationId("independent-remote-root")).toBe("original-conversation");
    });
  });
});
