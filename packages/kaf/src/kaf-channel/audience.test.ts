import { describe, expect, it } from "vitest";

import { defaultKafAudience } from "#kaf-channel/audience.js";
import type { AudienceContext } from "#shared/conversation-context.js";

function input(principalType: string | null): Omit<AudienceContext<undefined>, "state"> {
  return {
    auth:
      principalType === null
        ? null
        : {
            attributes: {},
            authenticator: "test",
            principalType,
          },
    caller:
      principalType === null || principalType === "anonymous"
        ? { type: "anonymous" }
        : {
            type: "principal",
            principal: { attributes: {}, authenticator: "test", kind: principalType },
          },
    channel: { kind: "http" },
    environment: "production",
  };
}

describe("defaultKafAudience", () => {
  it.each([
    [null, "unknown"],
    ["anonymous", "unknown"],
    ["user", "private"],
    ["service", "private"],
    ["runtime", "private"],
    ["app", "unknown"],
  ] as const)("classifies %s as %s", (principalType, audience) => {
    expect(defaultKafAudience(input(principalType))).toBe(audience);
  });
});
