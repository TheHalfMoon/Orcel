import { describe, expect, it } from "vitest";

import { toChannelLocalContinuationToken } from "#shared/continuation-token.js";

describe("toChannelLocalContinuationToken", () => {
  it("removes only the runtime channel namespace", () => {
    expect(toChannelLocalContinuationToken("slack:C1:T1")).toBe("C1:T1");
    expect(toChannelLocalContinuationToken("kaf:kaf:token")).toBe("kaf:token");
  });

  it("preserves an unnamespaced token", () => {
    expect(toChannelLocalContinuationToken("token")).toBe("token");
  });
});
