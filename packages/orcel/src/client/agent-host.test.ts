import { describe, expect, it } from "vitest";

import { resolveOrcelAgentHost } from "#client/agent-host.js";

describe("resolveOrcelAgentHost", () => {
  it("defaults to same-origin root orcel routes", () => {
    expect(resolveOrcelAgentHost({})).toBe("");
  });

  it("preserves explicit hosts", () => {
    expect(resolveOrcelAgentHost({ host: "/api" })).toBe("/api");
  });

  it("maps a named agent to the same-origin named route prefix", () => {
    expect(resolveOrcelAgentHost({ agent: "support" })).toBe("/orcel/support");
  });

  it("rejects host and agent together", () => {
    expect(() => resolveOrcelAgentHost({ agent: "support", host: "/api" })).toThrow(
      "cannot combine agent and host",
    );
  });

  it("rejects names that are not safe route segments", () => {
    expect(() => resolveOrcelAgentHost({ agent: "Support" })).toThrow("orcel agent name");
  });
});
