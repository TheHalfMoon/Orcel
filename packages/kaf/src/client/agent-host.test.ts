import { describe, expect, it } from "vitest";

import { resolveKafAgentHost } from "#client/agent-host.js";

describe("resolveKafAgentHost", () => {
  it("defaults to same-origin root kaf routes", () => {
    expect(resolveKafAgentHost({})).toBe("");
  });

  it("preserves explicit hosts", () => {
    expect(resolveKafAgentHost({ host: "/api" })).toBe("/api");
  });

  it("maps a named agent to the same-origin named route prefix", () => {
    expect(resolveKafAgentHost({ agent: "support" })).toBe("/kaf/support");
  });

  it("rejects host and agent together", () => {
    expect(() => resolveKafAgentHost({ agent: "support", host: "/api" })).toThrow(
      "cannot combine agent and host",
    );
  });

  it("rejects names that are not safe route segments", () => {
    expect(() => resolveKafAgentHost({ agent: "Support" })).toThrow("kaf agent name");
  });
});
