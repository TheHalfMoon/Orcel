import { describe, expect, it } from "vitest";

import { createRemoteAgentRouteUrl } from "#subagents/remote-route-url.js";

describe("createRemoteAgentRouteUrl", () => {
  it("preserves a mounted remote agent base path", () => {
    expect(
      createRemoteAgentRouteUrl(
        "https://remote.example/orcel/researcher",
        "/orcel/v1/task-input/capability",
      ),
    ).toBe("https://remote.example/orcel/researcher/v1/task-input/capability");
  });
});
