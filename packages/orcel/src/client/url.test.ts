import { describe, expect, it } from "vitest";

import { createClientUrl } from "#client/url.js";

describe("createClientUrl", () => {
  it("preserves absolute origins", () => {
    expect(createClientUrl("https://agent.example.com", "/orcel/v1/session")).toBe(
      "https://agent.example.com/orcel/v1/session",
    );
  });

  it("preserves absolute base paths for proxied agents", () => {
    expect(createClientUrl("https://app.example.com/api", "/orcel/v1/session")).toBe(
      "https://app.example.com/api/orcel/v1/session",
    );
  });

  it("maps internal routes onto an absolute compact named-agent mount", () => {
    expect(createClientUrl("https://app.example.com/orcel/support", "/orcel/v1/session")).toBe(
      "https://app.example.com/orcel/support/v1/session",
    );
  });

  it("preserves host query parameters on agent routes", () => {
    expect(
      createClientUrl(
        "https://agent.example.com?x-vercel-protection-bypass=secret",
        "/orcel/v1/session",
      ),
    ).toBe("https://agent.example.com/orcel/v1/session?x-vercel-protection-bypass=secret");
  });

  it("merges route query parameters over host query parameters", () => {
    expect(
      createClientUrl(
        "https://agent.example.com?token=secret&startIndex=stale",
        "/orcel/v1/session/123/stream",
        { startIndex: "4" },
      ),
    ).toBe("https://agent.example.com/orcel/v1/session/123/stream?token=secret&startIndex=4");
  });

  it("supports same-origin proxy prefixes", () => {
    expect(createClientUrl("/api", "/orcel/v1/session")).toBe("/api/orcel/v1/session");
  });

  it("maps internal routes onto a same-origin compact named-agent mount", () => {
    expect(createClientUrl("/orcel/support", "/orcel/v1/session")).toBe("/orcel/support/v1/session");
  });

  it("adds query parameters without forcing an absolute URL", () => {
    expect(createClientUrl("/api", "/orcel/v1/session/123/stream", { startIndex: "4" })).toBe(
      "/api/orcel/v1/session/123/stream?startIndex=4",
    );
  });

  it("preserves query parameters on same-origin proxy prefixes", () => {
    expect(createClientUrl("/api?token=secret", "/orcel/v1/session")).toBe(
      "/api/orcel/v1/session?token=secret",
    );
  });

  it("splits a query string embedded in the route path instead of encoding it", () => {
    expect(
      createClientUrl(
        "https://agent.example.com",
        "/orcel/v1/connections/auth-probe/callback/attempt_1/wrun_1%3Aauth?code=ok",
      ),
    ).toBe(
      "https://agent.example.com/orcel/v1/connections/auth-probe/callback/attempt_1/wrun_1%3Aauth?code=ok",
    );
  });

  it("splits embedded route queries on same-origin proxy prefixes", () => {
    expect(createClientUrl("/api", "/orcel/v1/session/123/stream?startIndex=4")).toBe(
      "/api/orcel/v1/session/123/stream?startIndex=4",
    );
  });

  it("prefers explicit search parameters over embedded route queries", () => {
    expect(
      createClientUrl("https://agent.example.com", "/orcel/v1/session/123/stream?startIndex=stale", {
        startIndex: "4",
      }),
    ).toBe("https://agent.example.com/orcel/v1/session/123/stream?startIndex=4");
  });
});
