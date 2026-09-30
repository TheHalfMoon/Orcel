import { describe, expect, it } from "vitest";

import { joinKafRoutePath, normalizePublicKafRoutePath } from "#shared/kaf-route-path.js";

describe("joinKafRoutePath", () => {
  it("maps an internal route onto a compact named-agent mount", () => {
    expect(joinKafRoutePath("/kaf/support", "/kaf/v1/session")).toBe("/kaf/support/v1/session");
  });

  it("appends an internal route to ordinary mounts unchanged", () => {
    expect(joinKafRoutePath("/api/support", "/kaf/v1/session")).toBe("/api/support/kaf/v1/session");
  });

  it("does not duplicate the protocol base", () => {
    expect(joinKafRoutePath("/kaf/support/v1", "/kaf/v1/session")).toBe("/kaf/support/v1/session");
  });
});

describe("normalizePublicKafRoutePath", () => {
  it("maps a compact named-agent route to its internal route", () => {
    expect(normalizePublicKafRoutePath("/kaf/support/v1/callback/token")).toBe(
      "/kaf/v1/callback/token",
    );
  });

  it("preserves ordinary and internal routes", () => {
    expect(normalizePublicKafRoutePath("/api/support/v1/callback/token")).toBe(
      "/api/support/v1/callback/token",
    );
    expect(normalizePublicKafRoutePath("/kaf/v1/callback/token")).toBe("/kaf/v1/callback/token");
  });
});
