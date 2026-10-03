import { describe, expect, it } from "vitest";

import { joinOrcelRoutePath, normalizePublicOrcelRoutePath } from "#shared/orcel-route-path.js";

describe("joinOrcelRoutePath", () => {
  it("maps an internal route onto a compact named-agent mount", () => {
    expect(joinOrcelRoutePath("/orcel/support", "/orcel/v1/session")).toBe("/orcel/support/v1/session");
  });

  it("appends an internal route to ordinary mounts unchanged", () => {
    expect(joinOrcelRoutePath("/api/support", "/orcel/v1/session")).toBe("/api/support/orcel/v1/session");
  });

  it("does not duplicate the protocol base", () => {
    expect(joinOrcelRoutePath("/orcel/support/v1", "/orcel/v1/session")).toBe("/orcel/support/v1/session");
  });
});

describe("normalizePublicOrcelRoutePath", () => {
  it("maps a compact named-agent route to its internal route", () => {
    expect(normalizePublicOrcelRoutePath("/orcel/support/v1/callback/token")).toBe(
      "/orcel/v1/callback/token",
    );
  });

  it("preserves ordinary and internal routes", () => {
    expect(normalizePublicOrcelRoutePath("/api/support/v1/callback/token")).toBe(
      "/api/support/v1/callback/token",
    );
    expect(normalizePublicOrcelRoutePath("/orcel/v1/callback/token")).toBe("/orcel/v1/callback/token");
  });
});
