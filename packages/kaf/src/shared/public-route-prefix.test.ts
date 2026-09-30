import { describe, expect, it } from "vitest";

import { normalizePublicRoutePrefix } from "#shared/public-route-prefix.js";

describe("normalizePublicRoutePrefix", () => {
  it("returns undefined for values resolving to the root route", () => {
    expect(normalizePublicRoutePrefix(undefined)).toBeUndefined();
    expect(normalizePublicRoutePrefix("")).toBeUndefined();
    expect(normalizePublicRoutePrefix("   ")).toBeUndefined();
    expect(normalizePublicRoutePrefix("/")).toBeUndefined();
    expect(normalizePublicRoutePrefix("//")).toBeUndefined();
  });

  it("adds the leading slash", () => {
    expect(normalizePublicRoutePrefix("kaf/support")).toBe("/kaf/support");
  });

  it("strips trailing slashes", () => {
    expect(normalizePublicRoutePrefix("/kaf/support/")).toBe("/kaf/support");
    expect(normalizePublicRoutePrefix("/kaf/support//")).toBe("/kaf/support");
  });

  it("keeps an already-normalized prefix unchanged", () => {
    expect(normalizePublicRoutePrefix("/kaf/support")).toBe("/kaf/support");
  });
});
