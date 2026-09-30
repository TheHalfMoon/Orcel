import { describe, expect, it } from "vitest";

import {
  assertValidVercelServiceName,
  isValidVercelServiceName,
} from "#internal/vercel/vercel-service-name.js";

describe("Vercel service names", () => {
  it("accepts the Vercel Services naming grammar", () => {
    expect(isValidVercelServiceName("kaf-support_agent")).toBe(true);
    expect(isValidVercelServiceName("a".repeat(64))).toBe(true);
  });

  it("rejects digits, invalid boundaries, and names longer than 64 characters", () => {
    expect(isValidVercelServiceName("kaf-agent1")).toBe(false);
    expect(isValidVercelServiceName("-kaf")).toBe(false);
    expect(isValidVercelServiceName("a".repeat(65))).toBe(false);
    expect(() => assertValidVercelServiceName("kaf-agent1", "Service name")).toThrow(
      /Service name/,
    );
  });
});
