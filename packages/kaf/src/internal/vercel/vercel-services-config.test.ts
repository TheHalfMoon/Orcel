import { describe, expect, it } from "vitest";

import {
  createServiceConfigRecord,
  parseVercelServicesConfig,
} from "#internal/vercel/vercel-services-config.js";

describe("parseVercelServicesConfig", () => {
  it("normalizes named service arrays", () => {
    const config = parseVercelServicesConfig(
      { services: [{ name: "kaf", framework: "kaf", root: "agent" }] },
      "vercel.json",
    );
    expect(createServiceConfigRecord(config.services)).toEqual({
      kaf: { framework: "kaf", root: "agent" },
    });
  });

  it("rejects duplicate names in service arrays", () => {
    expect(() =>
      createServiceConfigRecord([
        { framework: "nextjs", name: "web" },
        { framework: "nuxtjs", name: "web" },
      ]),
    ).toThrow('Duplicate Vercel service name "web".');
  });

  it.each([
    [null, /must contain a JSON object/],
    [{ services: null }, /services must be a JSON object or named service array/],
    [{ services: { kaf: null } }, /service "kaf" must contain a JSON object/],
    [{ services: [{}] }, /must have a non-empty name/],
    [{ services: { kaf: { framework: 42 } } }, /framework must be a string/],
    [{ services: { kaf: { mount: false } } }, /mount must be a string or JSON object/],
    [{ services: { kaf: { outputDirectory: 42 } } }, /outputDirectory must be a string/],
    [{ services: { kaf: { routes: {} } } }, /routes must be an array/],
    [{ routes: {} }, /routes must be an array/],
    [{ routes: [{ destination: 42 }] }, /destination must be a string or JSON object/],
  ])("rejects malformed configuration %#", (value, expected) => {
    expect(() => parseVercelServicesConfig(value, "vercel.json")).toThrow(expected);
  });
});
