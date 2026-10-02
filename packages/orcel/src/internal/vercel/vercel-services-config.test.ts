import { describe, expect, it } from "vitest";

import {
  createServiceConfigRecord,
  parseVercelServicesConfig,
} from "#internal/vercel/vercel-services-config.js";

describe("parseVercelServicesConfig", () => {
  it("normalizes named service arrays", () => {
    const config = parseVercelServicesConfig(
      { services: [{ name: "orcel", framework: "eve", root: "agent" }] },
      "vercel.json",
    );
    expect(createServiceConfigRecord(config.services)).toEqual({
      orcel: { framework: "eve", root: "agent" },
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
    [{ services: { orcel: null } }, /service "orcel" must contain a JSON object/],
    [{ services: [{}] }, /must have a non-empty name/],
    [{ services: { orcel: { framework: 42 } } }, /framework must be a string/],
    [{ services: { orcel: { mount: false } } }, /mount must be a string or JSON object/],
    [{ services: { orcel: { outputDirectory: 42 } } }, /outputDirectory must be a string/],
    [{ services: { orcel: { routes: {} } } }, /routes must be an array/],
    [{ routes: {} }, /routes must be an array/],
    [{ routes: [{ destination: 42 }] }, /destination must be a string or JSON object/],
  ])("rejects malformed configuration %#", (value, expected) => {
    expect(() => parseVercelServicesConfig(value, "vercel.json")).toThrow(expected);
  });
});
