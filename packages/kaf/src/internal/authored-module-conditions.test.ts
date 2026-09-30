import { afterEach, describe, expect, it, vi } from "vitest";

import { authoredModuleConditions } from "./authored-module-conditions.js";

describe("authoredModuleConditions", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("leaves ordinary builds on kaf's source condition", () => {
    expect(authoredModuleConditions(["--enable-source-maps"], "")).toEqual(["kaf-source"]);
  });

  it.each([
    ["--conditions=react-server"],
    ["--conditions", "react-server"],
    ["-C", "react-server"],
  ])("preserves command-line conditions %j", (...args) => {
    expect(authoredModuleConditions(args, "")).toEqual(["kaf-source", "react-server"]);
  });

  it("reads quoted NODE_OPTIONS from the environment and combines repeated conditions", () => {
    vi.stubEnv(
      "NODE_OPTIONS",
      '--conditions="react-server" --require "./path with spaces/preload.js" -C "custom condition"',
    );
    expect(authoredModuleConditions(["--conditions=react-server", "-C", "custom"])).toEqual([
      "kaf-source",
      "react-server",
      "custom condition",
      "custom",
    ]);
  });

  it("preserves escaped quotes in NODE_OPTIONS", () => {
    expect(authoredModuleConditions([], '--conditions="custom\\"condition"')).toEqual([
      "kaf-source",
      'custom"condition',
    ]);
  });

  it("leaves standard condition selection to each bundler import edge", () => {
    expect(
      authoredModuleConditions(
        [
          "--conditions=import",
          "--conditions=require",
          "--conditions=node",
          "--conditions=default",
          "--conditions=browser",
        ],
        "",
      ),
    ).toEqual(["kaf-source"]);
  });
});
