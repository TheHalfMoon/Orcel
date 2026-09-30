import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { resolveVersionToken } from "./version-tokens.js";

// These tests always execute from the dev tree (vitest runs over src), so the
// fallback's sources — kaf's package.json and the workspace catalog — are the
// live files the assertions read independently.
const KAF_PACKAGE_JSON_URL = new URL("../../../package.json", import.meta.url);

describe("resolveVersionToken", () => {
  it("returns stamped values untouched", () => {
    expect(resolveVersionToken("connectPackageVersion", "0.2.2")).toBe("0.2.2");
    expect(resolveVersionToken("kafPackage.version", "1.0.0-beta.3")).toBe("1.0.0-beta.3");
  });

  it("resolves kaf runtime and dependency version tokens from kaf's own package.json", () => {
    const runtimeVersion = resolveVersionToken(
      "kafPackage.runtimeVersion",
      "__KAF_PACKAGE_VERSION__",
    );
    const dependencyVersion = resolveVersionToken(
      "kafPackage.version",
      "__KAF_PACKAGE_DEPENDENCY_VERSION__",
    );

    const packageJson = JSON.parse(readFileSync(fileURLToPath(KAF_PACKAGE_JSON_URL), "utf8")) as {
      version: string;
    };
    expect(runtimeVersion).toBe(packageJson.version);
    expect(dependencyVersion).toBe(packageJson.version);
  });

  it("resolves the node engine token from kaf's own package.json engines.node", () => {
    const resolved = resolveVersionToken("nodeEngine", "__NODE_ENGINE__");

    const packageJson = JSON.parse(readFileSync(fileURLToPath(KAF_PACKAGE_JSON_URL), "utf8")) as {
      engines: { node: string };
    };
    expect(resolved).toBe(packageJson.engines.node);
  });

  it("throws the unstamped error for a token with no known source", () => {
    expect(() => resolveVersionToken("somePackageVersion", "__UNKNOWN_VERSION__")).toThrow(
      /unstamped version token \(somePackageVersion=__UNKNOWN_VERSION__\)/,
    );
  });
});
