import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { useScenarioApp } from "#internal/testing/scenario-app.js";

const runFile = promisify(execFile);
const scenarioApp = useScenarioApp();

const PACKED_CONSUMER_PROBE = `
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

const consumerRequire = createRequire(import.meta.url);
const consumerManifest = consumerRequire("./package.json");
const kafManifestPath = consumerRequire.resolve("kaf/package.json");
const kafManifest = consumerRequire(kafManifestPath);
const kafRequire = createRequire(kafManifestPath);
const nitroManifest = kafRequire("nitro/package.json");
const wrapperPath = join(
  dirname(kafManifestPath),
  "dist/src/internal/bundler/nitro-rolldown.js",
);
const { buildWithNitroRolldown, parseWithNitroRolldownAst } = await import(
  pathToFileURL(wrapperPath).href
);

const ast = await parseWithNitroRolldownAst(
  "entry.ts",
  "export const parsedAnswer: number = 42;",
);
const build = await buildWithNitroRolldown({
  input: "virtual:entry.js",
  output: { format: "esm" },
  plugins: [
    {
      name: "packed-consumer-entry",
      resolveId(id) {
        return id === "virtual:entry.js" ? id : null;
      },
      load(id) {
        return id === "virtual:entry.js" ? "export const bundledAnswer = 42;" : null;
      },
    },
  ],
  write: false,
});
const chunk = build.output.find((entry) => entry.type === "chunk");

console.log(
  JSON.stringify({
    bundled: chunk?.code.includes("bundledAnswer") === true,
    consumerDeclaresRolldown: typeof consumerManifest.dependencies?.rolldown === "string",
    kafDeclaresRolldown: typeof kafManifest.dependencies?.rolldown === "string",
    nitroDeclaresRolldown: typeof nitroManifest.dependencies?.rolldown === "string",
    parsed:
      ast?.type === "Program" &&
      Array.isArray(ast.body) &&
      ast.body[0]?.type === "ExportNamedDeclaration",
  }),
);
`;

describe("packed Nitro Rolldown wrapper", () => {
  it("builds and parses from Nitro's dependency tree without consumer-owned Rolldown", async () => {
    const app = await scenarioApp({
      files: {
        "probe.mjs": PACKED_CONSUMER_PROBE,
      },
      installDependencies: true,
      name: "packed-nitro-rolldown",
      packageManager: "npm",
    });

    const { stdout } = await runFile(process.execPath, ["probe.mjs"], {
      cwd: app.appRoot,
      maxBuffer: 10 * 1024 * 1024,
    });

    expect(JSON.parse(stdout.trim())).toEqual({
      bundled: true,
      consumerDeclaresRolldown: false,
      kafDeclaresRolldown: false,
      nitroDeclaresRolldown: true,
      parsed: true,
    });
  }, 120_000);
});
