// CR-02 acceptance: "no approval mutation path in the bundle (static
// check)". The Control Room is a client only: it never mints or answers an
// approval, never runs an MCP server and never opens a listener.

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import * as bundle from "../index.js";
import { READ_METHODS } from "./protocol/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..", "..");

function files(dir: string, suffix: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) return name === "tests" ? [] : files(full, suffix);
    return full.endsWith(suffix) && !full.endsWith(`.test${suffix}`) ? [full] : [];
  });
}

const FORBIDDEN: Array<[RegExp, string]> = [
  [/["'`]approval\.[a-z_]+["'`]/u, "an approval method name"],
  [/resolveApproval|respondToApproval|approveRun|grantApproval|mintApproval/u, "an approval command"],
  [/["'`](task\.(submit|cancel|run)|stop\.request|mcp\.[a-z_]+)["'`]/u, "a mutating method name"],
  [/\bcreateServer\s*\(|\.listen\s*\(/u, "a listener"],
  [/@modelcontextprotocol|McpServer/u, "an MCP server"],
  [/\bspawn\s*\(|\bfork\s*\(/u, "a child process other than whoami"],
  [/allowUnverified|unverifiedTestConnector|UNVERIFIED_PIPE_TEST/u, "the tests' unverified pipe connect (#398)"],
];

test("the shipped bundle has no approval, mutation, listener or MCP path", () => {
  const shipped = [...files(path.join(packageRoot, "src"), ".ts"), ...files(path.join(packageRoot, "dist"), ".js")];
  assert.ok(shipped.length >= 10, "the bundle was found");
  const hits: string[] = [];
  for (const file of shipped) {
    readFileSync(file, "utf8")
      .split(/\r?\n/u)
      .forEach((line, index) => {
        if (/^\s*(\/\/|\*|\/\*)/u.test(line)) return; // comments describe what is absent
        for (const [pattern, what] of FORBIDDEN) {
          if (pattern.test(line)) hits.push(`${path.relative(packageRoot, file)}:${index + 1}: ${what}: ${line.trim()}`);
        }
      });
  }
  assert.deepEqual(hits, []);
});

test("the production build compiles no test support (#398 item 4)", () => {
  const build = JSON.parse(readFileSync(path.join(packageRoot, "tsconfig.build.json"), "utf8")) as {
    extends?: string;
    exclude?: string[];
  };
  assert.equal(build.extends, "./tsconfig.json");
  assert.deepEqual(build.exclude, ["src/tests/**", "src/**/*.test.ts"]);
  const scripts = (
    JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")) as { scripts: Record<string, string> }
  ).scripts;
  assert.equal(scripts.build, "tsc -p tsconfig.build.json");
  // The unverified pipe connector exists only in the excluded test support.
  const unverified = files(path.join(packageRoot, "src"), ".ts").filter((file) =>
    readFileSync(file, "utf8").includes("connectUnverifiedPipe"),
  );
  assert.deepEqual(unverified, []);
  assert.match(
    readFileSync(path.join(packageRoot, "src", "tests", "unverified-pipe.ts"), "utf8"),
    /function connectUnverifiedPipe/u,
  );
});

test("the client's surface is read-only", () => {
  assert.deepEqual([...READ_METHODS], ["status.get", "capabilities.get", "events.subscribe"]);
  const names = Object.getOwnPropertyNames(bundle.ControlRoomClient.prototype);
  for (const name of names) {
    assert.doesNotMatch(name, /approv|submit|cancel|dispatch|mint|grant|resolve|stop[A-Z]|execute|write/iu, name);
  }
  for (const name of Object.keys(bundle)) {
    assert.doesNotMatch(name, /approv|submit|dispatch|mint|grant|^serve|Server$|listen/iu, name);
  }
});

test("the package has no runtime dependencies", () => {
  const manifest = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")) as Record<string, unknown>;
  assert.equal(manifest.dependencies, undefined);
  assert.deepEqual(Object.keys(manifest.devDependencies as object).sort(), ["@types/node", "typescript"]);
});
