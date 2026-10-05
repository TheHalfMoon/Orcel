import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

describe("extension orcel peer compatibility", () => {
  it.each(["0.24.6", "0.25.0-beta.1"])(
    "installs with orcel %s under npm strict peer checks",
    async (orcelVersion) => {
      const root = await mkdtemp(join(tmpdir(), "orcel-extension-peer-"));
      roots.push(root);
      const orcelRoot = join(root, "orcel-package");
      const extensionRoot = join(root, "extension-package");
      const appRoot = join(root, "app");
      await Promise.all([mkdir(orcelRoot), mkdir(extensionRoot), mkdir(appRoot)]);
      await Promise.all([
        writePackageJson(orcelRoot, { name: "@orcel/orcel", version: orcelVersion }),
        writePackageJson(extensionRoot, {
          name: "@acme/extension-peer-test",
          version: "1.0.0",
          peerDependencies: { "@orcel/orcel": "*" },
        }),
        writePackageJson(appRoot, { name: "consumer", version: "1.0.0", private: true }),
      ]);

      await Promise.all([
        runNpm(["pack", "--pack-destination", root], orcelRoot),
        runNpm(["pack", "--pack-destination", root], extensionRoot),
      ]);
      await runNpm(
        [
          "install",
          "--strict-peer-deps",
          "--ignore-scripts",
          "--no-audit",
          "--no-package-lock",
          join(root, `orcel-orcel-${orcelVersion}.tgz`),
          join(root, "acme-extension-peer-test-1.0.0.tgz"),
        ],
        appRoot,
      );

      const installed = JSON.parse(
        await readFile(join(appRoot, "node_modules", "@orcel", "orcel", "package.json"), "utf8"),
      ) as { version?: string };
      expect(installed.version).toBe(orcelVersion);
    },
  );
});

async function writePackageJson(root: string, value: Record<string, unknown>): Promise<void> {
  await writeFile(join(root, "package.json"), `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function runNpm(arguments_: readonly string[], cwd: string): Promise<void> {
  await promisify(execFile)(process.platform === "win32" ? "npm.cmd" : "npm", [...arguments_], {
    cwd,
  });
}
