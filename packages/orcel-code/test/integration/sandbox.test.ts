import assert from "node:assert/strict";
import test from "node:test";
import type { SandboxSession } from "@orcel/orcel/sandbox";
import { CODE_TOOLING_REVALIDATION_KEY, installCodeTooling } from "../../extension/lib/sandbox.ts";
import { toolingPaths, typescriptInstallCommand } from "../../extension/lib/tooling.ts";
import { shellQuote } from "../../extension/lib/shell.ts";

test("installs trusted GitHub executables, compiler, and diagnostics worker outside the writable workspace", async () => {
  const commands: string[] = [];
  const writes: string[] = [];
  const sandbox: Pick<SandboxSession, "resolvePath" | "run" | "writeTextFile"> = {
    resolvePath(path: string) {
      return `/workspace/${path}`.replace(/\/$/u, "");
    },
    async run({ command }: { command: string }) {
      commands.push(command);
      return { exitCode: 0, stdout: "", stderr: "" };
    },
    async writeTextFile({ path }: { path: string }) {
      writes.push(path);
    },
  };

  await installCodeTooling(sandbox as SandboxSession);

  assert.match(CODE_TOOLING_REVALIDATION_KEY, /orcel-code-tooling:3:/u);
  assert.ok(writes.every((path) => path.startsWith("/workspace/.orcel-code/")));
  assert.match(
    commands[0] ?? "",
    /\$INSTALL -m 755 \/usr\/bin\/gh '\/usr\/local\/lib\/orcel-code\/gh'/u,
  );
  assert.match(
    commands[0] ?? "",
    /\$INSTALL -m 755 '\/workspace\/\.orcel-code\/gh-signed-commit' '\/usr\/local\/lib\/orcel-code\/gh-signed-commit'/u,
  );
  assert.doesNotMatch(commands[0] ?? "", /install -m 755 "\$\(command -v gh\)"/u);
  const command = commands[0] ?? "";
  assert.match(
    command,
    /\$INSTALL -d -o root -g root -m 755 '\/usr\/local\/lib\/orcel-code' '\/usr\/local\/lib\/orcel-code\/typescript'/u,
  );
  assert.match(
    command,
    /\$INSTALL -m 644 '\/workspace\/\.orcel-code\/diagnostics.cjs' '\/usr\/local\/lib\/orcel-code\/diagnostics.cjs'/u,
  );
  assert.match(
    command,
    /sudo -n \/usr\/bin\/env -i HOME=\/root PATH=\/usr\/local\/bin:\/usr\/bin:\/bin/u,
  );
  assert.match(
    command,
    /NPM_CONFIG_USERCONFIG=\/dev\/null NPM_CONFIG_GLOBALCONFIG='\/usr\/local\/lib\/orcel-code\/typescript\/npmrc' NPM_CONFIG_REGISTRY=https:\/\/registry.npmjs.org/u,
  );
  assert.match(command, /umask 022/u);
  assert.match(command, /--ignore-scripts --no-audit --no-fund typescript@6\.0\.3/u);
  assert.match(command, /chmod -R go-w/u);
  assert.doesNotMatch(command, /\/workspace\/\.orcel-code\/typescript/u);
  const paths = toolingPaths(sandbox);
  assert.equal(paths.worker, "/usr/local/lib/orcel-code/diagnostics.cjs");
  assert.equal(
    paths.typescriptModule,
    "/usr/local/lib/orcel-code/typescript/node_modules/typescript/lib/typescript.js",
  );
  const install = typescriptInstallCommand(sandbox);
  assert.ok(install.includes(shellQuote(`cd ${shellQuote(paths.typescriptRoot)}`).slice(1, -1)));
});

test("tooling installation fails rather than caching an incomplete bootstrap", async () => {
  await assert.rejects(
    installCodeTooling({
      resolvePath: (path) => `/workspace/${path}`,
      async writeTextFile() {},
      async run() {
        return { exitCode: 1, stdout: "", stderr: "trusted compiler install failed" };
      },
    }),
    /tooling installation failed \(exit 1\): stderr:\ntrusted compiler install failed/u,
  );
});
