import { describe, expect, it, vi } from "vitest";

import { ensureBuiltCli, runOrcelCli } from "../bin/orcel.js";

const bootstrapOptions = {
  cliEntrypointPath: "/workspace/packages/orcel/dist/src/cli/run.js",
  packageRoot: "/workspace/packages/orcel",
  postBuildScriptPaths: [
    "/workspace/packages/orcel/scripts/copy-compiled-assets.mjs",
    "/workspace/packages/orcel/scripts/copy-docs.mjs",
    "/workspace/packages/orcel/scripts/stamp-version-tokens.mjs",
  ],
  tscCliPath: "/workspace/node_modules/typescript/bin/tsc",
};
const workspaceBuildInputPaths = new Set([
  ...bootstrapOptions.postBuildScriptPaths,
  `${bootstrapOptions.packageRoot}/bin`,
  `${bootstrapOptions.packageRoot}/src`,
  `${bootstrapOptions.packageRoot}/scripts/vendor-compiled.mjs`,
  `${bootstrapOptions.packageRoot}/tsconfig.json`,
]);
const workspaceBuildCommands = [
  [
    process.execPath,
    [`${bootstrapOptions.packageRoot}/scripts/vendor-compiled.mjs`],
    { cwd: bootstrapOptions.packageRoot },
  ],
  [
    process.execPath,
    [bootstrapOptions.tscCliPath, "-p", "tsconfig.json"],
    { cwd: bootstrapOptions.packageRoot },
  ],
  ...bootstrapOptions.postBuildScriptPaths.map((scriptPath) => [
    process.execPath,
    [scriptPath],
    { cwd: bootstrapOptions.packageRoot },
  ]),
];

describe("orcel CLI bootstrap", () => {
  it("fails before bootstrapping when Node.js is older than 24", async () => {
    const exists = vi.fn(async () => true);
    const importModule = vi.fn(async () => ({
      runCli: vi.fn(async () => {}),
    }));
    const runCommand = vi.fn(async () => {});

    await expect(
      runOrcelCli(["info"], bootstrapOptions, {
        exists,
        importModule,
        nodeVersion: "v23.11.0",
        runCommand,
      }),
    ).rejects.toThrow(
      "orcel requires Node.js >=24. You are running v23.11.0. " +
        "Please install a compatible Node.js version and try again.",
    );

    expect(exists).not.toHaveBeenCalled();
    expect(importModule).not.toHaveBeenCalled();
    expect(runCommand).not.toHaveBeenCalled();
  });

  it.each(["v24.0.0-rc.1", "v24garbage"])(
    "rejects %s when it does not satisfy orcel's package engine",
    async (nodeVersion) => {
      const exists = vi.fn(async () => true);
      const importModule = vi.fn(async () => ({
        runCli: vi.fn(async () => {}),
      }));
      const runCommand = vi.fn(async () => {});

      await expect(
        runOrcelCli(["info"], bootstrapOptions, {
          exists,
          importModule,
          nodeVersion,
          runCommand,
        }),
      ).rejects.toThrow(`You are running ${nodeVersion}.`);

      expect(exists).not.toHaveBeenCalled();
      expect(importModule).not.toHaveBeenCalled();
      expect(runCommand).not.toHaveBeenCalled();
    },
  );

  it("enforces upper bounds and gaps in the package engine range", async () => {
    const exists = vi.fn(async () => true);
    const importModule = vi.fn(async () => ({
      runCli: vi.fn(async () => {}),
    }));

    await expect(
      runOrcelCli(["info"], bootstrapOptions, {
        exists,
        importModule,
        nodeEngineRequirement: ">=24 <26",
        nodeVersion: "v26.0.0",
      }),
    ).rejects.toThrow("orcel requires Node.js >=24 <26. You are running v26.0.0.");

    expect(exists).not.toHaveBeenCalled();
    expect(importModule).not.toHaveBeenCalled();
  });

  it("imports the compiled CLI when build output already exists", async () => {
    const runCli = vi.fn(async () => {});
    const exists = vi.fn(async () => true);
    const getLatestBuildInputMtimeMs = vi.fn(async () => 100);
    const getPathMtimeMs = vi.fn(async () => 200);
    const importModule = vi.fn(async () => ({
      runCli,
    }));
    const runCommand = vi.fn(async () => {});

    await runOrcelCli(["info"], bootstrapOptions, {
      exists,
      getLatestBuildInputMtimeMs,
      getPathMtimeMs,
      importModule,
      runCommand,
    });

    expect(runCommand).not.toHaveBeenCalled();
    expect(importModule).toHaveBeenCalledWith("file:///workspace/packages/orcel/dist/src/cli/run.js");
    expect(runCli).toHaveBeenCalledWith(["info"]);
  });

  it("builds the CLI before importing when output is missing", async () => {
    const runCli = vi.fn(async () => {});
    let cliEntrypointExists = false;
    const exists = vi.fn(async (path: string) => {
      if (path === bootstrapOptions.cliEntrypointPath) {
        return cliEntrypointExists;
      }

      return workspaceBuildInputPaths.has(path);
    });
    const importModule = vi.fn(async () => ({
      runCli,
    }));
    const runCommand = vi.fn(async () => {
      cliEntrypointExists = true;
    });

    await runOrcelCli(["build"], bootstrapOptions, {
      exists,
      importModule,
      runCommand,
    });

    expect(runCommand.mock.calls).toEqual(workspaceBuildCommands);
    expect(importModule).toHaveBeenCalledWith("file:///workspace/packages/orcel/dist/src/cli/run.js");
    expect(runCli).toHaveBeenCalledWith(["build"]);
  });

  it("rebuilds the CLI when the compiled output is stale", async () => {
    const runCli = vi.fn(async () => {});
    const exists = vi.fn().mockResolvedValue(true);
    const getLatestBuildInputMtimeMs = vi.fn(async () => 200);
    const getPathMtimeMs = vi.fn(async () => 100);
    const importModule = vi.fn(async () => ({
      runCli,
    }));
    const runCommand = vi.fn(async () => {});

    await runOrcelCli(["dev"], bootstrapOptions, {
      exists,
      getLatestBuildInputMtimeMs,
      getPathMtimeMs,
      importModule,
      runCommand,
    });

    expect(runCommand.mock.calls).toEqual(workspaceBuildCommands);
    expect(importModule).toHaveBeenCalledWith("file:///workspace/packages/orcel/dist/src/cli/run.js");
    expect(runCli).toHaveBeenCalledWith(["dev"]);
  });

  it("trusts packaged build output when workspace sources are not installed", async () => {
    const runCli = vi.fn(async () => {});
    const exists = vi.fn(async (path: string) => path === bootstrapOptions.cliEntrypointPath);
    const getLatestBuildInputMtimeMs = vi.fn(async () => 200);
    const getPathMtimeMs = vi.fn(async () => 100);
    const importModule = vi.fn(async () => ({
      runCli,
    }));
    const runCommand = vi.fn(async () => {});

    await runOrcelCli(["info"], bootstrapOptions, {
      exists,
      getLatestBuildInputMtimeMs,
      getPathMtimeMs,
      importModule,
      runCommand,
    });

    expect(getLatestBuildInputMtimeMs).not.toHaveBeenCalled();
    expect(getPathMtimeMs).not.toHaveBeenCalled();
    expect(runCommand).not.toHaveBeenCalled();
    expect(importModule).toHaveBeenCalledWith("file:///workspace/packages/orcel/dist/src/cli/run.js");
    expect(runCli).toHaveBeenCalledWith(["info"]);
  });

  it("does not attempt a workspace build without the vendor script", async () => {
    const availablePaths = new Set(workspaceBuildInputPaths);
    availablePaths.delete(`${bootstrapOptions.packageRoot}/scripts/vendor-compiled.mjs`);
    const exists = vi.fn(async (path: string) => availablePaths.has(path));
    const runCommand = vi.fn(async () => {});

    await expect(
      ensureBuiltCli(bootstrapOptions, {
        exists,
        runCommand,
      }),
    ).rejects.toThrow(
      `orcel package at ${bootstrapOptions.packageRoot} does not include the sources required to rebuild the CLI.`,
    );

    expect(runCommand).not.toHaveBeenCalled();
  });

  it("fails when the CLI is missing from a packaged install", async () => {
    const exists = vi.fn(async () => false);
    const runCommand = vi.fn(async () => {});

    await expect(
      ensureBuiltCli(bootstrapOptions, {
        exists,
        runCommand,
      }),
    ).rejects.toThrow(
      `orcel package at ${bootstrapOptions.packageRoot} does not include the sources required to rebuild the CLI.`,
    );

    expect(runCommand).not.toHaveBeenCalled();
  });

  it("fails when a bootstrap build does not create the CLI entrypoint", async () => {
    const exists = vi.fn(async (path: string) => workspaceBuildInputPaths.has(path));
    const runCommand = vi.fn(async () => {});

    await expect(
      ensureBuiltCli(bootstrapOptions, {
        exists,
        runCommand,
      }),
    ).rejects.toThrow(`Building orcel did not produce ${bootstrapOptions.cliEntrypointPath}.`);
  });
});
