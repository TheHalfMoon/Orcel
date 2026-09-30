import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { packageInstallResult } from "#internal/testing/package-process.js";
import { detectPackageManager } from "#setup/package-manager.js";
import {
  scaffoldExtensionProject,
  type ScaffoldExtensionProjectOptions,
} from "#setup/scaffold/index.js";
import { pathExists } from "#setup/path-exists.js";

import type { GitInitResult } from "./init-git.js";
import {
  KAF_INIT_PACKAGE_SPEC_ENV,
  runExtensionInitCommand,
  type ExtensionInitCliLogger,
  type ExtensionInitCommandDependencies,
} from "./extension-init.js";

const BASE_VERSIONS = {
  kafPackage: { version: "0.6.0", nodeEngine: ">=24" },
  typescriptPackageVersion: "7.0.2",
  zodPackageVersion: "4.0.0",
} as const;

function logger(): ExtensionInitCliLogger & { messages: string[]; errors: string[] } {
  const messages: string[] = [];
  const errors: string[] = [];
  return {
    messages,
    errors,
    log: (message) => messages.push(message),
    error: (message) => errors.push(message),
  };
}

function dependencies(
  gitResult: GitInitResult = { kind: "initialized" },
): ExtensionInitCommandDependencies & {
  detectInvokingPackageManager: ReturnType<
    typeof vi.fn<ExtensionInitCommandDependencies["detectInvokingPackageManager"]>
  >;
  isCodingAgentLaunch: ReturnType<
    typeof vi.fn<ExtensionInitCommandDependencies["isCodingAgentLaunch"]>
  >;
  now: ReturnType<typeof vi.fn<ExtensionInitCommandDependencies["now"]>>;
  runPackageManagerInstall: ReturnType<
    typeof vi.fn<ExtensionInitCommandDependencies["runPackageManagerInstall"]>
  >;
  tryInitializeGit: ReturnType<typeof vi.fn<ExtensionInitCommandDependencies["tryInitializeGit"]>>;
} {
  return {
    detectInvokingPackageManager: vi.fn(() => undefined),
    isCodingAgentLaunch: vi.fn(async () => false),
    now: vi.fn(() => 0),
    detectPackageManager,
    scaffoldExtensionProject: (options: ScaffoldExtensionProjectOptions) => {
      const merged = {
        ...options,
        kafPackage: options.kafPackage ?? BASE_VERSIONS.kafPackage,
        typescriptPackageVersion:
          options.typescriptPackageVersion ?? BASE_VERSIONS.typescriptPackageVersion,
        zodPackageVersion: options.zodPackageVersion ?? BASE_VERSIONS.zodPackageVersion,
      };
      return scaffoldExtensionProject(merged);
    },
    runPackageManagerInstall: vi.fn(async () => packageInstallResult()),
    tryInitializeGit: vi.fn(async () => gitResult),
  };
}

async function createHostProject(
  parentDirectory: string,
  packageJson: Record<string, unknown> = { name: "host-app" },
): Promise<string> {
  const projectRoot = join(parentDirectory, "host-app");
  await mkdir(projectRoot, { recursive: true });
  await writeFile(
    join(projectRoot, "package.json"),
    `${JSON.stringify(packageJson, null, 2)}\n`,
    "utf8",
  );
  await writeFile(join(projectRoot, "pnpm-lock.yaml"), "lockfileVersion: 9.0\n", "utf8");
  return projectRoot;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("runExtensionInitCommand", () => {
  it("scaffolds an extension package and prints next steps without starting kaf dev", async () => {
    const parentDirectory = await mkdtemp(join(tmpdir(), "kaf-extension-init-"));
    const output = logger();
    const deps = dependencies();

    await runExtensionInitCommand(output, parentDirectory, "my-crm", deps);

    const projectPath = join(parentDirectory, "my-crm");
    const packageJson = JSON.parse(await readFile(join(projectPath, "package.json"), "utf8")) as {
      kaf?: { extension?: { source?: string; dist?: string } };
      files?: string[];
      peerDependencies?: { kaf?: string };
      peerDependenciesMeta?: Record<string, unknown>;
      devDependencies?: { kaf?: string; typescript?: string };
      dependencies?: { zod?: string; ai?: string };
      scripts?: Record<string, string>;
    };
    expect(packageJson.kaf?.extension).toEqual({
      source: "./extension",
      dist: "./dist/extension",
    });
    expect(packageJson.files).toEqual(["dist"]);
    expect(packageJson.peerDependencies?.kaf).toBe("*");
    expect(packageJson.peerDependenciesMeta).toBeUndefined();
    expect(packageJson.devDependencies?.kaf).toBe("0.6.0");
    expect(packageJson.dependencies?.zod).toBe("4.0.0");
    expect(packageJson.dependencies?.ai).toBeUndefined();
    expect(packageJson.scripts?.build).toBe("kaf extension build");
    expect(packageJson.scripts?.prepare).toBe("kaf extension build");
    expect(packageJson.scripts?.dev).toBeUndefined();
    expect(await readFile(join(projectPath, "extension/extension.ts"), "utf8")).toContain(
      "defineExtension",
    );
    await expect(pathExists(join(projectPath, "extension/tools"))).resolves.toBe(false);
    await expect(pathExists(join(projectPath, "agent"))).resolves.toBe(false);

    expect(deps.runPackageManagerInstall).toHaveBeenCalledWith(
      "pnpm",
      projectPath,
      expect.any(Object),
    );
    expect(deps.tryInitializeGit).toHaveBeenCalledWith(projectPath);

    const printed = output.messages.join("\n");
    expect(printed).toContain("Created an kaf extension in ");
    expect(printed).toContain(projectPath);
    expect(printed).toContain("Initialized Git repository");
    expect(printed).toContain("extension/extension.ts");
    expect(printed).toContain("kaf extension build");
    expect(printed).toContain("pnpm run build");
    expect(printed).toContain("agent/extensions/my-crm.ts");
    expect(printed).not.toContain("kaf dev");
  });

  it("scaffolds an extension for a coding agent with a named target", async () => {
    const parentDirectory = await mkdtemp(join(tmpdir(), "kaf-extension-init-agent-"));
    const output = logger();
    const deps = dependencies();
    deps.isCodingAgentLaunch.mockResolvedValue(true);

    await runExtensionInitCommand(output, parentDirectory, "my-crm", deps);

    const projectPath = join(parentDirectory, "my-crm");
    await expect(pathExists(join(projectPath, "extension/extension.ts"))).resolves.toBe(true);
    expect(deps.runPackageManagerInstall).toHaveBeenCalled();
    expect(deps.tryInitializeGit).toHaveBeenCalledWith(projectPath);
    const printed = output.messages.join("\n");
    expect(printed).toContain("Created an kaf extension in ");
    expect(printed).toContain("What we set up:");
    expect(printed).not.toContain("Set up an kaf agent");
  });

  it("hands a coding agent the extension setup guide when the target is omitted", async () => {
    const parentDirectory = await mkdtemp(join(tmpdir(), "kaf-extension-init-bare-"));
    const output = logger();
    const deps = dependencies();
    deps.isCodingAgentLaunch.mockResolvedValue(true);

    await runExtensionInitCommand(output, parentDirectory, undefined, deps);

    await expect(pathExists(join(parentDirectory, "extension"))).resolves.toBe(false);
    expect(deps.runPackageManagerInstall).not.toHaveBeenCalled();
    expect(deps.tryInitializeGit).not.toHaveBeenCalled();
    const printed = output.messages.join("\n");
    expect(printed).toContain("npx kaf@latest extension init <name>");
    expect(printed).toContain("does not start kaf dev");
    expect(printed).toContain("kaf extension build");
  });

  it("rejects an existing project with package.json", async () => {
    const parentDirectory = await mkdtemp(join(tmpdir(), "kaf-extension-init-existing-"));
    const projectRoot = await createHostProject(parentDirectory);
    const output = logger();
    const deps = dependencies();

    await expect(
      runExtensionInitCommand(output, parentDirectory, "host-app", deps),
    ).rejects.toThrow("cannot add to an existing project");

    await expect(pathExists(join(projectRoot, "extension"))).resolves.toBe(false);
    expect(deps.runPackageManagerInstall).not.toHaveBeenCalled();
  });

  it("honors KAF_INIT_PACKAGE_SPEC for the dev dependency while keeping a wildcard peer", async () => {
    const parentDirectory = await mkdtemp(join(tmpdir(), "kaf-extension-init-spec-"));
    const output = logger();
    const deps = dependencies();
    vi.stubEnv(KAF_INIT_PACKAGE_SPEC_ENV, "file:/tmp/kaf-local.tgz");

    await runExtensionInitCommand(output, parentDirectory, "my-crm", deps);

    const packageJson = JSON.parse(
      await readFile(join(parentDirectory, "my-crm", "package.json"), "utf8"),
    ) as {
      peerDependencies?: { kaf?: string };
      devDependencies?: { kaf?: string };
    };
    expect(packageJson.peerDependencies?.kaf).toBe("*");
    expect(packageJson.devDependencies?.kaf).toBe("file:/tmp/kaf-local.tgz");
  });
});
