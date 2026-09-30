import { mkdir, mkdtemp, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-kaf-binary.js", async () => {
  const { join } = await import("node:path");
  return {
    // Pin resolution to the conventional app-local path so build-command
    // assertions stay deterministic without a real kaf install on disk. The
    // real resolver is exercised in resolve-kaf-binary.integration.test.ts.
    resolveKafBinaryPath: (appRoot: string) =>
      join(appRoot, "node_modules", "kaf", "bin", "kaf.js"),
  };
});

import { ensureKafVercelServicesConfig } from "#shared/vercel-services.js";

async function createTempHostRoot(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "kaf-vercel-services-"));
}

async function directoryExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory();
  } catch {
    return false;
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("ensureKafVercelServicesConfig", () => {
  it("generates the kaf service when vercel.json is missing", async () => {
    const hostRoot = await createTempHostRoot();

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({
      mode: "generated",
      services: {
        kaf: {
          buildCommand:
            "cd '../../..' && export KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY='.kaf/vercel-services/kaf/.vercel/output' && export KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && node 'node_modules/kaf/bin/kaf.js' build",
          framework: "kaf",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/kaf/v1/(.*)$",
              transforms: [
                {
                  args: "/kaf/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".kaf/vercel-services/kaf",
        },
      },
    });
  });

  it("creates the isolated service build root", async () => {
    const hostRoot = await createTempHostRoot();

    await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(await directoryExists(join(hostRoot, ".kaf", "vercel-services", "kaf"))).toBe(true);
  });

  it("uses a custom kaf build command verbatim", async () => {
    const hostRoot = await createTempHostRoot();

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      kafBuildCommand: "pnpm build:kaf",
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result.mode).toBe("generated");
    expect(result.mode === "generated" && result.services.kaf?.buildCommand).toBe(
      "cd '../../..' && export KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY='.kaf/vercel-services/kaf/.vercel/output' && export KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && pnpm build:kaf",
    );
  });

  it("resolves relative paths for an kaf app in a subdirectory", async () => {
    const hostRoot = await createTempHostRoot();
    const appRoot = join(hostRoot, "agent");
    await mkdir(appRoot, { recursive: true });

    const result = await ensureKafVercelServicesConfig({
      appRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result.mode === "generated" && result.services.kaf?.buildCommand).toBe(
      "cd '../../../agent' && export KAF_INTERNAL_BUILD_OUTPUT_DIRECTORY='../.kaf/vercel-services/kaf/.vercel/output' && export KAF_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../.vercel/output' && node '../node_modules/kaf/bin/kaf.js' build",
    );
  });

  it("reads vercel.json from a linked Vercel project root", async () => {
    const projectRoot = await createTempHostRoot();
    const hostRoot = join(projectRoot, "apps", "web");
    await mkdir(join(projectRoot, ".vercel"), { recursive: true });
    await writeFile(join(projectRoot, ".vercel", "project.json"), "{}\n");
    await mkdir(hostRoot, { recursive: true });
    await writeFile(
      join(projectRoot, "vercel.json"),
      `${JSON.stringify({
        services: {
          web: { root: "apps/web", framework: "nuxtjs" },
          kaf: { root: "agent", framework: "kaf" },
        },
      })}\n`,
    );

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({ mode: "root" });
  });

  it("prefers the host root vercel.json services over the linked project root's", async () => {
    const projectRoot = await createTempHostRoot();
    const hostRoot = join(projectRoot, "apps", "web");
    await mkdir(join(projectRoot, ".vercel"), { recursive: true });
    await writeFile(join(projectRoot, ".vercel", "project.json"), "{}\n");
    await mkdir(hostRoot, { recursive: true });
    await writeFile(join(projectRoot, "vercel.json"), `${JSON.stringify({})}\n`);
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        services: {
          web: { root: ".", framework: "nuxtjs" },
          kaf: { root: "agent", framework: "kaf" },
        },
      })}\n`,
    );

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({ mode: "root" });
  });

  it("generates nothing when vercel.json declares services including kaf", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        services: {
          web: { root: ".", framework: "nuxtjs" },
          agent: { root: "agent", framework: "kaf" },
        },
      })}\n`,
    );

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({ mode: "root" });
    expect(await directoryExists(join(hostRoot, ".kaf", "vercel-services"))).toBe(false);
  });

  it("accepts the named service array form", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        services: [
          { name: "web", root: ".", framework: "nuxtjs" },
          { name: "kaf", root: "agent", framework: "kaf" },
        ],
      })}\n`,
    );

    await expect(
      ensureKafVercelServicesConfig({
        appRoot: hostRoot,
        frameworkName: "Test",
        hostRoot: hostRoot,
      }),
    ).resolves.toEqual({ mode: "root" });
  });

  it("throws when vercel.json services omit the kaf service", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({ services: { web: { root: ".", framework: "nuxtjs" } } })}\n`,
    );

    await expect(
      ensureKafVercelServicesConfig({
        appRoot: hostRoot,
        frameworkName: "Test",
        hostRoot: hostRoot,
      }),
    ).rejects.toThrow(/already defines services/);
  });

  it("warns and generates when vercel.json only has legacy experimentalServices", async () => {
    const hostRoot = await createTempHostRoot();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        experimentalServices: {
          web: { entrypoint: ".", framework: "nuxtjs", routePrefix: "/" },
          kaf: { entrypoint: ".", framework: "kaf", routePrefix: "/_kaf_internal/kaf" },
        },
      })}\n`,
    );

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result.mode).toBe("generated");
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("experimentalServices"));
  });

  it("prefers stable services over legacy experimentalServices without warning", async () => {
    const hostRoot = await createTempHostRoot();
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        experimentalServices: { kaf: { entrypoint: ".", framework: "kaf", routePrefix: "/x" } },
        services: { kaf: { root: ".", framework: "kaf" } },
      })}\n`,
    );

    const result = await ensureKafVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({ mode: "root" });
    expect(warn).not.toHaveBeenCalled();
  });

  it("rejects a malformed vercel.json", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(join(hostRoot, "vercel.json"), `["not", "an", "object"]\n`);

    await expect(
      ensureKafVercelServicesConfig({
        appRoot: hostRoot,
        frameworkName: "Test",
        hostRoot: hostRoot,
      }),
    ).rejects.toThrow(/must contain a JSON object/);
  });
});
