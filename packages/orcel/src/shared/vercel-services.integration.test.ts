import { mkdir, mkdtemp, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("#shared/resolve-orcel-binary.js", async () => {
  const { join } = await import("node:path");
  return {
    // Pin resolution to the conventional app-local path so build-command
    // assertions stay deterministic without a real orcel install on disk. The
    // real resolver is exercised in resolve-orcel-binary.integration.test.ts.
    resolveOrcelBinaryPath: (appRoot: string) =>
      join(appRoot, "node_modules", "orcel", "bin", "orcel.js"),
  };
});

import { ensureOrcelVercelServicesConfig } from "#shared/vercel-services.js";

async function createTempHostRoot(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "orcel-vercel-services-"));
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

describe("ensureOrcelVercelServicesConfig", () => {
  it("generates the orcel service when vercel.json is missing", async () => {
    const hostRoot = await createTempHostRoot();

    const result = await ensureOrcelVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({
      mode: "generated",
      services: {
        orcel: {
          buildCommand:
            "cd '../../..' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && node 'node_modules/@orcel/orcel/bin/orcel.js' build",
          framework: "eve",
          outputDirectory: ".vercel/output",
          routes: [
            {
              src: "^/orcel/v1/(.*)$",
              transforms: [
                {
                  args: "/orcel/v1/$1",
                  op: "set",
                  type: "request.path",
                },
              ],
            },
          ],
          root: ".orcel/vercel-services/orcel",
        },
      },
    });
  });

  it("creates the isolated service build root", async () => {
    const hostRoot = await createTempHostRoot();

    await ensureOrcelVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(await directoryExists(join(hostRoot, ".orcel", "vercel-services", "orcel"))).toBe(true);
  });

  it("uses a custom orcel build command verbatim", async () => {
    const hostRoot = await createTempHostRoot();

    const result = await ensureOrcelVercelServicesConfig({
      appRoot: hostRoot,
      orcelBuildCommand: "pnpm build:orcel",
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result.mode).toBe("generated");
    expect(result.mode === "generated" && result.services.orcel?.buildCommand).toBe(
      "cd '../../..' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='.vercel/output' && pnpm build:orcel",
    );
  });

  it("resolves relative paths for an orcel app in a subdirectory", async () => {
    const hostRoot = await createTempHostRoot();
    const appRoot = join(hostRoot, "agent");
    await mkdir(appRoot, { recursive: true });

    const result = await ensureOrcelVercelServicesConfig({
      appRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result.mode === "generated" && result.services.orcel?.buildCommand).toBe(
      "cd '../../../agent' && export ORCEL_INTERNAL_BUILD_OUTPUT_DIRECTORY='../.orcel/vercel-services/orcel/.vercel/output' && export ORCEL_INTERNAL_HOST_BUILD_OUTPUT_DIRECTORY='../.vercel/output' && node '../node_modules/@orcel/orcel/bin/orcel.js' build",
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
          orcel: { root: "agent", framework: "eve" },
        },
      })}\n`,
    );

    const result = await ensureOrcelVercelServicesConfig({
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
          orcel: { root: "agent", framework: "eve" },
        },
      })}\n`,
    );

    const result = await ensureOrcelVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({ mode: "root" });
  });

  it("generates nothing when vercel.json declares services including orcel", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        services: {
          web: { root: ".", framework: "nuxtjs" },
          agent: { root: "agent", framework: "eve" },
        },
      })}\n`,
    );

    const result = await ensureOrcelVercelServicesConfig({
      appRoot: hostRoot,
      frameworkName: "Test",
      hostRoot: hostRoot,
    });

    expect(result).toEqual({ mode: "root" });
    expect(await directoryExists(join(hostRoot, ".orcel", "vercel-services"))).toBe(false);
  });

  it("accepts the named service array form", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({
        services: [
          { name: "web", root: ".", framework: "nuxtjs" },
          { name: "orcel", root: "agent", framework: "eve" },
        ],
      })}\n`,
    );

    await expect(
      ensureOrcelVercelServicesConfig({
        appRoot: hostRoot,
        frameworkName: "Test",
        hostRoot: hostRoot,
      }),
    ).resolves.toEqual({ mode: "root" });
  });

  it("throws when vercel.json services omit the orcel service", async () => {
    const hostRoot = await createTempHostRoot();
    await writeFile(
      join(hostRoot, "vercel.json"),
      `${JSON.stringify({ services: { web: { root: ".", framework: "nuxtjs" } } })}\n`,
    );

    await expect(
      ensureOrcelVercelServicesConfig({
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
          orcel: { entrypoint: ".", framework: "eve", routePrefix: "/_orcel_internal/orcel" },
        },
      })}\n`,
    );

    const result = await ensureOrcelVercelServicesConfig({
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
        experimentalServices: { orcel: { entrypoint: ".", framework: "eve", routePrefix: "/x" } },
        services: { orcel: { root: ".", framework: "eve" } },
      })}\n`,
    );

    const result = await ensureOrcelVercelServicesConfig({
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
      ensureOrcelVercelServicesConfig({
        appRoot: hostRoot,
        frameworkName: "Test",
        hostRoot: hostRoot,
      }),
    ).rejects.toThrow(/must contain a JSON object/);
  });
});
