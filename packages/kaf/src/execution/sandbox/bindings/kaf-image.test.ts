import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const packageInfo = vi.hoisted(() => ({ name: "kaf", version: "1.2.3" }));
vi.mock("#internal/application/package.js", () => ({
  resolveInstalledPackageInfo: () => packageInfo,
}));

import {
  DEFAULT_KAF_SANDBOX_IMAGE,
  resolveKafSandboxImage,
  resolveVercelKafSandboxImage,
  VERCEL_KAF_SANDBOX_IMAGE,
} from "#execution/sandbox/bindings/kaf-image.js";

describe("kaf sandbox image", () => {
  beforeEach(() => {
    packageInfo.version = "1.2.3";
    vi.stubEnv("KAF_SANDBOX_IMAGE_TAG", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("uses the versioned GHCR image outside Vercel Sandbox", () => {
    expect(resolveKafSandboxImage()).toBe("ghcr.io/vercel/kaf:1.2.3");
    expect(DEFAULT_KAF_SANDBOX_IMAGE).toBe("ghcr.io/vercel/kaf:1.2.3");
  });

  it("uses the versioned VCR image for Vercel Sandbox", () => {
    expect(resolveVercelKafSandboxImage()).toBe("vcr.vercel.com/vercel/kaf/base:1.2.3");
    expect(VERCEL_KAF_SANDBOX_IMAGE).toBe("vcr.vercel.com/vercel/kaf/base:1.2.3");
  });

  it.each([
    ["0.56.0+git.4c27b3e37fa36d84", "0.56.0"],
    ["0.56.0+main.4c27b3e37fa36d84", "0.56.0"],
    ["0.56.0-beta.1+git.4c27b3e37fa36d84", "0.56.0-beta.1"],
  ])("uses the release image for artifact version %s", async (version, tag) => {
    packageInfo.version = version;
    vi.resetModules();
    const images = await import("#execution/sandbox/bindings/kaf-image.js");
    expect(images.resolveKafSandboxImage()).toBe(`ghcr.io/vercel/kaf:${tag}`);
    expect(images.DEFAULT_KAF_SANDBOX_IMAGE).toBe(`ghcr.io/vercel/kaf:${tag}`);
    expect(images.resolveVercelKafSandboxImage()).toBe(`vcr.vercel.com/vercel/kaf/base:${tag}`);
    expect(images.VERCEL_KAF_SANDBOX_IMAGE).toBe(`vcr.vercel.com/vercel/kaf/base:${tag}`);
  });

  it("uses KAF_SANDBOX_IMAGE_TAG for both registries", async () => {
    packageInfo.version = "0.56.0+git.4c27b3e37fa36d84";
    vi.stubEnv("KAF_SANDBOX_IMAGE_TAG", "latest");
    vi.resetModules();

    const images = await import("#execution/sandbox/bindings/kaf-image.js");
    expect(images.resolveKafSandboxImage()).toBe("ghcr.io/vercel/kaf:latest");
    expect(images.DEFAULT_KAF_SANDBOX_IMAGE).toBe("ghcr.io/vercel/kaf:latest");
    expect(images.resolveVercelKafSandboxImage()).toBe("vcr.vercel.com/vercel/kaf/base:latest");
    expect(images.VERCEL_KAF_SANDBOX_IMAGE).toBe("vcr.vercel.com/vercel/kaf/base:latest");
  });
});
