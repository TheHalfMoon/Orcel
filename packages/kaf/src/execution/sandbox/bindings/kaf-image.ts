import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import { stripVersionBuildMetadata } from "#shared/package-version.js";

const GHCR_KAF_SANDBOX_IMAGE_REPOSITORY = "ghcr.io/vercel/kaf";
const VERCEL_KAF_SANDBOX_IMAGE_REPOSITORY = "vcr.vercel.com/vercel/kaf/base";

export function resolveKafSandboxImage(): string {
  return `${GHCR_KAF_SANDBOX_IMAGE_REPOSITORY}:${resolveKafSandboxImageTag()}`;
}

export function resolveVercelKafSandboxImage(): string {
  return `${VERCEL_KAF_SANDBOX_IMAGE_REPOSITORY}:${resolveKafSandboxImageTag()}`;
}

function resolveKafSandboxImageTag(): string {
  const override = process.env.KAF_SANDBOX_IMAGE_TAG?.trim();
  return override !== undefined && override.length > 0
    ? override
    : stripVersionBuildMetadata(resolveInstalledPackageInfo().version);
}

export const DEFAULT_KAF_SANDBOX_IMAGE = resolveKafSandboxImage();
export const VERCEL_KAF_SANDBOX_IMAGE = resolveVercelKafSandboxImage();
