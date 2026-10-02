import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import { stripVersionBuildMetadata } from "#shared/package-version.js";

// These repository coordinates are external Vercel/Eve runtime contracts from
// the pinned upstream foundation. Orcel owns the local API names below, but it
// must not silently rewrite provider-owned image coordinates.
const GHCR_ORCEL_SANDBOX_IMAGE_REPOSITORY = "ghcr.io/vercel/eve";
const VERCEL_ORCEL_SANDBOX_IMAGE_REPOSITORY = "vcr.vercel.com/vercel/eve/base";

export function resolveOrcelSandboxImage(): string {
  return `${GHCR_ORCEL_SANDBOX_IMAGE_REPOSITORY}:${resolveOrcelSandboxImageTag()}`;
}

export function resolveVercelOrcelSandboxImage(): string {
  return `${VERCEL_ORCEL_SANDBOX_IMAGE_REPOSITORY}:${resolveOrcelSandboxImageTag()}`;
}

function resolveOrcelSandboxImageTag(): string {
  const override = process.env.ORCEL_SANDBOX_IMAGE_TAG?.trim();
  return override !== undefined && override.length > 0
    ? override
    : stripVersionBuildMetadata(resolveInstalledPackageInfo().version);
}

export const DEFAULT_ORCEL_SANDBOX_IMAGE = resolveOrcelSandboxImage();
export const VERCEL_ORCEL_SANDBOX_IMAGE = resolveVercelOrcelSandboxImage();
