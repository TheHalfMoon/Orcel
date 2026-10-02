import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import { stripVersionBuildMetadata } from "#shared/package-version.js";

const GHCR_ORCEL_SANDBOX_IMAGE_REPOSITORY = "ghcr.io/thehalfmoon/orcel";
const VERCEL_ORCEL_SANDBOX_IMAGE_REPOSITORY = "vcr.vercel.com/vercel/orcel/base";

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
