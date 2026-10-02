import { packageVersion } from "../../../package-version.js";

const upstreamEveImage =
  process.env.VERCEL_EVE_IMAGE ||
  process.env.EVE_IMAGE ||
  `ghcr.io/vercel/eve:${packageVersion}`;

export const VERCEL_ORCEL_IMAGE = process.env.VERCEL_ORCEL_IMAGE || upstreamEveImage;

export const ORCEL_IMAGE = process.env.ORCEL_IMAGE || VERCEL_ORCEL_IMAGE;
