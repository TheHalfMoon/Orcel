/**
 * Custom URL scheme for serializing `URL` objects in `FilePart.data`
 * across the queue boundary.
 *
 * Route handlers place `new URL("https://...")` on `FilePart.data`.
 * Before the message crosses the queue, `send()` rewrites these as
 * `orcel-url:https://...` strings. After the queue, the staging pipeline
 * reconstitutes them back to `URL` objects so `instanceof URL` checks
 * work reliably.
 */

import { ATTACHMENT_REF_SCHEME } from "#internal/attachments/refs.js";
import { SANDBOX_URL_SCHEME } from "#internal/attachments/sandbox-refs.js";

const ORCEL_URL_SCHEME = "orcel-url:";

export function serializeUrlFilePart(url: URL): string {
  return `${ORCEL_URL_SCHEME}${url.href}`;
}

export function isSerializedUrlFilePart(data: unknown): data is string {
  return typeof data === "string" && data.startsWith(ORCEL_URL_SCHEME);
}

export function deserializeUrlFilePart(data: string): URL {
  return new URL(data.slice(ORCEL_URL_SCHEME.length));
}

/**
 * Framework-internal `FilePart.data` ref schemes (`orcel-url:`, `orcel-sandbox:`,
 * `orcel-attachment:`). orcel produces these during its own serialization and
 * staging; an inbound channel payload must never carry one. The staging
 * pipeline trusts the scheme prefix and reconstitutes such a string into a
 * privileged sandbox/attachment read, so a caller-supplied ref is an
 * arbitrary-read / path-traversal vector and must be rejected at the channel
 * boundary.
 */
const INTERNAL_REF_SCHEMES = [ORCEL_URL_SCHEME, SANDBOX_URL_SCHEME, ATTACHMENT_REF_SCHEME];

/**
 * Whether a `FilePart.data` string carries a framework-internal ref scheme.
 */
export function hasInternalRefScheme(data: string): boolean {
  return INTERNAL_REF_SCHEMES.some((scheme) => data.startsWith(scheme));
}
