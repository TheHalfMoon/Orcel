/**
 * The published npm package name for the orcel framework.
 *
 * This module is intentionally free of side effects and heavy imports so that
 * any layer can reference the package identity without pulling in filesystem
 * or module-resolution code.
 */
export const ORCEL_PACKAGE_NAME = "@orcel/orcel";

/** Stable durable-workflow identity preserved across package-coordinate migrations. */
export const ORCEL_STABLE_WORKFLOW_ID_BASE = "orcel";
/** Stable framework slug used by deployment platforms such as Vercel. */
export const ORCEL_FRAMEWORK_SLUG = "orcel";
