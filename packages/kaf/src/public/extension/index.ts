/**
 * Authoring helpers for kaf extensions — reusable packages mounted into an
 * agent through `agent/extensions/`.
 *
 * @example
 * ```ts
 * import { defineExtension } from "kaf/extension";
 * ```
 */

export {
  defineExtension,
  type ExtensionHandle,
  type MountedExtension,
  type NoConfigExtensionHandle,
} from "#public/definitions/extension.js";
