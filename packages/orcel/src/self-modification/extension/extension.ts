import { defineExtension } from "@orcel/orcel/extension";

import type { StandardSchemaV1 } from "#compiled/@standard-schema/spec/index.js";
import type { SelfModificationExtensionConfig } from "../config.js";
import { selfModificationConfigSchema } from "./config-schema.js";

// Typed as a Standard Schema so the public declaration names orcel's own
// config type instead of Zod's.
const config: StandardSchemaV1<SelfModificationExtensionConfig> = selfModificationConfigSchema;

/** Extension mount configured with the same policy as the agent and sandbox. */
export default defineExtension({ config });
