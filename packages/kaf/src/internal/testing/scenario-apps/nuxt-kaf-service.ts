import type { ScenarioAppDescriptor } from "#internal/testing/scenario-app.js";

// Not resolved from the installed workspace like the Next.js descriptor's
// dependencies: `nuxt` is only an optional peer of kaf, so no copy is
// installed to resolve a version from.
const NUXT_VERSION = "^4.0.0";
const VUE_VERSION = "^3.5.0";

interface NuxtKafServiceDescriptorOptions {
  readonly installDependencies?: boolean;
}

/**
 * A Nuxt host with a generated kaf Vercel service.
 */
export function createNuxtKafServiceDescriptor(
  options: NuxtKafServiceDescriptorOptions = {},
): ScenarioAppDescriptor {
  return {
    dependencies: {
      nuxt: NUXT_VERSION,
      vue: VUE_VERSION,
    },
    files: {
      "agent/agent.mjs": `import { defineAgent } from "kaf";

export default defineAgent({ model: "openai/gpt-5.4" });
`,
      "agent/instructions.md": "You are a test agent.\n",
      "app/app.vue": `<template>
  <main>kaf nuxt deployment</main>
</template>
`,
      "nuxt.config.ts": `export default defineNuxtConfig({
  compatibilityDate: "2026-05-27",
  kaf: { kafRoot: "agent" },
  modules: ["kaf/nuxt"],
  telemetry: false,
});
`,
      "pnpm-workspace.yaml": "minimumReleaseAge: 0\n",
    },
    installDependencies: options.installDependencies,
    name: "nuxt-kaf-service",
  };
}
