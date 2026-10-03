# Nuxt with orcel demo

A Nuxt 4 app with an embedded orcel agent, integrated through the `orcel/nuxt` module:

```ts
export default defineNuxtConfig({
  modules: ["orcel/nuxt"],
});
```

The agent lives in `agent/` (instructions, tools, channels) next to the Nuxt `app/` directory. In local development the module starts the orcel runtime alongside the Nuxt dev server and proxies same-origin orcel endpoints to it.

## Run locally

```sh
pnpm --filter framework-nuxt dev
```

## Deploy

On Vercel builds the module generates the orcel service and its routing in the Build Output config, so no `vercel.json` is required. See [the Nuxt frontend docs](../../../docs/guides/frontend/nuxt.mdx) for details.
