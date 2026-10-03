# SvelteKit with orcel demo

A SvelteKit app with an embedded orcel agent, integrated through the
`orcelSvelteKit()` Vite plugin:

```ts
import { orcelSvelteKit } from "@orcel/@orcel/orcel/sveltekit";

export default defineConfig({
  plugins: [orcelSvelteKit(), sveltekit()],
});
```

The agent lives in `agent/` (instructions, tools, channels). The UI in
`src/lib/` is a small agent console built on orcel's Svelte hooks, with
streaming, reasoning, and tool-call rendering.

## Run locally

```sh
pnpm --filter framework-sveltekit dev
```

## Deploy

On Vercel builds the plugin generates the orcel service and its routing in the
Build Output config, so no `vercel.json` is required. See
[the SvelteKit frontend docs](../../../docs/guides/frontend/sveltekit.mdx) for details.
