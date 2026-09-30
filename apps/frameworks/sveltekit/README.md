# SvelteKit with kaf demo

A SvelteKit app with an embedded kaf agent, integrated through the
`kafSvelteKit()` Vite plugin:

```ts
import { kafSvelteKit } from "kaf/sveltekit";

export default defineConfig({
  plugins: [kafSvelteKit(), sveltekit()],
});
```

The agent lives in `agent/` (instructions, tools, channels). The UI in
`src/lib/` is a small agent console built on kaf's Svelte hooks, with
streaming, reasoning, and tool-call rendering.

## Run locally

```sh
pnpm --filter framework-sveltekit dev
```

## Deploy

On Vercel builds the plugin generates the kaf service and its routing in the
Build Output config, so no `vercel.json` is required. See
[the SvelteKit frontend docs](../../../docs/guides/frontend/sveltekit.mdx) for details.
