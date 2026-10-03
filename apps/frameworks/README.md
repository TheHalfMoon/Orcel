# Framework apps

These apps verify orcel's frontend framework integrations and act as runnable examples for maintainers.

- `framework-next` covers `@orcel/orcel/next` and `withEve()`.
- `framework-next-multi-agent` covers `withEve()` workspace discovery and named `useOrcelAgent({ agent })` calls.
- `framework-nuxt` covers the `@orcel/orcel/nuxt` module.
- `framework-sveltekit` covers the `@orcel/orcel/sveltekit` Vite plugin.

Keep these apps small and focused on framework wiring. Smoke-test-only behavior belongs in `apps/fixtures`.
