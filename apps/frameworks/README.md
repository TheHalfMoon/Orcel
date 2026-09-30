# Framework apps

These apps verify kaf's frontend framework integrations and act as runnable examples for maintainers.

- `framework-next` covers `kaf/next` and `withEve()`.
- `framework-next-multi-agent` covers `withEve()` workspace discovery and named `useKafAgent({ agent })` calls.
- `framework-nuxt` covers the `kaf/nuxt` module.
- `framework-sveltekit` covers the `kaf/sveltekit` Vite plugin.

Keep these apps small and focused on framework wiring. Smoke-test-only behavior belongs in `apps/fixtures`.
