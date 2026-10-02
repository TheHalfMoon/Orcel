# @orcel/code Extension Package

This private package is the source of the `orcel/extensions/code` extension for CLI-based coding work. It contributes one patch editing primitive, an authenticated `gh` tool, sandbox `grep`, shared PR-watch primitives, investigation and PR skills, instruction fragments, a read-only worker subagent, Connect-backed authentication hooks, and consumer sandbox helpers. Durable `prwatch` / `prwatch_delete` wrappers currently live beside e0's consumer mount because orcel workflow directives are application-only.

Before writing code, read the installed orcel package docs for extensions, hooks, tools, skills, subagents, and sandboxes as applicable.

## Boundaries

- Connector UIDs and GitHub organization names enter through extension config. The authentication hook resolves Vercel app tokens before each turn; the `gh` tool leases a repository-scoped GitHub token per invocation.
- Consumers with non-Connect credentials may call `authenticateGitHub` or `authenticateVercel` directly from their sandbox lifecycle.
- Broker credentials without placing them in model-authored URLs or arguments.
- Use real `git`, `gh`, and `vc` CLIs rather than bespoke repository lifecycle tools.
- Keep `apply_patch` as the only extension-owned file editing primitive.
- Keep shared implementation under `extension/lib/`; filesystem paths define contribution names.
- Computer use lives in `@orcel/computer-use` (`orcel/computer-use`). Keep the deprecated computer-use re-exports in `extension/lib/sandbox.ts` until they are removed; do not add computer-use code here.

## Build and publish

The orcel build copies `extension/` into `packages/orcel/src/extensions/code/extension` and compiles it into the `orcel` package; public entry points are declared in `packages/orcel/package.json` and `packages/orcel/src/extensions/code/`. Do not publish this package or add it as an orcel dependency (it depends on orcel). Import only public `orcel/*` APIs from `extension/`; third-party imports are bundled into orcel's dist. Keep tests under `test/unit/`, `test/integration/`, and `test/scenario/`, outside the discovered extension tree. Run typecheck, all three test tiers, orcel's build, lint, and package-scoped formatting before completion.
