# @orcel/computer-use Extension Package

This private package is the source of the `@orcel/orcel/computer-use` extension. It contributes the `computer_use` tool and the sandbox helpers that install and start the desktop and driver.

Before writing code, read the installed orcel package docs for extensions, tools, and sandboxes as applicable.

## Boundaries

- Keep this extension free of coding tools; those belong in `@orcel/code`.
- Keep shared implementation under `extension/lib/`; filesystem paths define contribution names.
- Keep the sandbox exports in `extension/lib/sandbox.ts`; `@orcel/code` re-exports them for compatibility.

## Build and publish

The orcel build copies `extension/` into `packages/orcel/src/computer-use/extension` and compiles it into the `orcel` package; public entry points are declared in `packages/@orcel/orcel/package.json` and `packages/orcel/src/computer-use/`. Do not publish this package or add it as an orcel dependency (it depends on orcel). Import only public `orcel/*` APIs from `extension/`; third-party imports are bundled into orcel's dist. Keep tests under `test/scenario/`, outside the discovered extension tree. Run typecheck, the scenario tests, orcel's build, lint, and package-scoped formatting before completion.
