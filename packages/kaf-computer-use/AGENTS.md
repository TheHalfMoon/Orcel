# @kaf/computer-use Extension Package

This private package is the source of the `kaf/computer-use` extension. It contributes the `computer_use` tool and the sandbox helpers that install and start the desktop and driver.

Before writing code, read the installed kaf package docs for extensions, tools, and sandboxes as applicable.

## Boundaries

- Keep this extension free of coding tools; those belong in `@kaf/code`.
- Keep shared implementation under `extension/lib/`; filesystem paths define contribution names.
- Keep the sandbox exports in `extension/lib/sandbox.ts`; `@kaf/code` re-exports them for compatibility.

## Build and publish

The kaf build copies `extension/` into `packages/kaf/src/computer-use/extension` and compiles it into the `kaf` package; public entry points are declared in `packages/kaf/package.json` and `packages/kaf/src/computer-use/`. Do not publish this package or add it as an kaf dependency (it depends on kaf). Import only public `kaf/*` APIs from `extension/`; third-party imports are bundled into kaf's dist. Keep tests under `test/scenario/`, outside the discovered extension tree. Run typecheck, the scenario tests, kaf's build, lint, and package-scoped formatting before completion.
