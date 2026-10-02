# orcel/computer-use

`orcel/computer-use` is an orcel extension for computer use. It contributes the `computer_use` tool, which drives a Linux desktop inside the sandbox, plus the helpers that install and start that desktop.

It ships inside the `orcel` package. This private `@orcel/computer-use` workspace package is its source of truth: orcel's build copies `extension/` into `packages/orcel/src/computer-use/extension` and publishes it with these entry points:

- `orcel/computer-use`: the extension
- `orcel/computer-use/sandbox`: `installComputerUse`, `startComputerUse`, and `COMPUTER_USE_REVALIDATION_KEY`
- `orcel/computer-use/tools`: `computer_use`

## Mount

The extension has no config:

```ts
// agent/extensions/computer-use.ts
export { default } from "orcel/computer-use";
```

Mount it only for agents whose sandbox runs the desktop. The tool schema is large, so agents that never use a desktop should leave it out.

## Sandbox bootstrap

Install the desktop and driver in the environment's `prepare` callback, then start them after `open()` in `defineSandbox()`. Computer use requires an apt-based Linux image with root or passwordless sudo; it cannot run on the `just-bash` provider.

```ts
// agent/sandbox.ts
import { defineSandbox } from "orcel/sandbox";
import { VercelSandbox } from "orcel/sandbox/vercel";
import { installComputerUse, startComputerUse } from "orcel/computer-use/sandbox";

export const environment = VercelSandbox.environment({
  prepare: async (sandbox) => {
    await installComputerUse(sandbox);
  },
});

export default defineSandbox(async () => {
  const sandbox = await environment.open();
  await startComputerUse(sandbox);
  return sandbox;
});
```

Mounting the extension exposes `computer_use` but does not install or start its driver. The prepared artifact captures files, not running processes; the `defineSandbox()` selector starts the driver once for each new durable sandbox. If the driver exits or the provider resumes only filesystem state, call `startComputerUse` again before using the tool; resuming a sandbox does not rerun the selector. Stop recordings with `record_stop` to finalize the MP4 at the returned sandbox path. A five-minute watchdog also finalizes forgotten recordings, and the driver attempts finalization on `SIGINT` or `SIGTERM`; abrupt VM termination cannot guarantee a finalized MP4.

## Develop in this workspace

Rebuild orcel after editing `extension/`:

```sh
pnpm --filter orcel build
pnpm --filter @orcel/computer-use typecheck
pnpm --filter @orcel/computer-use test:scenario
pnpm exec oxlint packages/orcel-computer-use
pnpm exec oxfmt --check packages/orcel-computer-use
```
