# kaf/extensions/code

`kaf/extensions/code` is an kaf extension for coding work. It contributes `apply_patch`, `gh`, `grep`, investigation and PR skills, a read-only worker subagent, sandbox tooling, and shared PR-watch primitives. Vercel credentials are brokered before each turn; GitHub credentials are scoped to one repository and leased for each `gh` tool invocation. Because kaf workflow directives are application-only, consumers own their `prwatch` / `prwatch_delete` workflow tools.

It ships inside the `kaf` package. This private `@kaf/code` workspace package is its source of truth: kaf's build copies `extension/` into `packages/kaf/src/extensions/code/extension` and publishes it with these entry points:

- `kaf/extensions/code`: the extension
- `kaf/extensions/code/sandbox`: sandbox bootstrap and credential helpers
- `kaf/extensions/code/tools`: `apply_patch`, `gh`, and `grep`
- `kaf/extensions/code/prwatch`: PR-watch primitives for consumer-owned workflow tools

## Mount

```ts
// agent/extensions/code.ts
import code from "kaf/extensions/code";

export default code({
  // Optional; omit to mount without Connect-backed Vercel authentication.
  vercel: { connector: "vercel/acme-bot" },
});
```

Both connectors are optional; `code({})` mounts without either. The Vercel connector requests an app-subject token. Firewall delivery is the default and keeps tokens outside sandbox processes; without a consumer `broker`, it requires a sandbox provider that exposes `setNetworkPolicy()` and fails otherwise. Use `delivery: "command"` on the Vercel connector for providers without mutable network policy. A top-level `broker(sandbox, rules)` callback lets the consumer merge Vercel credential rules into its own network policy.

To enable the authenticated `gh` tool, configure `github` with `connector`, `org`, and a required `broker(sandbox, rules)` callback. The tool requests a token for exactly one repository in that organization. The callback installs the supplied GitHub header-transform rules for the command, then receives `null` to remove the lease. It must preserve the consumer's other network rules. GitHub authentication has no command-delivery option on this tool; sandbox processes receive a placeholder token, not the real credential.

The read-only worker subagent defaults to `openai/gpt-5.6-terra-fast` with `xhigh` reasoning. Set `worker: { model, reasoning, openaiReasoningEffort? }` to choose another model; `openaiReasoningEffort` is passed to OpenAI models as `reasoningEffort`.

## Sandbox bootstrap

Install CLI tooling in the environment's `prepare` callback:

```ts
// agent/sandbox.ts
import { defineSandbox } from "kaf/sandbox";
import { VercelSandbox } from "kaf/sandbox/vercel";
import { installCodeTooling } from "kaf/extensions/code/sandbox";

export const environment = VercelSandbox.environment({
  prepare: async (sandbox) => {
    await installCodeTooling(sandbox, { vercel: true });
  },
});

export default defineSandbox(() => environment.open());
```

kaf derives the prepared environment generation from the sandbox file and environment options, not from imported helpers, so upgrading kaf alone does not rebuild an existing prepared artifact.

Computer use lives in `kaf/computer-use`. Mount it next to this extension when the sandbox has a desktop. `installComputerUse`, `startComputerUse`, and `COMPUTER_USE_REVALIDATION_KEY` are still re-exported from `kaf/extensions/code/sandbox`, and `computer_use` from `kaf/extensions/code/tools`, but both are deprecated.

Preparation ensures `gh`, installs wrappers for `gh`, `vc`, and `gh-signed-commit`, and installs TypeScript diagnostics. For repositories requiring verified signatures, stage the intended changes and use `gh-signed-commit`.

## Non-Connect escape hatch

Consumers with a PAT, benchmark token, or another credential provider can omit the corresponding connector and call `authenticateGitHub` or `authenticateVercel` from `kaf/extensions/code/sandbox` in their own sandbox lifecycle. These helpers support firewall, command-delivery, and broker options for consumer-owned commands; they do not configure the extension's `gh` tool.

## Develop in this workspace

Rebuild kaf after editing `extension/`; the local agent under `agent/` mounts the built `kaf/extensions/code`:

```sh
pnpm --filter kaf build
pnpm --filter @kaf/code typecheck
pnpm --filter @kaf/code test
pnpm --filter @kaf/code test:scenario
pnpm exec oxlint packages/kaf-code
pnpm exec oxfmt --check packages/kaf-code
```

Tests live under `test/`, outside the extension distribution. Unit and integration tests run through the workspace's matching test tasks. The package integration task depends only on kaf's build. The root integration command runs the framework suite before the other packages because that suite rebuilds the runtime files they import. Scenario tests exercise temporary files, local Git repositories, and subprocesses; they need Node.js 24 or newer, Git, and Bash, but no model or service credentials.

The `typescript-compiler` development alias supplies the JavaScript compiler API used by the diagnostics worker test. The workspace's TypeScript 7 CLI remains the package typechecker. `prepack` builds the extension; installation does not run the extension CLI before the local framework has been built.

## Benchmarks

kaf-code is benchmarked with [kaf-bench](https://github.com/vercel-labs/kaf-bench#readme) on the SWE-lean dataset. kaf-bench owns datasets, execution, comparisons, and reports; this package keeps no benchmark runner of its own.

### In CI

The `kaf-code > Benchmark harness` workflow runs whenever `packages/kaf-code/**` changes. It benchmarks the PR head's kaf-code, opencode, and pi together, using the model in the `KAF_CODE_BENCH_MODEL` repository variable. Every trial runs in its own Vercel Sandbox, and all of them start at once, so a run takes about as long as its slowest trial. Each harness is compared with its own latest result from `main`. The report covers resolved tasks, latency, and token usage. It goes to the job summary and a PR comment.

Comment `/benchmark` to re-run the default harnesses, or `/benchmark <harness>[,<harness>...]` to choose, for example `/benchmark codex,kaf-code`. You need write access to the repository. Every push to `main` that touches kaf-code publishes fresh results to the kaf-bench result store, which is where later PRs get their baselines.

### Locally

With [kaf-bench](https://github.com/vercel-labs/kaf-bench#readme) linked (`npm link` in its checkout), commit and push this checkout, then run:

```sh
kaf-bench -a kaf-code --agent-dir packages/kaf-code --model openai/gpt-6-luna --reasoning low \
  --scope <vercel-team> --execution vercel-sandbox
```

Pass several harnesses to compare them in one run, for example `-a kaf-code,opencode,pi`. Use `--task <name>` to run a single task. Local runs never publish to the result store.

### Investigating a failed trial

Trial sandboxes are deleted as soon as each trial finishes. Before deletion, kaf-bench pulls each trial's logs and traces out of the sandbox and uploads them with the workflow artifact. To read them, point kaf-bench at the CI run:

```sh
kaf-bench trials logs https://github.com/TheHalfMoon/kaf/actions/runs/<id>
kaf-bench trials logs https://github.com/TheHalfMoon/kaf/actions/runs/<id> --harness kaf-code --task <task>
```

The report's Diagnostics section prints this command with the run URL filled in. The download uses the GitHub CLI and needs read access to this repository. The raw files (`agent.log`, `events.ndjson`, `observability.ndjson`, `verifier.log`) are cached under `~/.cache/kaf-bench/runs/`.
