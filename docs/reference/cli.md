---
title: "CLI"
description: "Reference for every orcel CLI command."
---

Relevant `orcel` commands can run from the application root or any directory beneath it. Running `orcel` with no command runs `orcel init` when the current directory is not an orcel project, or `orcel dev` when it is.

## Commands

| Command                                        | Description                                            |
| ---------------------------------------------- | ------------------------------------------------------ |
| `orcel init [target]`                            | Create a new agent, or add one to an existing project  |
| `orcel dev`                                      | Start the local development server and terminal UI     |
| `orcel remote connect --url <url>`               | Open the terminal UI for an existing agent             |
| `orcel remote invoke --url <url> [prompt]`       | Invoke an existing agent without a terminal UI         |
| `orcel remote info --url <url>`                  | Inspect an existing agent                              |
| `orcel acp [url]`                                | Serve a local or existing agent through ACP over stdio |
| `orcel info`                                     | Inspect the local application                          |
| `orcel set model [model] [--reasoning <effort>]` | Change model and reasoning settings                    |
| `orcel build` / `orcel start`                      | Build or serve the application                         |
| `orcel logs show [logid]` / `orcel logs list`      | Inspect local diagnostic logs                          |
| `orcel traces show [trace]` / `orcel traces list`  | Inspect local traces                                   |
| `orcel link` / `orcel deploy`                      | Link or deploy a Vercel project                        |
| `orcel eval`                                     | Run evals against a local or remote target             |
| `orcel add [item]` / `orcel registry <command>`    | Install and browse registry items                      |
| `orcel extension <command>`                      | Create and build extension packages                    |
| `orcel telemetry <command>`                      | Manage CLI telemetry collection                        |

When `orcel build` fails on discovery errors, it prints the full diagnostics report (severity, message, source path) and the diagnostics artifact path.

## CLI telemetry

orcel collects CLI telemetry by default to improve the command-line interface. Run `orcel telemetry disable` to disable it for this machine, or set `ORCEL_TELEMETRY_DISABLED=1` for one command. See [CLI telemetry](./telemetry) for the current data fields, exclusions, debug mode, notice, and local preference storage.

## `orcel init`

```bash
orcel init [target] [--model <provider/model-id>] [--reasoning <effort>] [--channel-web-nextjs] [--non-interactive]
```

Creates a new agent app or adds an agent to an existing app. Always installs dependencies. New directories also initialize Git.

| Target                                                                                                     | What happens                                                                                                           |
| ---------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `orcel init my-agent`                                                                                        | Creates an agent project in `my-agent/`                                                                                |
| `orcel init` or `orcel init .` in an empty directory                                                           | Creates an agent project in the current directory                                                                      |
| `orcel init` or `orcel init .` in a directory with files other than environment metadata and no `package.json` | Refuses to overwrite the directory. Pass a new directory name, such as `orcel init my-agent`                             |
| `orcel init` or `orcel init .` in an existing project                                                          | Adds `agent/` plus missing `orcel`, `ai`, and `zod` dependencies. Requires `package.json` and no existing `agent/` files |
| `orcel init path/to/app`                                                                                     | Adds an agent to the existing package at `path/to/app`                                                                 |

Existing packages do not need a target-selection prompt: run `orcel init` from the project directory or `orcel init path/to/app`. New projects in non-interactive environments need a new directory name, such as `orcel init my-agent`.

After scaffolding in an interactive human terminal, orcel opens the TUI directly. Pass `-n` or `--non-interactive` to return after scaffolding instead. It still installs dependencies and follows the normal Git setup behavior. Noninteractive and coding-agent invocations return without starting an interactive session. Fresh projects use the parent workspace's package manager when there is one; otherwise they use the manager that launched `orcel init`.

| Flag                    | Type   | Default                                              | Description                                                                                                              |
| ----------------------- | ------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `--model <model>`       | string | `openai/gpt-6-luna-fast`                             | Set the root agent's AI Gateway model ID.                                                                                |
| `--reasoning <effort>`  | enum   | `high` without `--model`; otherwise provider default | Set reasoning to `none`, `minimal`, `low`, `medium`, `high`, or `xhigh`. `provider-default` leaves the field unauthored. |
| `--channel-web-nextjs`  | flag   | off                                                  | Add the Web Chat app (Next.js). Not for existing projects — run `orcel add channel/web` there instead.                     |
| `-n, --non-interactive` | flag   | off                                                  | Scaffold and install dependencies without starting development.                                                          |

## `orcel extension`

Commands for reusable [extension](/docs/extensions) packages. An extension declares distinct authoring and distribution roots in `package.json#orcel.extension` (for example `"orcel": { "extension": { "source": "./extension", "dist": "./dist/extension" } }`).

### `orcel extension init`

```bash
orcel extension init [target]
```

Creates a new extension package, installs dependencies, and initializes Git. Prints next steps instead of starting `orcel dev`.

| Target                      | What happens                                                  |
| --------------------------- | ------------------------------------------------------------- |
| `orcel extension init my-crm` | New extension package in `my-crm/`                            |
| `orcel extension init .`      | Scaffold in the current empty directory                       |
| No target                   | Same as `.` for humans; coding agents get a short setup guide |

Create-only: cannot target an existing project that already has a `package.json`.

See [Extensions](/docs/extensions) for authoring and mount details.

### `orcel extension build`

```bash
orcel extension build
```

Builds the complete agent-shaped extension tree into its configured dist root, emits declarations and compatibility metadata, and fills the package `exports` map. The original TypeScript source is not required in the published package.

## Set model settings

Change the root agent's AI Gateway model and reasoning effort without opening the dev TUI:

```bash
orcel set model openai/gpt-6-sol --reasoning high
orcel set model --reasoning medium
```

Use `orcel set model` to change the model, its reasoning effort, or both. Omit
the optional model argument to keep the current model. When you set both, orcel
writes them to `agent/agent.ts` in one source edit. `--reasoning` accepts
`provider-default`, `none`, `minimal`, `low`, `medium`, `high`, or `xhigh`;
`provider-default` removes the authored `reasoning` field.

The command uses the same model ID validation and source editor as `/model` in
the local dev TUI. It does not configure model credentials. The `model`
argument cannot rewrite models defined with `defineDynamic`, an environment expression,
or a provider-authored SDK model; change those models in `agent.ts`.
`--reasoning` can still update an editable root config when its model comes from
an SDK call.

## Registry items

Commands for installing and discovering [shadcn registry](https://ui.shadcn.com/docs/registry) items. Official registry items use a kind and slug (for example, `extension/agent-browser`); URLs and configured registry addresses are also supported.

```bash
orcel add extension/agent-browser
orcel add channel/linear
orcel add channel/slack --skip-install
orcel add https://example.com/r/my-extension.json --overwrite
orcel registry add @acme=https://example.com/r/{name}.json
orcel registry search browser
orcel registry search browser --limit 5
orcel registry search browser --registry @acme
orcel registry view @acme/my-extension
orcel add @acme/my-extension
```

`orcel add` asks before running setup declared by an official item and runs multiple declared flows in declaration order. Interactive Vercel-backed setup signs in and creates or links a project when needed instead of stopping with a prerequisite. `--yes` accepts detected or recommended setup answers.

Coding agents should use `orcel add <item> --non-interactive`, adding `--yes` to accept recommended setup values and reduce setup round trips. Explicit `--answer` values take precedence. This mode never opens an orcel prompt. When a setup decision is missing, the NDJSON terminal event includes a stable question key and a safe continuation command; add the requested answer to that command. Supply answers with repeatable `--answer 'key=<JSON value>'` options. Follow a reported `orcel link` prerequisite before retrying Vercel Connect setup. Do not put secrets in command-line answers; use the integration's documented environment variable or secret store.

When setup is skipped, cancelled, or needs more input after installation, orcel prints or returns the matching `orcel add <item> --skip-install` continuation. It reruns the item's declared flows without reinstalling registry files.

`orcel registry add` records configured sources in `package.json#registries`. `orcel registry list` aggregates the official catalog and all configured sources by default. `orcel registry search` also includes [skills.sh](https://skills.sh), available without configuration at `@skills`, and groups results by source with each source's available result count. Search returns up to 10 matches per source by default; pass `--limit <count>` to request between 1 and 100. Either command can browse one supplied URL or namespace. Official and other universal items with explicit file targets do not require shadcn project configuration.

## `orcel info`

```bash
orcel info [--json]
```

| Flag     | Type | Default | Description  |
| -------- | ---- | ------- | ------------ |
| `--json` | flag | off     | Emit as JSON |

Run this first when something behaves unexpectedly. It confirms a file was discovered, lists the active surface, and surfaces discovery diagnostics, all faster than booting the dev server. Static instructions appear in source order with their `system` or `user` role. Dynamic instruction results are runtime-only and do not appear here.

## `orcel build`

```bash
orcel build [--profile <path>] [--skip-sandbox-prewarm]
```

Compiles and bundles in an invocation-owned directory under `.orcel/builds/`, prepares sandbox artifacts, then publishes the completed host output and prints its path. Scratch workspaces are removed after success or failure. Pass `--skip-sandbox-prewarm` when you only need compiled output, such as before a separate typecheck. Skipping preparation can produce output that cannot start its configured sandbox, so do not deploy that output.

Authored bundles preserve custom Node.js resolution conditions supplied through `--conditions`,
`-C`, or `NODE_OPTIONS`. For example, `NODE_OPTIONS="--conditions=react-server" orcel build`
keeps a channel's `server-only` imports on the same export used during compilation.

| Flag                     | Type   | Default | Description                                                                                   |
| ------------------------ | ------ | ------- | --------------------------------------------------------------------------------------------- |
| `--profile <path>`       | string | off     | Best-effort versioned JSON report with build-phase timings and final output-size measurements |
| `--skip-sandbox-prewarm` | flag   | off     | Skip sandbox preparation; the output might not be deployable                                  |

Use a profile file to establish a repeatable baseline before changing the build pipeline:

```bash
orcel build --profile .orcel/build-profiles/baseline.json
```

The report is attempted only after a successful build. It records total elapsed time, completed phase timings, and final regular-file totals for file count, raw bytes, and the sum of each file compressed with gzip. For Vercel output it also includes a subtotal for every real `.func` directory, so app and flow bundles can be compared separately. The profile path resolves from the app root and should be outside the published output directory; profile collection does not add a file to the deployment. If collection or writing fails, orcel emits a warning but keeps the completed build successful.

Production builds do not write through the stable compiler, host, Nitro, or Workflow files owned by `orcel dev`, so builds can run while a local dev server is active. A failed build leaves the last successful `.output/` and agent summary untouched. Concurrent completed builds serialize only the final publication window.

Useful stable artifacts written by inspection and development flows under `.orcel/` include:

| Artifact                                       | Description                                          |
| ---------------------------------------------- | ---------------------------------------------------- |
| `.orcel/discovery/agent-discovery-manifest.json` | What orcel found on disk                               |
| `.orcel/discovery/diagnostics.json`              | Authored-shape errors and warnings                   |
| `.orcel/compile/compiled-agent-manifest.json`    | The serialized authored surface orcel loads at runtime |
| `.orcel/compile/compile-metadata.json`           | Build-time metadata and paths                        |
| `.orcel/compile/module-map.mjs`                  | Compiled module entrypoints orcel imports at runtime   |

## `orcel start`

```bash
orcel start [--host <host>] [--port <port>]
```

| Flag            | Type   | Default            | Description            |
| --------------- | ------ | ------------------ | ---------------------- |
| `--host <host>` | string | all interfaces     | Host interface to bind |
| `--port <port>` | number | `$PORT`, then 3000 | Port to listen on      |

Serves the previously built output. Prints the listening URL.

For self-hosted deployments, copy the app source, `.output/`, and installed dependencies together. The deployment directory can differ from the build directory. Preserve the relative layout of any workspace packages used by the app; startup resolves sandbox prewarm modules from the deployed source.

## `orcel dev`

```bash
orcel dev [options]
```

Starts a local development server and terminal UI. To connect the UI to an existing agent, use `orcel remote connect --url <url>`.

| Flag                                | Type   | Default            | Description                                                     |
| ----------------------------------- | ------ | ------------------ | --------------------------------------------------------------- |
| `--host <host>`                     | string | all interfaces     | Host interface to bind                                          |
| `--port <port>`                     | number | `$PORT`, then 2000 | Port to listen on                                               |
| `--no-ui`                           | flag   | UI on              | Start the server without an interactive UI                      |
| `--resume`                          | flag   | off                | Attempt recovery of retained runs from previous dev invocations |
| `--no-default-extensions`           | flag   | extensions on      | Do not mount bundled development extensions                     |
| `--name <name>`                     | string | app folder name    | Title shown in the terminal UI                                  |
| `--input <text>`                    | string | none               | Pre-fill the prompt input                                       |
| `--tools <mode>`                    | enum   | `auto-collapsed`   | Tool-call rendering                                             |
| `--reasoning <mode>`                | enum   | `full`             | Reasoning rendering                                             |
| `--subagents <mode>`                | enum   | `collapsed`        | Subagent task rendering: `full`, `collapsed`, or `hidden`       |
| `--connection-auth <mode>`          | enum   | `full`             | Connection-authorization rendering                              |
| `--assistant-response-stats <mode>` | enum   | `tokensPerSecond`  | Assistant header statistic                                      |
| `--context-size <tokens>`           | number | none               | Model context window size                                       |
| `--logs <mode>`                     | enum   | `stderr`           | Server and agent logs to show                                   |

Local development mounts bundled development extensions without adding files to your project. Pass `--no-default-extensions` to disable them. See [Self-Modification](../guides/self-modification) for details.

A fresh `orcel init` opens the TUI and reuses an available model connection or opens `/login`. No Vercel project, channels, integrations, or review step is required before chat. Use `/model` to change models and settings, and `/add` to install an addition. Other `--input` text stays editable in the prompt. See [Terminal UI](../guides/dev-tui) for credential precedence and login options.

### Local development lifecycle

Local dev records the last ready URL per resolved app root in `.orcel/dev-server-state.v1.json`. A second interactive `orcel dev` reconnects only when that URL is loopback and healthy; each terminal UI creates a fresh client session while sharing the server process. A stale or malformed record is replaced when orcel starts a new server. Passing `--host`, `--port`, or a `PORT` environment value skips reconnection and reports a healthy recorded server instead.

Local dev keeps immutable runtime generations under `.orcel/dev-runtime/snapshots/` so in-flight turns hold a consistent code revision while new turns pick up rebuilds. Each generation contains the compiled authored module graph and runtime resources rather than a recursive copy of the app or workspace. The terminal REPL keeps its logical session across successful rebuilds, so the next turn continues the conversation on the latest generation; `/new` terminally retires that session before clearing the transcript, and the next prompt starts a fresh session with a new session-scoped sandbox on first sandbox use. After a generation is superseded, `orcel dev` retains it for at least 30 minutes and also retains the five most recently superseded generations, regardless of the configured Workflow World. The active generation is never pruned. Old runtime snapshots and local sandbox templates are pruned in the background. For manual cleanup, stop `orcel dev` before deleting `.orcel/dev-runtime/snapshots/` or `.orcel/sandbox-cache/local/templates/`. A turn that remains unfinished beyond the automatic retention window can no longer resume after its generation is pruned.

Local development records traces under `.orcel/traces/` by default and bounds that store by age, size, and a keep-newest floor. Configure it with `ORCEL_TRACES*` in `.env.local`, or disable the destination with `agent/instrumentation/local.ts`; see [`orcel traces`](#retention) for the rules and defaults.

`orcel acp` reserves stdin and stdout for newline-delimited JSON-RPC and sends diagnostics to stderr. Without a URL, it supervises an isolated local development server. With a URL, it bridges ACP to that server's existing orcel HTTP API. See [Agent Client Protocol (ACP)](../protocols/acp) for client configuration and capability limits.

### Local workflow recovery

With the built-in local Workflow World, a new `orcel dev` server leaves previous invocations' runs dormant by default, including deliveries triggered by timers or hooks. A new message or control request addressed to a dormant conversation fails instead of being accepted without a response; the HTTP channel reports its usual request failure. Start a new conversation, or restart `orcel dev` with `--resume` to attempt recovery. Already-open event streams are not changed by this request guard. Source-watcher rebuilds and worker restarts within the same server retain current runs' eligibility.

Pass `orcel dev --resume` to attempt recovery of unfinished runs from previous invocations. Recovery requires a retained snapshot with readable generation metadata. Snapshots from older orcel versions with a valid `runtimeAppRoot` remain eligible. Changes to the orcel framework or authored workflow sources do not prevent the attempt, but replay can fail and leave the run terminally failed after executing some work. Use `--resume` only when you want to try continuing those previous runs.

Runs with malformed generation metadata remain stored and dormant for that server invocation, including later timer and hook deliveries. Startup with `--resume` reports why recovery was skipped without blocking other eligible runs. Restore malformed snapshot metadata from a backup or start a new session.

Recovery eligibility is decided before startup queue delivery begins. Hot reload does not recheck admitted runs against the latest workflow sources, so follow-up turns, cancellation, and `/new` retain their existing behavior. Changing an authored workflow body while it is running can likewise cause replay failure.

With the built-in local Workflow World, `orcel dev` cancels unfinished runs whose runtime snapshots are missing, at startup and after snapshot pruning. This includes waiting conversations and session timeout workflows. Cancellation records the reason in the run history without a terminal warning; normal run-data retention still applies. Stopping `orcel dev` does not cancel runs whose snapshots remain available, but recovering them on the next start requires `--resume`.

Recovery limits:

- Custom Workflow Worlds do not use this cleanup and recovery policy; `orcel dev --resume` rejects them.
- `orcel dev --resume` refuses to attach to an already running local server. The flag requires starting a server.
- `orcel dev --resume` recovers workflows, not the terminal transcript or a particular TUI conversation.

## `orcel remote`

Use `orcel remote` only with an explicit existing agent URL:

```bash
orcel remote connect --url https://agent.example.com
orcel remote invoke --url https://agent.example.com "Summarize station telemetry"
orcel remote info --url https://agent.example.com
```

`connect` opens the terminal UI. `info` verifies the target and prints its inspection response. Remote commands never start a local application.

### `orcel remote connect`

```bash
orcel remote connect --url <url> [-H "Name: value"]
```

Use `-H, --header <header>` for a bearer token or another custom request header; repeat it for multiple headers. For HTTP Basic authentication, put credentials in the URL. orcel sends them as a Basic `Authorization` header and removes them from the target URL.

### `orcel remote invoke`

```bash
orcel remote invoke --url <url> [prompt] [--resume] [-H "Name: value"] [--scope <team>]
```

Invokes an existing agent without opening the terminal UI. It emits JSON after the invocation completes or reaches a blocking input or authorization event.

| Option                  | Type   | Default  | Description                                     |
| ----------------------- | ------ | -------- | ----------------------------------------------- |
| `<url>`                 | string | required | Existing orcel agent URL                          |
| `[prompt]`              | string | none     | Prompt, follow-up, or answer to a pending input |
| `-H, --header <header>` | string | none     | Request header for the URL target; repeatable   |
| `--resume`              | flag   | off      | Read a previous resumable result from stdin     |
| `--scope <team>`        | string | current  | Vercel team that owns the URL target            |

`--resume` reads a complete previous result from stdin. Supply text for a `ready` follow-up or pending input. An `authorization-required` result lists every unresolved challenge; complete them, then resume without text. Pass headers and scope again when resuming. Paused invocations exit `3`; failures exit `1`. If a waiting invocation receives `SIGINT` or `SIGTERM` after acceptance, it emits a final resumable `running` result before exiting.

### `orcel remote info`

```bash
orcel remote info --url <url> [-H "Name: value"] [--json]
```

Verifies the existing agent and prints its inspection response. Use `-H, --header <header>` for protected targets; repeat it for multiple headers.

## `orcel logs`

```bash
orcel logs            # print the most recent diagnostic log
orcel logs list          # list logs, most recent first
orcel logs show <logid>  # print a specific log
orcel logs --dump     # prepend the log's environment dump
orcel logs --events   # interleave session events from the local workflow store
```

Each interactive `orcel dev` process writes a private diagnostic log under `.orcel/logs/` capturing stderr, stdout (including sandbox and rebuild lines), tool failures, workflow errors, and orcel framework log records — regardless of what the transcript shows. The file is JSON Lines — every line is one JSON record with `at` and `source` fields. `orcel logs` reads those files back.

A log id is the file name without `.log` (for example `dev-2026-07-15T12-00-00.000Z-123`). `orcel logs show <logid>` also accepts the file name, the `.orcel/logs/...` path printed in the dev transcript, or any unambiguous prefix of the id with or without the `dev-` lead — so `orcel logs 2026-07-15` works when a single log matches. An ambiguous prefix fails and lists the candidates.

`orcel logs` prints nothing but records — no path banner on either stream — so `orcel logs 2>&1 | jq -c .` always parses. Discover ids and file paths with `orcel logs list`; `orcel logs list --json` emits a machine-readable array with `id`, `path`, `startedAt`, and `sizeBytes`.

`orcel logs --events` resolves session events (`session.started`, `turn.failed`, message deltas, …) from the local workflow store (`.orcel/.workflow-data`) at query time and interleaves them into the output by timestamp as `source: "event"` records — the log file itself never stores them, so nothing is duplicated at capture time. Selection is by the log's time window (its start through the next log's start), so events from concurrently running `orcel dev` processes may appear.

Each log has a same-named `.dump` sibling holding environment diagnostics and session stats as one JSON document. `orcel logs --dump` (with or without a log id) prepends that document to the JSONL log body; the combined output is a valid JSON value stream (`orcel logs --dump | jq -c .`), one self-contained report to attach to an issue. When a log has no dump, the flag is silently a no-op.

## `orcel traces`

```bash
orcel traces list              # list traces, most recent first
orcel traces list --json       # emit machine-readable trace summaries
orcel traces show         # show the most recent span tree
orcel traces show <trace> # show one span tree
orcel traces --verbose       # expand every span with all attributes and events
orcel traces --json          # dump the full trace as JSON
```

Reads the immutable OTLP/JSON segments under `.orcel/traces/v1`, so `orcel dev` need not be running. Accepts a full trace id, a `gen_ai.conversation.id`, or an unambiguous prefix of either. Malformed segments are skipped without hiding valid spans from the same trace.

Span rows carry inline metrics when the span recorded them — `↑input`/`↓output` token counts, gateway cost, and the tool name for `execute_tool` spans. The header lists models across the trace, sums token usage and cost from step spans, and counts all error-bearing spans. `--verbose` expands each span under its tree row: status (with the error message on failures), timing, ids, every attribute (prompts, responses, and tool payloads as transcripts or pretty-printed JSON), and every span event with its offset from span start. `--json` prints the same records as JSON, one object per selected trace.

Every subagent activation starts its own trace. The first child's `invoke_agent` root links to the dispatching caller with `orcel.link.type=agent.dispatch`; remote agents preserve that caller in W3C `tracestate` even when HTTP `traceparent` advances through platform ingress. Later turns also start fresh traces without repeating the initial caller link. All related sessions retain the same `gen_ai.conversation.id`, and `agent.subagent.name` labels the child invocation.

Each workflow tool call has one `agent.action` span and keeps its `execute_tool <tool>` span. Sessions the tool opens with `ctx.agent` link to that call's `agent.action` span as their dispatching caller; individual `ctx.agent` calls get no span of their own. Only agent execution uses `invoke_agent`.

Outbound MCP `tools/call` requests add MCP semantic attributes to the matching `execute_tool` span. When orcel has no tool span to enrich, it creates a `CLIENT` `tools/call <tool>` span. Each `tools/list` discovery also has a `CLIENT` span. Configured OpenTelemetry propagation fields are injected into MCP `params._meta` for JSON-RPC bodies up to 1 MiB and propagation metadata up to 8 KiB; larger requests are sent unchanged. orcel removes its audience and session-lineage baggage before forwarding, and keeps the input/output content-capture policy local.

A durable conversation produces one bounded trace per turn. Worker replacements reuse the prepared context for the same turn, while a later turn or an independently replayed attempt starts a fresh trace. Passing the conversation ID shows every trace it produced, oldest first.

Every span carries a real duration. A turn's root `invoke_agent` span is written when the turn settles, so a running turn shows only its steps.

Model, `execute_tool`, and memory spans retain their content by default. Set `ORCEL_TRACES_CONTENT=off` to omit system prompts, prompt messages, and response text for models; call arguments and results for tools; and recalled memory records. Each captured value is capped at 32 KB.

Step spans carry token counts under `agent.usage.*`, and cost when Vercel AI Gateway served the call. Model spans also expose `gen_ai.usage.*` token counters. The CLI sums step-level counters only, so model and delegated-call totals are not counted twice.

### Retention

orcel sweeps the store when an activation's writes finish, when a session finishes, and when the dev server starts. An open conversation does not pin every completed turn's trace. Sweeps evict oldest-first past the bounds below, except that active traces, the newest traces, and anything written in the last five minutes are kept. A sweep can therefore exceed the size budget. Set the bounds in `.env.local`, which `orcel dev` loads automatically; each accepts `off` to disable it individually.

| Variable                     | Default              | Effect                                                                                            |
| ---------------------------- | -------------------- | ------------------------------------------------------------------------------------------------- |
| `ORCEL_TRACES`                 | on                   | `off` stops writing traces and stops sweeping                                                     |
| `ORCEL_TRACES_CONTENT`         | on                   | `off` omits model prompt/response, tool input/output, and memory-record attributes on local spans |
| `ORCEL_TRACES_MAX_AGE_MS`      | `604800000` (7d)     | Age after which a trace may be evicted                                                            |
| `ORCEL_TRACES_MAX_TOTAL_BYTES` | `536870912` (512 MB) | Size budget for the whole store                                                                   |
| `ORCEL_TRACES_RETAIN_COUNT`    | `20`                 | Newest traces kept regardless of age or size                                                      |

## `orcel link`

```bash
orcel link
orcel link --non-interactive --project <name-or-id> [--team <team-id-or-slug>]
```

Links the current directory to a Vercel project. After selecting a team, you can create a project named for the agent or link an existing project. The existing-project picker shows recent projects; type a project name and choose **Search for '<name>'** to search the rest of that team's projects. Vercel links the resolved project, orcel verifies its project ID, and then pulls the project's environment so an AI Gateway credential (`VERCEL_OIDC_TOKEN` or `AI_GATEWAY_API_KEY`) lands in `.env.local`. Running it again re-links: the pickers always run, and the new choice wins.

For CI or an agent, pass `--non-interactive` and `--project`. `--project` accepts the same Vercel project name or ID as `vercel link`; `--team` accepts its team ID or slug. The command never opens a picker or browser in this mode. A running `orcel dev` reloads env files automatically, so you don't need to restart after the pull.

## `orcel deploy`

```bash
orcel deploy
orcel deploy --non-interactive --yes [--project <name-or-id>] [--team <team-id-or-slug>]
```

Deploys the agent to Vercel production (`vercel deploy --prod`), installing dependencies first and pulling environment variables after. An already-linked project deploys with or without a TTY. When a terminal is present, an unlinked deployment signs in to Vercel if needed and then walks the `orcel link` pickers.

For CI or an agent, pass `--non-interactive --yes`. `--yes` explicitly confirms the production deployment. With `--project`, orcel links that Vercel project and pulls its environment before deploying; `--team` has the same ID-or-slug semantics as `orcel link`. Without `--project`, the directory must already be linked. The non-interactive mode never opens a picker, browser, or login flow.

## `orcel eval`

```bash
orcel eval [evalId...] [--url <url>] [options]
```

Runs all discovered evals when no eval ids are given; ids match exactly or by directory prefix (`orcel eval weather` runs everything under `evals/weather/`). Exits `0` when every eval passed its checks, `1` when any eval failed (a failed check, an execution error, or a `--strict` threshold miss), `2` on configuration errors.

| Flag                     | Type   | Default | Description                                                   |
| ------------------------ | ------ | ------- | ------------------------------------------------------------- |
| `--url <url>`            | string | none    | Remote agent URL (skip local host startup)                    |
| `--tag <tag...>`         | string | none    | Run only evals carrying a tag                                 |
| `--exclude-tag <tag...>` | string | none    | Skip evals carrying a tag                                     |
| `--strict`               | flag   | off     | Below-threshold scores also fail the exit code                |
| `--list`                 | flag   | off     | Print evals selected by the tag filters, without running them |
| `--timeout <ms>`         | number | none    | Per-eval timeout in milliseconds                              |
| `--max-concurrency <n>`  | number | 8       | Max concurrent eval executions                                |
| `--json`                 | flag   | off     | Output results as JSON                                        |
| `--junit <path>`         | string | none    | Write JUnit XML results to a file                             |
| `--skip-report`          | flag   | off     | Skip eval-defined reporters (e.g. Braintrust)                 |
| `--verbose`              | flag   | off     | Stream per-eval logs and workflow run IDs to stdout           |

See [Evals](../evals/overview) for authoring evals.

## Recommended loop

1. Edit files under `agent/`.
2. `orcel info` to confirm discovery or read diagnostics.
3. `orcel dev` while iterating locally.
4. `orcel build` before shipping.
5. `orcel start` to smoke-test the built output locally.

Related: [Agent Files](/docs/reference/agent-files) · [Instrumentation](../observability/instrumentation).

## What to read next

- [Agent Files](/docs/reference/agent-files): what `orcel info` discovers
- [Instrumentation](../observability/instrumentation): tracing and the error catalog
- [Deployment](../guides/deployment/overview): `orcel build` and `orcel start` in production
