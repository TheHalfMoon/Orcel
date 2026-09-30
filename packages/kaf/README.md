# kaf

Kaf is a filesystem-first framework for durable backend AI agents that run anywhere.

You author an agent as a directory on disk. The directory is the contract — markdown for the parts a human should read like a spec, TypeScript for the parts that benefit from real types and runtime behavior.

The framework is called kaf. The published npm package is `kaf`. The CLI binary is `kaf`.

## Preview Terms and Safeguards

Kaf is under active development; the framework, APIs, documentation, and behavior may change before the first stable release.

As the deployer, it is your responsibility to ensure your agent complies with applicable laws.

You are responsible for configuring approval policies, tool restrictions, connection scopes, route/session authorization, sandbox controls, telemetry exports, and other safeguards appropriate for your use case.

Before using kaf with non-public, sensitive, regulated, or production data, review which default tools, custom tools, MCP tools, shell/file/web tools, connected services, subagents, schedules, and external actions are available to the agent.

Require human approval or other safeguards for sensitive, irreversible, regulated, financial, healthcare, employment, housing, legal, safety-impacting, user-impacting, or external side-effecting actions.

Unless you configure stricter controls, kaf agents may operate with permissive settings, including tool execution without human approval where approval is omitted and sandbox network egress that is not deny-all. Do not rely on model behavior alone to prevent sensitive or irreversible actions.

## What kaf Prioritizes

- Markdown-first authoring for instructions and procedures
- TypeScript where typed runtime behavior matters
- Durable message runs and follow-up turns
- Inspectable compiled artifacts under `.kaf/`
- Per-agent sandbox with optional authored overrides
- A stable HTTP protocol built around immutable session IDs
- A runtime model that keeps channels, harnesses, and workflow execution separate

## Authored Directory

```text
my-agent/
├── package.json
├── tsconfig.json
└── agent/
    ├── agent.ts           # additive runtime config (model, name, build, compaction, …)
    ├── instructions.md    # always-on instructions prompt
    ├── tools/             # typed executable integrations
    ├── skills/            # optional named procedures the model can load on demand
    ├── hooks/             # lifecycle and stream-event subscribers
    ├── channels/          # message ingress and delivery (HTTP, Slack, …)
    ├── connections/       # external MCP server connections
    ├── sandbox/           # the agent's single sandbox (optional override)
    ├── workspace/         # files seeded into the sandbox on each session
    ├── subagents/         # specialist child agents (reuse `defineAgent`)
    ├── schedules/         # recurring jobs
    └── lib/               # shared authored code imported by other files
```

## Authoring Helpers

Every authored directory has a typed helper. Import each from the matching subpath:

| Helper                                                          | Subpath                               | Authored Location                                |
| --------------------------------------------------------------- | ------------------------------------- | ------------------------------------------------ |
| `defineAgent(...)`                                              | `kaf`                                 | `agent.ts`, `subagents/<id>/agent.ts`            |
| `defineInstructions(...)`                                       | `kaf/instructions`                    | `instructions.ts` (or `instructions.md`)         |
| `defineTool(...)`, `defineDynamic(...)`, `disableTool(...)`     | `kaf/tools`                           | `tools/<name>.ts`                                |
| `bash`, `readFile`, `writeFile`, and other provided definitions | `kaf/tools/<name>`                    | `tools/<name>.ts`                                |
| `defineSkill(...)`                                              | `kaf/skills`                          | `skills/<name>.ts` (or `skills/<name>.md`)       |
| `defineHook(...)`                                               | `kaf/hooks`                           | `hooks/<slug>.ts`                                |
| `defineChannel(...)`, `POST`, `GET`                             | `kaf/channels`                        | `channels/<name>.ts`                             |
| `kafChannel(...)`, `slackChannel(...)`, `vercelOidc(...)`       | `kaf/channels/kaf`, `/slack`, `/auth` | reused from `channels/<name>.ts`                 |
| `defineSandbox(...)`                                            | `kaf/sandbox`                         | `sandbox.ts` (or `sandbox/sandbox.ts`)           |
| `defineSchedule(...)`                                           | `kaf/schedules`                       | `schedules/<name>.ts` (or `schedules/<name>.md`) |
| `defineEval(...)`, `defineEvalConfig(...)`                      | `kaf/evals`                           | `evals/<name>.eval.ts`, `evals/evals.config.ts`  |

Runtime accessors live on the subpath that owns the concern:

- `getSession()` — current session, turn, auth, parent lineage (`kaf/context`)
- `getSandbox()` — live sandbox handle for the current agent (`kaf/sandbox`)
- `getContext(key)`, `requireContext(key)`, `hasContext(key)`, `setContext(key)`, `ensureContext(key, factory)` — unified context helpers (`kaf/context`)

The complete API reference, including types and lower-level runtime primitives, is in the [TypeScript API Reference](https://github.com/TheHalfMoon/kaf/docs/reference/typescript-api).

## Tiny Example

`agent/instructions.md`

```md
You are a weather-focused assistant. Be concise, accurate, and explicit when you use a tool.
```

`agent/tools/get_weather.ts`

```ts
import { defineTool } from "kaf/tools";
import { z } from "zod";

export default defineTool({
  description: "Get the current weather for a city.",
  inputSchema: z.object({
    city: z.string(),
  }),
  async execute(input) {
    return {
      city: input.city,
      condition: "Sunny",
      temperatureF: 72,
    };
  },
});
```

`agent/agent.ts`

```ts
import { defineAgent } from "kaf";

export default defineAgent({
  model: "openai/gpt-5.4-mini",
});
```

## Quick Start

```bash
npx kaf@latest init my-agent
```

`kaf init` writes a new agent with kaf's default model. Pass `--model
openai/gpt-5.5` to choose another AI Gateway model, `--reasoning high` to set a
reasoning effort, or `--channel-web-nextjs` to add the Web Chat application. It
installs dependencies, initializes Git, and starts the development server. When
it finds a supported coding-agent REPL, the handoff menu can open that REPL
instead or exit. Targeting an existing project directory (`kaf init .`) adds the
agent files and missing dependencies instead. It does not create a Vercel
project or deploy the agent.

CLI commands:

- `kaf` (including `npx kaf`) — initialize the current directory, or start development in a Kaf project
- `kaf init <name>` — create a new agent
- `kaf info` — discovery results and compiled artifacts
- `kaf build` — compile `.kaf/` and build the host output
- `kaf start` — serve the built `.output/` app
- `kaf dev` — start the local runtime and REPL
- `kaf set [--model <model-id>] [--reasoning <effort>]` — change root model settings
- `kaf extension init <name>` — create a new extension package
- `kaf extension build` — build an extension package

## Deploying

kaf is built to be durable. The runtime is Nitro + Workflows. Read the [deployment guide](https://github.com/TheHalfMoon/kaf/docs/guides/deployment/overview) for the deployment path, environment variables, and configuration.

## Read Next

These files ship inside the installed package at `node_modules/kaf/docs/`:

- [Full docs index](https://github.com/TheHalfMoon/kaf/docs) — recommended entry point
- [Getting Started](https://github.com/TheHalfMoon/kaf/docs/getting-started) — install, scaffold, and run locally
- [Project Layout](https://github.com/TheHalfMoon/kaf/docs/getting-started#project-layout) — every authored directory in depth
- [`agent.ts`](https://github.com/TheHalfMoon/kaf/docs/agent-config) — agent config reference
- [Automatic Model Selection](https://github.com/TheHalfMoon/kaf/docs/guides/evaluate) — choose an agent model for each request
- [TypeScript API Reference](https://github.com/TheHalfMoon/kaf/docs/reference/typescript-api) — complete `define*` and runtime helper reference
- [Vercel Deployment](https://github.com/TheHalfMoon/kaf/docs/guides/deployment/overview) — deploy to production

By authoring concern: [Tools](https://github.com/TheHalfMoon/kaf/docs/tools) · [Channels](https://github.com/TheHalfMoon/kaf/docs/channels/overview) · [Hooks](https://github.com/TheHalfMoon/kaf/docs/guides/hooks) · [Skills](https://github.com/TheHalfMoon/kaf/docs/skills) · [Sandbox](https://github.com/TheHalfMoon/kaf/docs/sandbox) · [Connections](https://github.com/TheHalfMoon/kaf/docs/connections) · [Subagents](https://github.com/TheHalfMoon/kaf/docs/subagents) · [Schedules](https://github.com/TheHalfMoon/kaf/docs/schedules) · [Evals](https://github.com/TheHalfMoon/kaf/docs/evals/overview)

By runtime concern: [Sessions and Streaming](https://github.com/TheHalfMoon/kaf/docs/concepts/sessions-runs-and-streaming) · [Session Context](https://github.com/TheHalfMoon/kaf/docs/guides/session-context) · [Context Control](https://github.com/TheHalfMoon/kaf/docs/concepts/context-control) · [Auth and Route Protection](https://github.com/TheHalfMoon/kaf/docs/guides/auth-and-route-protection) · [CLI, Build, and Debugging](https://github.com/TheHalfMoon/kaf/docs/reference/cli) · [Instrumentation](https://github.com/TheHalfMoon/kaf/docs/guides/instrumentation)

## Architecture (Internals)

You do not need this section to author a Kaf agent — it documents the public HTTP protocol contracts so kaf composes predictably with other systems.

kaf's internal split is:

- the **channel** normalizes inbound transport, applies auth and delivery policy, and owns channel-local addresses
- the **harness** does one unit of AI work and returns `{ session, next }`
- the **runtime** persists state, follows `next`, streams events, and owns workflow primitives (`start()`, `resumeHook()`, `createHook()`, `getWritable()`)

The public HTTP protocol exposes one immutable identifier: `sessionId`. Create a
session explicitly, then use that ID for follow-up messages, controls, streaming,
and inspection. Channel-local addresses remain behind authored channel APIs.

## Changelog

See [`./CHANGELOG.md`](./CHANGELOG.md) for the release history. The changelog ships inside the published package so agents can read it directly from `node_modules/kaf/CHANGELOG.md` to evaluate upgrades.
