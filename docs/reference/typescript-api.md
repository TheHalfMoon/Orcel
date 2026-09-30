---
title: "TypeScript API Reference"
description: "The define* helpers, the runtime ctx, and where each one is imported from."
---

This is the public surface of the `kaf` package: the `define*` helpers you author with, the `ctx` they receive at runtime, and the import path for each. The package's export map defines the full contract; source files that are not reachable through an exported package subpath are framework internals.

Identity comes from the filesystem, not a field you set. A tool at `agent/tools/get_weather.ts` is `get_weather`, and a connection at `agent/connections/linear.ts` is `linear`, so no definition carries a `name` or `id`.

Most files look the same: import a helper, default-export the result.

```ts title="agent/agent.ts"
import { defineAgent } from "kaf";

export default defineAgent({ model: "anthropic/claude-opus-5.5" });
```

```ts title="agent/tools/get_weather.ts"
import { defineTool } from "kaf/tools";
import { z } from "zod";

export default defineTool({
  description: "Get the weather for a city.",
  inputSchema: z.object({ city: z.string() }),
  async execute({ city }, ctx) {
    return { city, condition: "Sunny" };
  },
});
```

## The define\* helpers

| Helper                                                | Import from                                                             | Authored at                                                                            | Guide                                                  |
| ----------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `defineAgent`                                         | `kaf`                                                                   | `agent/agent.ts`                                                                       | [agent.ts](../agent-config)                            |
| `defineTool`                                          | `kaf/tools`                                                             | `agent/tools/<name>.ts`                                                                | [Tools](../tools)                                      |
| `defineDurableCallback`                               | `kaf/tools`                                                             | provider-package dynamic tool factories                                                | [Dynamic capabilities](../guides/dynamic-capabilities) |
| `defineDurableSchema`                                 | `kaf/tools`                                                             | provider-package dynamic input and output schemas                                      | [Dynamic capabilities](../guides/dynamic-capabilities) |
| `defineWorkflowTool`                                  | `kaf/tools`                                                             | `agent/tools/<name>.ts`                                                                | [Workflow tools](../tools/workflows)                   |
| `defineDynamic`                                       | `kaf`, `kaf/tools`, `kaf/skills`, `kaf/instructions`, `kaf/connections` | dynamic model or subagent `agent.ts`; `agent/{tools,skills,instructions,connections}/` | [Dynamic capabilities](../guides/dynamic-capabilities) |
| `defineMcpClientConnection`                           | `kaf/connections`                                                       | `agent/connections/<name>.ts`                                                          | [MCP connections](../connections/mcp)                  |
| `defineOpenAPIConnection`                             | `kaf/connections`                                                       | `agent/connections/<name>.ts`                                                          | [OpenAPI connections](../connections/openapi)          |
| `defineChannel`                                       | `kaf/channels`                                                          | `agent/channels/<name>.ts`                                                             | [Custom channels](../channels/custom)                  |
| `kafChannel`, `slackChannel`, and the other platforms | `kaf/channels/<platform>`                                               | `agent/channels/<platform>.ts`                                                         | [Channels](../channels/overview)                       |
| `defineSkill`                                         | `kaf/skills`                                                            | `agent/skills/<name>.ts`                                                               | [Skills](../skills)                                    |
| `defineInstructions`                                  | `kaf/instructions`                                                      | `agent/instructions.ts`                                                                | [Instructions](../instructions)                        |
| `defineMemory`, `defineMemoryProvider`                | `kaf/memory`                                                            | `agent/memory.ts` or `agent/memory/<slot>.ts`                                          | [Memory](../memory)                                    |
| `defineHook`                                          | `kaf/hooks`                                                             | `agent/hooks/<slug>.ts`                                                                | [Hooks](../guides/hooks)                               |
| `defineSchedule`                                      | `kaf/schedules`                                                         | `agent/schedules/<name>.ts`                                                            | [Schedules](../schedules)                              |
| `defineState`                                         | `kaf/context`                                                           | tools, hooks, lifecycle                                                                | [Session context](../guides/session-context)           |
| `defineSandbox`                                       | `kaf/sandbox`                                                           | `agent/sandbox.ts`                                                                     | [Sandbox](../sandbox)                                  |
| `defineInstrumentation`                               | `kaf/instrumentation`                                                   | `agent/instrumentation/<name>.ts`                                                      | [Instrumentation](../observability/instrumentation)    |
| `otel`, `otelIntegration`                             | `kaf/instrumentation/otel`                                              | `agent/instrumentation/<destination>.ts`                                               | [OpenTelemetry](../observability/otel)                 |
| `defineRemoteAgent`                                   | `kaf`                                                                   | `agent/subagents/<id>/agent.ts`                                                        | [Remote agents](../guides/remote-agents)               |
| `defineEval`                                          | `kaf/evals`                                                             | `evals/*.eval.ts`                                                                      | [Evals](../evals/overview)                             |
| `defineEvalConfig`                                    | `kaf/evals`                                                             | `evals/evals.config.ts`                                                                | [Evals](../evals/overview)                             |
| `mockModel`                                           | `kaf/evals`                                                             | Deterministic fixture agent models                                                     | [Evals](../evals/overview)                             |
| `useKafAgent`                                         | `kaf/react`, `kaf/vue`, `kaf/svelte`                                    | frontend                                                                               | [Frontend](../guides/frontend/overview)                |

Tool-wide authoring helpers and types such as `defineTool`, `defineWorkflowTool`, `defineDurableCallback`, `defineDurableSchema`, `defineDynamic`, `disableTool`, and `ToolLabelDefinition` come from `kaf/tools`. Capability-specific definitions and helpers use their own subpaths (see [Built-in tools](../concepts/built-in-tools)): reusable definitions such as `bash` and `glob` come from `kaf/tools/<name>`, `webSearch` comes from `kaf/tools/web_search`, `agentRouter` comes from `kaf/tools/agent-router`, `sleep` comes from `kaf/tools/sleep`, and approval policies and types come from `kaf/tools/approval`. The route verbs `GET`/`HEAD`/`POST`/`PUT`/`PATCH`/`DELETE`/`OPTIONS`/`WS` plus `disableRoute` come from `kaf/channels`, and the channel auth helpers `localDev`/`vercelOidc`/`placeholderAuth` come from `kaf/channels/auth`.

`AgentReasoningDefinition` is exported from `kaf` for the top-level `defineAgent({ reasoning })` setting. `AgentLimitsDefinition` is exported for `defineAgent({ limits })`. `AgentWorkflowDefinition`, `AgentWorkflowRetentionDefinition`, and `AgentWorkflowWorldDefinition` are exported from `kaf` for the `defineAgent({ experimental: { workflow } })` config shape. `WebSearchToolInput` and `WebSearchProvider` are exported from `kaf/tools/web_search`.

`defineInstructions` accepts `{ content: string, role?: "system" | "user" }`; omitted `role` means `"system"`. Its `kaf/instructions` version of `defineDynamic` accepts only `session.started` and `turn.started` handlers returning `defineInstructions(...)` or `null`. The legacy `{ markdown: string }` definition remains available as a deprecated system-role form.

The `kaf/connections` version of `defineDynamic` accepts `session.started` and
`turn.started` handlers returning one MCP or OpenAPI connection definition, a
map of connection definitions, or `null`. Its resolver context exposes
authenticated session identity and `channel.kind`, but not conversation history,
delivery payloads, tool inputs, model outputs, or free-form channel metadata. An
authenticated returned definition must set `instanceKey` to a stable,
non-secret account or tenant identifier so durable authorization resumes cannot
cross resolved instances.

## Authored module lifecycle

kaf evaluates TypeScript definition modules during compilation so it can validate and normalize the agent. Within one agent node, each module namespace loads at most once during that compile. The resolved definition then determines whether the module is also an entry in the runtime bundle:

| Lifecycle           | Authored definitions                                                                                                                                                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Compile only        | Static instructions and skills, prompt-form TypeScript schedules, static Gateway or default agent config, provider-managed web search, Workflow SDK configuration, fully shadowed channels, and a child sandbox that selects its parent's sandbox |
| Compile and runtime | Dynamic instructions, skills, tools, models, and subagents; executable tools; effective channels; connections; hooks; memory; handler schedules; direct-provider models; independent sandboxes; and remote subagents                              |
| Runtime only        | Instrumentation modules and extension mount initialization                                                                                                                                                                                        |

A compile-only module is not imported when the deployed runtime starts. For example, kaf stores the resolved content from a static `instructions.ts` in the compiled manifest. A compile-and-runtime module is evaluated during compilation and imported again when a runtime process loads the module map. Keep module-top-level work deterministic, and put request- or session-specific work in the definition's runtime callbacks.

The runtime bundler follows the normal ESM graph from every runtime entry. A helper remains runtime code when a tool or other runtime entry imports it, even if static instructions also import that helper. Lifecycle selection applies to definition entries, not as tree-shaking permission for their ordinary dependencies.

### Asset imports

Authored modules may import relative non-code assets from anywhere inside their project package, including outside `agent/`:

```ts title="agent/tools/read_template.ts"
import icon from "../../assets/icon.png";
import template from "../../prompts/template.txt?raw";
```

`?raw` embeds the file as UTF-8 text. Other non-code asset imports produce a data URL with an inferred media type. Compilation, local development, and production builds use the same resolution behavior. Imports that escape the project package are rejected; package those files with the application instead.

## Runtime context (`ctx`)

`ctx` is passed to your tool `execute`, hook handlers, channel event handlers, and connection auth/header resolvers. It is live only while authored code is running, so reaching for it at module top level throws. See [Session context](../guides/session-context) for the full model.

| Member                      | Use                                                                          |
| --------------------------- | ---------------------------------------------------------------------------- |
| `ctx.session`               | Current session, turn, auth, and optional parent lineage (read-only)         |
| `ctx.getSandbox()`          | Live sandbox handle; `stop()` releases compute but preserves durable state   |
| `ctx.getToken(provider)`    | Resolve a bearer token for an inline auth provider such as `connect("...")`  |
| `ctx.requireAuth(provider)` | Evict and re-authorize an inline provider, commonly after a downstream `401` |

Tool definitions accept `availableInSubagents: false` to restrict the tool to top-level root sessions. Authored workflow bodies also receive `ctx.agents`, a replay-stable map of callable-agent metadata, and `ctx.agent(name)`, which returns an `AgentSession` whose `send(message, options?)` resolves to a response with `result()`. A `"use step"` helper that receives the context directly should type it as `WorkflowStepToolContext`, which excludes `agents`, `agent`, and `ask`. The root-copy `agent` entry has an empty description when the root omits `description`. See [Workflows as tools](../tools/workflows#delegate-work-ctxagent) for the workflow-only context.

## Imports at a glance

| Import                                                                 | Holds                                                                                                                          |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `kaf`                                                                  | `defineAgent`, `defineRemoteAgent`, `defineDynamic`, agent config types                                                        |
| `kaf/tools`                                                            | `defineTool`, `defineWorkflowTool`, `defineDurableCallback`, `defineDurableSchema`, `defineDynamic`, `disableTool`, tool types |
| `kaf/tools/{bash,read_file,write_file,web_fetch,load_skill,glob,grep}` | Individual reusable tool definitions                                                                                           |
| `kaf/tools/approval`                                                   | Approval types and `auto`, `always`, `once`, `never`                                                                           |
| `kaf/tools/ask_question`                                               | Opt-in `askQuestion` tool factory                                                                                              |
| `kaf/tools/web_search`                                                 | Provider-managed `webSearch` configuration                                                                                     |
| `kaf/tools/workflow`                                                   | Runtime-generated `workflow` tool factory                                                                                      |
| `kaf/tools/sleep`                                                      | Opt-in durable `sleep` tool                                                                                                    |
| `kaf/connections`                                                      | `defineMcpClientConnection`, `defineOpenAPIConnection`, `defineDynamic`                                                        |
| `kaf/channels`                                                         | `defineChannel`, `disableRoute`, route verbs                                                                                   |
| `kaf/channels/kaf`                                                     | `kafChannel`                                                                                                                   |
| `kaf/channels/auth`                                                    | `localDev`, `vercelOidc`, `placeholderAuth`                                                                                    |
| `kaf/channels/{slack,discord,teams,telegram,twilio,github}`            | platform channel factories                                                                                                     |
| `kaf/hooks`                                                            | `defineHook`                                                                                                                   |
| `kaf/schedules`                                                        | `defineSchedule`                                                                                                               |
| `kaf/skills`                                                           | `defineSkill`, `defineDynamic`                                                                                                 |
| `kaf/instructions`                                                     | `defineInstructions`, `defineDynamic`                                                                                          |
| `kaf/memory`                                                           | `defineMemory`, `defineMemoryProvider`, provider and lifecycle types                                                           |
| `kaf/memory/scope`                                                     | `byPrincipal` and memory scope helpers                                                                                         |
| `kaf/memory/file`                                                      | `fileMemory`, `inMemory`, and the conditional document backend contract                                                        |
| `kaf/memory/file/vercel`                                               | `vercelBlob` and Vercel Blob backend options                                                                                   |
| `kaf/context`                                                          | `defineState`, session and state types                                                                                         |
| `kaf/sandbox`                                                          | `defineSandbox`, provider environments, and sandbox session types                                                              |
| `kaf/instrumentation`                                                  | `defineInstrumentation`, `disableInstrumentation`, `isChannel`, lifecycle provider types                                       |
| `kaf/instrumentation/otel`                                             | `otel`, `otelIntegration`, `localTraces`, `agentRuns`, OpenTelemetry policy types                                              |
| `kaf/local-dev`                                                        | `getLocalDevCapability`, `LocalDevCapability`                                                                                  |
| [`kaf/models`](../guides/evaluate)                                     | Automatic model selection with `auto`                                                                                          |
| `kaf/models/openai`                                                    | `openai`, `chatgpt`, deprecated `experimental_chatgpt`                                                                         |
| `kaf/models/anthropic`                                                 | `anthropic`                                                                                                                    |
| [`kaf/ai`](../guides/evaluate#evaluate-inside-a-tool)                  | Standalone `evaluate`                                                                                                          |
| `kaf/evals`                                                            | `defineEval`, `defineEvalConfig`, `mockModel`, eval types                                                                      |
| `kaf/evals/expect`                                                     | `includes`, `equals`, `matches`, `similarity`                                                                                  |
| `kaf/evals/reporters`                                                  | `Braintrust`, `JUnit`, `EvalReporter`                                                                                          |
| `kaf/evals/loaders`                                                    | `loadJson`, `loadYaml`                                                                                                         |
| `kaf/react`, `kaf/vue`, `kaf/svelte`                                   | `useKafAgent`                                                                                                                  |
| `kaf/next`, `kaf/nuxt`, `kaf/sveltekit`                                | framework bundler plugins                                                                                                      |
| [`kaf/client`](../guides/client/overview)                              | `Client`, `ClientSession`, health and agent-info schemas, response errors                                                      |

Exported types ship from the same entrypoint as the helper they describe (for example `ToolDefinition` and `ToolContext` from `kaf/tools`). The `exports` field in `packages/kaf/package.json` lists every public entrypoint.

## Direct provider models

`openai(model?)` from `kaf/models/openai` and `anthropic(model?)` from `kaf/models/anthropic` return kaf-owned model instances using the vendored providers. They accept only an optional model ID. Defaults are `gpt-6-luna-fast` and `claude-sonnet-5`, respectively.

Use `/login` for local credentials, or set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. Local secret-store discovery is disabled in deployments; provision server credentials explicitly. See [Set the model](../agent-config#set-the-model) for an example.

## ChatGPT subscription models

`chatgpt()` from `kaf/models/openai` serves an OpenAI model through your local ChatGPT login and bills the ChatGPT subscription. With no argument, it selects `gpt-6-luna-fast`:

```ts title="agent/agent.ts"
import { defineAgent } from "kaf";
import { chatgpt } from "kaf/models/openai";

export default defineAgent({
  model: chatgpt(),
});
```

Pass another bare OpenAI model slug to override the default. `experimental_chatgpt()` remains as a deprecated alias.

`chatgpt()` uses stateless requests (`store: false`). kaf retains reasoning summaries and encrypted reasoning in session history and replays them after tool calls and on later turns. You do not need to configure `reasoning.encrypted_content` explicitly.

kaf uses one local authentication path with two credential owners:

1. Run `kaf dev`, open `/login`, and select **ChatGPT subscription**.
2. If `codex` is on `PATH`, kaf uses `codex app-server` and launches `codex login` when sign-in is needed. Codex owns credential storage and refresh.
3. If the Codex binary is not found, kaf falls back to direct browser sign-in and owns the saved session and refresh. If the browser does not open, use the URL printed in the terminal.

When Codex is available, kaf asks app-server for tokens and does not read or write Codex login files. App-server errors other than a missing binary are reported instead of silently switching credential owners.

For the kaf-owned fallback, kaf stores your refresh token and account details in your operating system's credential store through [just-secrets](https://github.com/vercel-labs/just-secrets): the login Keychain on macOS, Credential Manager on Windows, or Secret Service on Linux. Access tokens stay in process memory; a new kaf process refreshes the saved session when it first needs a token. The fallback login is separate from Codex and is never written to your project.

If you previously used kaf's `~/.kaf/auth/chatgpt.json` file, sign in once through the kaf-owned fallback after upgrading. A successful save removes the old plaintext session file. kaf does not fall back to file storage if the OS credential store is unavailable.

Linux, including WSL, requires `/usr/bin/secret-tool` (commonly provided by `libsecret-tools`), a session D-Bus, and an unlocked Secret Service keyring. On macOS, unlock your login keychain and allow credential access if prompted. On Windows, PowerShell and Credential Manager must be available in your user session. OS credential storage protects secrets at rest; it does not guarantee isolation from malicious processes running as your OS user.

For the kaf-owned fallback, SSH sessions or a busy localhost port 1455 use a device code. Open the displayed link in a browser and enter the code. Device sign-in requires enabling device code authorization in **ChatGPT Settings → Security**, or having a workspace admin enable it in workspace permissions. Sign-in times out after five minutes; press **Ctrl+C** to cancel sooner. Device sign-in still requires an available OS credential store; use an API-key model in headless environments without one.

ChatGPT subscription credentials are local user credentials. `kaf deploy` blocks agents whose active model is `chatgpt()` because those credentials are not uploaded to a deployment. Use an environment branch with a deployable model, or switch to an AI Gateway model before deploying.

Troubleshooting:

- **`chatgpt-sub login`**: open `/login` and select **ChatGPT subscription** to sign in again. kaf launches `codex login` when Codex is available, or its direct sign-in flow when it is not.
- **`chatgpt-sub unavailable` with Codex installed**: update or restart Codex and retry. kaf does not mask app-server failures by switching to a different saved session.
- **`chatgpt-sub unavailable` without Codex**: follow the reported OS credential-store recovery steps, or check your network connection if token refresh failed. Retry from `/login`. If kaf reports an invalid stored session, sign in again to replace it.
- **Model rejected by the backend**: model availability depends on the signed-in ChatGPT account. Pick another supported OpenAI model.
- **Device sign-in unavailable**: enable device code authorization in ChatGPT security settings, or sign in from a local terminal with port 1455 available.

## What to read next

- [`agent.ts`](../agent-config): the agent config these helpers configure
- [Tools](../tools): `defineTool`, the most-used helper
- [Agent Files](/docs/reference/agent-files): where each define\* lives on disk
