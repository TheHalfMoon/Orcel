const KAF_ORIGIN = "https://github.com/TheHalfMoon/kaf";

export const createLlmsIndex = (): string => `# kaf

> kaf is a filesystem-first, Apache-2.0 framework for building durable backend AI agents that run on Vercel or self-hosted infrastructure. kaf is currently in beta.

Use this file to choose the smallest relevant documentation set. Use \`/sitemap.md\` for the exhaustive page map and \`/llms-full.txt\` only for offline indexing or a large context window. For an installed project, prefer \`node_modules/kaf/docs/\`: those docs match the installed kaf version, while kaf.dev documents the latest release.

kaf.dev publishes framework documentation. It is not a shared API, authorization server, MCP server, or A2A server. Every deployed kaf app exposes its own \`/kaf/v1\` routes and authentication policy. External API, OpenAPI, and MCP URLs in these docs describe third-party connections or examples unless stated otherwise.

Documentation links below point directly to Markdown. Remove the \`.md\` suffix for the canonical HTML page.

## Introduction

- [Getting Started](${KAF_ORIGIN}/docs/getting-started.md): Create a project, configure model credentials, and run your first agent.
- [Project Structure](${KAF_ORIGIN}/docs/concepts/project-structure.md): Choose a layout for agents and application code, add specialist subagents, and grow into an agent workspace.

## Core Concepts

- [Execution Model and Durability](${KAF_ORIGIN}/docs/concepts/execution-model-and-durability.md): Understand sessions, checkpointed steps, and parked work.
- [Sessions, Runs, and Streaming](${KAF_ORIGIN}/docs/concepts/sessions-runs-and-streaming.md): Understand session IDs, NDJSON events, controls, and reconnecting.
- [Default Harness](${KAF_ORIGIN}/docs/concepts/default-harness.md): Understand model context and compaction in the built-in loop.
- [Built-in Tools](${KAF_ORIGIN}/docs/concepts/built-in-tools.md): Review default tools and add opt-in tools such as Workflow, glob, grep, and sleep.
- [Context Control](${KAF_ORIGIN}/docs/concepts/context-control.md): Choose what the model sees and when.
- [Security Model](${KAF_ORIGIN}/docs/concepts/security-model.md): Review trust boundaries, secret handling, credentials, and fail-closed behavior.

## Build

- [Agents](${KAF_ORIGIN}/docs/agent-config.md): Configure the model, reasoning effort, compaction, and runtime behavior.
- [Instructions](${KAF_ORIGIN}/docs/instructions.md): Write the agent's always-on system prompt.
- [Tools](${KAF_ORIGIN}/docs/tools.md): Define typed actions and gate sensitive calls on human approval.
- [Memory](${KAF_ORIGIN}/docs/memory.md): Give an agent cross-session context through kaf-managed slots backed by Supermemory, the built-in file provider, or your own provider.
- [File Memory](${KAF_ORIGIN}/docs/memory/file.md): Configure the built-in bounded document provider and its storage backends.
- [Build a Memory Provider](${KAF_ORIGIN}/docs/memory/custom-provider.md): Implement the recall, capture, and tools contract for any store or memory service.
- [Connections](${KAF_ORIGIN}/docs/connections.md): Connect external MCP and OpenAPI servers without exposing credentials to the model.
- [Channels](${KAF_ORIGIN}/docs/channels/overview.md): Expose the agent through HTTP, Slack, Discord, and other messaging surfaces.
- [Base kaf Channel](${KAF_ORIGIN}/docs/channels/kaf.md): Understand the HTTP API exposed by each running kaf app.
- [Skills](${KAF_ORIGIN}/docs/skills.md): Add procedures that the model loads on demand.
- [Sandbox](${KAF_ORIGIN}/docs/sandbox.md): Configure the isolated shell, filesystem, lifecycle, and network policy.
- [Subagents](${KAF_ORIGIN}/docs/subagents.md): Delegate work to copies of the root agent or declared specialists.
- [Evals](${KAF_ORIGIN}/docs/evals/overview.md): Define repeatable scored checks and run them with \`kaf eval\`.
- [Durable State](${KAF_ORIGIN}/docs/concepts/state.md): Persist per-session memory across step boundaries.
- [Session Context](${KAF_ORIGIN}/docs/guides/session-context.md): Use session metadata and runtime accessors in authored code.
- [Schedules](${KAF_ORIGIN}/docs/schedules.md): Run prompts or handlers on a cron cadence.
- [Hooks](${KAF_ORIGIN}/docs/guides/hooks.md): Subscribe to runtime stream events.
- [Dynamic Capabilities](${KAF_ORIGIN}/docs/guides/dynamic-capabilities.md): Resolve models, tools, skills, subagents, and instructions at runtime.

## Integrate

- [Add Integrations](${KAF_ORIGIN}/docs/install-integrations.md): Discover and add official or third-party integrations.
- [Extensions](${KAF_ORIGIN}/docs/extensions.md): Package and mount reusable kaf capabilities.
- [Remote Agents](${KAF_ORIGIN}/docs/guides/remote-agents.md): Call another kaf deployment as a subagent.
- [Agent Client Protocol (ACP)](${KAF_ORIGIN}/docs/protocols/acp.md): Use local or deployed kaf agents from ACP clients.
- [Universal Commerce Protocol (UCP)](${KAF_ORIGIN}/docs/protocols/ucp.md): Serve a UCP profile from a custom kaf channel.
- [Frontend Frameworks](${KAF_ORIGIN}/docs/guides/frontend/overview.md): Build browser chat interfaces with \`useKafAgent\`.
- [Next.js](${KAF_ORIGIN}/docs/guides/frontend/nextjs.md): Mount kaf routes and use the React client in Next.js.
- [Nuxt](${KAF_ORIGIN}/docs/guides/frontend/nuxt.md): Mount kaf routes and use the Vue client in Nuxt.
- [SvelteKit](${KAF_ORIGIN}/docs/guides/frontend/sveltekit.md): Mount kaf routes and use the Svelte client in SvelteKit.
- [Client SDK](${KAF_ORIGIN}/docs/guides/client/overview.md): Call an kaf app from scripts, services, tests, or custom UIs.

## Operate

- [Deployment Overview](${KAF_ORIGIN}/docs/guides/deployment/overview.md): Choose between Vercel and self-hosted infrastructure.
- [Deploy to Vercel](${KAF_ORIGIN}/docs/guides/deployment/vercel.md): Build and deploy with Vercel Workflow and Vercel Sandbox.
- [Self-Hosting](${KAF_ORIGIN}/docs/guides/deployment/self-hosting.md): Run kaf as a Node service or container.
- [Authentication](${KAF_ORIGIN}/docs/guides/auth-and-route-protection.md): Secure an agent's HTTP routes and establish caller identity.
- [Instrumentation](${KAF_ORIGIN}/docs/observability/instrumentation.md): Configure lifecycle instrumentation and OpenTelemetry destinations.
- [Terminal UI](${KAF_ORIGIN}/docs/guides/dev-tui.md): Work with a local or deployed agent from the interactive terminal UI.

## Tutorial

- [Tutorial](${KAF_ORIGIN}/docs/tutorial/first-agent.md): Build an agent with tools, durable state, and an interface.

## Patterns

- [Multi-Tenant Memory](${KAF_ORIGIN}/docs/patterns/multi-tenant-memory.md): Scope any memory provider to an authenticated tenant and caller.
- [Dynamic Scheduling](${KAF_ORIGIN}/docs/patterns/dynamic-scheduling.md): Build application-managed schedules from an kaf schedule and authored tools.
- [Multi-Tenant Outbound Auth](${KAF_ORIGIN}/docs/patterns/multi-tenant-auth.md): Select tenant-scoped credentials for tools and connections.
- [Multi-Tenant Approvals](${KAF_ORIGIN}/docs/patterns/multi-tenant-approvals.md): Apply tenant policy to authored and connection tools.

## API Reference and Discovery

- [Agent Files](${KAF_ORIGIN}/docs/reference/agent-files.md): Look up filesystem slots, path-derived names, and discovery rules.
- [TypeScript API Reference](${KAF_ORIGIN}/docs/reference/typescript-api.md): Find public \`define*\` helpers, runtime context, and import paths.
- [CLI Reference](${KAF_ORIGIN}/docs/reference/cli.md): Find every kaf command and option.
- [Responsible Use](${KAF_ORIGIN}/docs/responsible-use.md): Review deployer responsibilities and safeguards.
- [Documentation Map](${KAF_ORIGIN}/sitemap.md): Browse every documentation, integration, and template page with type and summary metadata.
- [Agent Instructions](${KAF_ORIGIN}/agents.md): Read operational guidance for coding agents working with kaf.
- [Full Documentation Corpus](${KAF_ORIGIN}/llms-full.txt): Load all docs and integration content for offline indexing or a large context window.

## Optional

- [Changelog](${KAF_ORIGIN}/changelog.md): Read kaf release notes, including breaking changes and fixes. Follow the next-page links for older releases.
- [Integrations](${KAF_ORIGIN}/integrations): Browse official channels, connections, extensions, and observability integrations.
- [Templates](${KAF_ORIGIN}/templates): Browse complete example projects and their source.
- [Official kaf Skill](https://github.com/TheHalfMoon/kaf/blob/main/skills/kaf/SKILL.md): Install or inspect the coding-agent skill; its guidance defers to version-matched bundled docs.
- [Source Repository](https://github.com/TheHalfMoon/kaf): Read source, releases, issues, and contribution guidance.
`;
