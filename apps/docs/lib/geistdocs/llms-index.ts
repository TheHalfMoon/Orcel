const ORCEL_ORIGIN = "https://github.com/TheHalfMoon/orcel";

export const createLlmsIndex = (): string => `# orcel

> orcel is a filesystem-first, Apache-2.0 framework for building durable backend AI agents that run on Vercel or self-hosted infrastructure. orcel is currently in beta.

Use this file to choose the smallest relevant documentation set. Use \`/sitemap.md\` for the exhaustive page map and \`/llms-full.txt\` only for offline indexing or a large context window. For an installed project, prefer \`node_modules/orcel/docs/\`: those docs match the installed orcel version, while orcel.dev documents the latest release.

orcel.dev publishes framework documentation. It is not a shared API, authorization server, MCP server, or A2A server. Every deployed orcel app exposes its own \`/orcel/v1\` routes and authentication policy. External API, OpenAPI, and MCP URLs in these docs describe third-party connections or examples unless stated otherwise.

Documentation links below point directly to Markdown. Remove the \`.md\` suffix for the canonical HTML page.

## Introduction

- [Getting Started](${ORCEL_ORIGIN}/docs/getting-started.md): Create a project, configure model credentials, and run your first agent.
- [Project Structure](${ORCEL_ORIGIN}/docs/concepts/project-structure.md): Choose a layout for agents and application code, add specialist subagents, and grow into an agent workspace.

## Core Concepts

- [Execution Model and Durability](${ORCEL_ORIGIN}/docs/concepts/execution-model-and-durability.md): Understand sessions, checkpointed steps, and parked work.
- [Sessions, Runs, and Streaming](${ORCEL_ORIGIN}/docs/concepts/sessions-runs-and-streaming.md): Understand session IDs, NDJSON events, controls, and reconnecting.
- [Default Harness](${ORCEL_ORIGIN}/docs/concepts/default-harness.md): Understand model context and compaction in the built-in loop.
- [Built-in Tools](${ORCEL_ORIGIN}/docs/concepts/built-in-tools.md): Review default tools and add opt-in tools such as Workflow, glob, grep, and sleep.
- [Context Control](${ORCEL_ORIGIN}/docs/concepts/context-control.md): Choose what the model sees and when.
- [Security Model](${ORCEL_ORIGIN}/docs/concepts/security-model.md): Review trust boundaries, secret handling, credentials, and fail-closed behavior.

## Build

- [Agents](${ORCEL_ORIGIN}/docs/agent-config.md): Configure the model, reasoning effort, compaction, and runtime behavior.
- [Instructions](${ORCEL_ORIGIN}/docs/instructions.md): Write the agent's always-on system prompt.
- [Tools](${ORCEL_ORIGIN}/docs/tools.md): Define typed actions and gate sensitive calls on human approval.
- [Memory](${ORCEL_ORIGIN}/docs/memory.md): Give an agent cross-session context through orcel-managed slots backed by Supermemory, the built-in file provider, or your own provider.
- [File Memory](${ORCEL_ORIGIN}/docs/memory/file.md): Configure the built-in bounded document provider and its storage backends.
- [Build a Memory Provider](${ORCEL_ORIGIN}/docs/memory/custom-provider.md): Implement the recall, capture, and tools contract for any store or memory service.
- [Connections](${ORCEL_ORIGIN}/docs/connections.md): Connect external MCP and OpenAPI servers without exposing credentials to the model.
- [Channels](${ORCEL_ORIGIN}/docs/channels/overview.md): Expose the agent through HTTP, Slack, Discord, and other messaging surfaces.
- [Base orcel Channel](${ORCEL_ORIGIN}/docs/channels/orcel.md): Understand the HTTP API exposed by each running orcel app.
- [Skills](${ORCEL_ORIGIN}/docs/skills.md): Add procedures that the model loads on demand.
- [Sandbox](${ORCEL_ORIGIN}/docs/sandbox.md): Configure the isolated shell, filesystem, lifecycle, and network policy.
- [Subagents](${ORCEL_ORIGIN}/docs/subagents.md): Delegate work to copies of the root agent or declared specialists.
- [Evals](${ORCEL_ORIGIN}/docs/evals/overview.md): Define repeatable scored checks and run them with \`orcel eval\`.
- [Durable State](${ORCEL_ORIGIN}/docs/concepts/state.md): Persist per-session memory across step boundaries.
- [Session Context](${ORCEL_ORIGIN}/docs/guides/session-context.md): Use session metadata and runtime accessors in authored code.
- [Schedules](${ORCEL_ORIGIN}/docs/schedules.md): Run prompts or handlers on a cron cadence.
- [Hooks](${ORCEL_ORIGIN}/docs/guides/hooks.md): Subscribe to runtime stream events.
- [Dynamic Capabilities](${ORCEL_ORIGIN}/docs/guides/dynamic-capabilities.md): Resolve models, tools, skills, subagents, and instructions at runtime.

## Integrate

- [Add Integrations](${ORCEL_ORIGIN}/docs/install-integrations.md): Discover and add official or third-party integrations.
- [Extensions](${ORCEL_ORIGIN}/docs/extensions.md): Package and mount reusable orcel capabilities.
- [Remote Agents](${ORCEL_ORIGIN}/docs/guides/remote-agents.md): Call another orcel deployment as a subagent.
- [Agent Client Protocol (ACP)](${ORCEL_ORIGIN}/docs/protocols/acp.md): Use local or deployed orcel agents from ACP clients.
- [Universal Commerce Protocol (UCP)](${ORCEL_ORIGIN}/docs/protocols/ucp.md): Serve a UCP profile from a custom orcel channel.
- [Frontend Frameworks](${ORCEL_ORIGIN}/docs/guides/frontend/overview.md): Build browser chat interfaces with \`useOrcelAgent\`.
- [Next.js](${ORCEL_ORIGIN}/docs/guides/frontend/nextjs.md): Mount orcel routes and use the React client in Next.js.
- [Nuxt](${ORCEL_ORIGIN}/docs/guides/frontend/nuxt.md): Mount orcel routes and use the Vue client in Nuxt.
- [SvelteKit](${ORCEL_ORIGIN}/docs/guides/frontend/sveltekit.md): Mount orcel routes and use the Svelte client in SvelteKit.
- [Client SDK](${ORCEL_ORIGIN}/docs/guides/client/overview.md): Call an orcel app from scripts, services, tests, or custom UIs.

## Operate

- [Deployment Overview](${ORCEL_ORIGIN}/docs/guides/deployment/overview.md): Choose between Vercel and self-hosted infrastructure.
- [Deploy to Vercel](${ORCEL_ORIGIN}/docs/guides/deployment/vercel.md): Build and deploy with Vercel Workflow and Vercel Sandbox.
- [Self-Hosting](${ORCEL_ORIGIN}/docs/guides/deployment/self-hosting.md): Run orcel as a Node service or container.
- [Authentication](${ORCEL_ORIGIN}/docs/guides/auth-and-route-protection.md): Secure an agent's HTTP routes and establish caller identity.
- [Instrumentation](${ORCEL_ORIGIN}/docs/observability/instrumentation.md): Configure lifecycle instrumentation and OpenTelemetry destinations.
- [Terminal UI](${ORCEL_ORIGIN}/docs/guides/dev-tui.md): Work with a local or deployed agent from the interactive terminal UI.

## Tutorial

- [Tutorial](${ORCEL_ORIGIN}/docs/tutorial/first-agent.md): Build an agent with tools, durable state, and an interface.

## Patterns

- [Multi-Tenant Memory](${ORCEL_ORIGIN}/docs/patterns/multi-tenant-memory.md): Scope any memory provider to an authenticated tenant and caller.
- [Dynamic Scheduling](${ORCEL_ORIGIN}/docs/patterns/dynamic-scheduling.md): Build application-managed schedules from an orcel schedule and authored tools.
- [Multi-Tenant Outbound Auth](${ORCEL_ORIGIN}/docs/patterns/multi-tenant-auth.md): Select tenant-scoped credentials for tools and connections.
- [Multi-Tenant Approvals](${ORCEL_ORIGIN}/docs/patterns/multi-tenant-approvals.md): Apply tenant policy to authored and connection tools.

## API Reference and Discovery

- [Agent Files](${ORCEL_ORIGIN}/docs/reference/agent-files.md): Look up filesystem slots, path-derived names, and discovery rules.
- [TypeScript API Reference](${ORCEL_ORIGIN}/docs/reference/typescript-api.md): Find public \`define*\` helpers, runtime context, and import paths.
- [CLI Reference](${ORCEL_ORIGIN}/docs/reference/cli.md): Find every orcel command and option.
- [Responsible Use](${ORCEL_ORIGIN}/docs/responsible-use.md): Review deployer responsibilities and safeguards.
- [Documentation Map](${ORCEL_ORIGIN}/sitemap.md): Browse every documentation, integration, and template page with type and summary metadata.
- [Agent Instructions](${ORCEL_ORIGIN}/agents.md): Read operational guidance for coding agents working with orcel.
- [Full Documentation Corpus](${ORCEL_ORIGIN}/llms-full.txt): Load all docs and integration content for offline indexing or a large context window.

## Optional

- [Changelog](${ORCEL_ORIGIN}/changelog.md): Read orcel release notes, including breaking changes and fixes. Follow the next-page links for older releases.
- [Integrations](${ORCEL_ORIGIN}/integrations): Browse official channels, connections, extensions, and observability integrations.
- [Templates](${ORCEL_ORIGIN}/templates): Browse complete example projects and their source.
- [Official orcel Skill](https://github.com/TheHalfMoon/orcel/blob/main/skills/orcel/SKILL.md): Install or inspect the coding-agent skill; its guidance defers to version-matched bundled docs.
- [Source Repository](https://github.com/TheHalfMoon/orcel): Read source, releases, issues, and contribution guidance.
`;
