---
name: kaf-chat-template-kaf
description: Work safely on Kaf-specific internals in the Kaf chat template. Use when changing the Kaf agent, withEve routes, kafChannel auth, useKafAgent, ClientSession/SessionState, persisted event logs, stream/resume behavior, connection authorization, Vercel Connect MCP connections, local Kaf tools, or upstream Kaf API assumptions.
---

# Kaf Template Runtime

## Overview

Use this skill to preserve the Kaf protocol and durable-session invariants while changing the chat template.

## First Pass

- Read `AGENTS.md` first. It requires reading the relevant guide under `node_modules/kaf/dist/docs/public/` before writing code.
- Read `docs/how-the-chatbot-works.md` for architecture changes and `docs/setup-and-deploy.md` for setup, auth, storage, or deployment changes.
- Search with `rg "useKafAgent|ClientSession|SessionState|message.appended|authorization.required|kafSession|chat_event|streamIndex|continuationToken|defineMcpClientConnection|defineTool"`.
- Keep Kaf runtime code separate from product shell code: `agent/` defines agent behavior; `app/_components/agent-chat.tsx` bridges Kaf to the web UI; `lib/db/*` persists app state.

## Core Model

- Treat an app chat row and an Kaf session as different things. The app row owns URL, title, user ownership, `pendingUserMessage`, stored `kafSession`, and event rows. Kaf owns the remote durable session and stream cursor.
- Do not confuse `chat_event.eventIndex` with `SessionState.streamIndex`. The first orders local Postgres rows; the second resumes `/kaf/v1/session/:sessionId/stream`.
- Preserve same-origin Kaf routes mounted by `withEve(nextConfig)`: `POST /kaf/v1/session`, `POST /kaf/v1/session/:sessionId`, and `GET /kaf/v1/session/:sessionId/stream?startIndex=n`.
- Keep `betterAuthKafAuth`, `localDev()`, and `vercelOidc()` in the Kaf channel unless deliberately changing local, browser, or Vercel auth behavior.

## Persistence And Resume

- Persist `SessionState` immediately after Kaf returns `sessionId` and `continuationToken`; do not wait for the stream to finish.
- Persist each stream event as it arrives, then use the final snapshot as the canonical cleanup pass.
- Upsert events by local `eventIndex`; on final snapshot, delete rows beyond the final event length.
- Keep `pendingUserMessage` for interruption recovery. Mark it before sending, consume it once in the session page, hide it after a settled event, and clear it after snapshot or authorization skip.
- When preserving initial events, merge by prefix and compare JSON structurally. Do not rely on `JSON.stringify` key order.
- Reset per-chat refs on route changes: event index, known initial events, stream events, resumed events, local events, pending bubbles, resume-started flags, and finalize timers.

## Streaming

- `useKafAgent` reduces Kaf events into renderable messages; the template wraps it with a custom `ClientSession` to persist and resume sessions.
- Treat `message.appended.data.messageDelta` as the new text. Treat `messageSoFar`, reduced message text, and rendered parts as cumulative.
- Read the stream as NDJSON. Buffering until newline is normal parsing, not app-level response buffering.
- Consider a turn settled on `session.completed`, `session.failed`, or `session.waiting`. Treat `authorization.required` as a blocked state for normal text input.
- Treat `turn.waiting` as progress, not a settled turn: the turn is parked, for example while its tasks work or a running call asks a question, and resumes with the next `step.started` for the same `turnId`. Keep following the stream until one of the settling events above.
- On disconnect, reconnect from the next unread remote stream index. On refresh mid-turn, resume from saved `activeChat.session` and layer resumed events until the final snapshot catches up.

## Connections And Tools

- Define local tools in `agent/tools/<snake_case>.ts` with `defineTool(...)`. Tool filenames become runtime tool names, so keep them ASCII snake_case.
- Define Vercel Connect-backed MCP connections in `agent/connections/<name>.ts` with `defineMcpClientConnection(...)` and `connect(process.env.ENV_NAME ?? "local-name")`.
- Treat composer connection toggles as per-turn intent, not connector provisioning or OAuth state.
- Do not parse assistant text for auth requirements. Use `authorization.required` and `authorization.completed` events.
- Implement Skip as a structured outcome: stop the stream, synthesize declined authorization completion plus `session.waiting`, apply those local events to the session, persist them, and clear pending input.

## Upstream Signals

- Prefer upstreaming generic Kaf lifecycle needs: `onSessionStarted(session)`, hook-level resume APIs, durable event persistence adapters, authorization continuation helpers, structured connection policy, and stream debug helpers.
- Keep template-specific concerns in the template: Better Auth UX, Neon/Drizzle schema, Upstash limits, sidebar pagination, Notion UI toggles, and setup docs.
- Do not split server events just to make coarse provider deltas look token-level. Preserve wire semantics and smooth only at the UI layer when needed.

## Verification

- Run `pnpm typecheck` for protocol/type changes and `pnpm build` before opening a PR that touches runtime, routes, or docs examples.
- Manually verify first message, follow-up send, refresh during a response, authorization Connect/Skip, disabled input while auth is pending, and Notion enabled/disabled turns when those flows are touched.
