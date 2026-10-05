## Build it out, then verify

Work from the project directory. Once orcel is installed, the full docs are bundled
with the installed package and match its version exactly. In most installs, they
are at `node_modules/@orcel/orcel/docs/`. In workspaces or local package installs, resolve
the installed `orcel` package location first and read its `docs/` directory. If
package docs are unavailable, use https://github.com/TheHalfMoon/orcel/docs as a fallback. Read
`README.md` in the package docs first, then the guide for what you're adding,
such as `connections`, `channels/slack`, or `guides/auth-and-route-protection`
for the Vercel Connect flow.

Before implementing an integration yourself, use `orcel registry search <query>` or
`orcel registry list` to discover available integrations. Inspect one with
`orcel registry view <item>`, then install it with `orcel add <item>`.

- Put the purpose in `agent/instructions.md` (the always-on system prompt),
  replacing the scaffold's placeholder with what the user said the agent should
  do.
- Add a first typed tool under `agent/tools/` with `defineTool` from `@orcel/orcel/tools`
  and a Zod `inputSchema`.

`{{devCommand}}` starts orcel's HMR development server and opens the agent's
terminal REPL. It does not start or control this coding-agent session, so don't
use the bare command as a background verification process. Start orcel without the
terminal UI in a controllable background process instead:

    {{devCommand}} --no-ui

Wait for the server URL, then exercise the HTTP API: create a session with
`POST /orcel/v1/session`, attach to `GET /orcel/v1/session/:id/stream`, and send a
follow-up to `POST /orcel/v1/session/:id`. Stop the dev process after verification.

When the user is ready to use their agent's REPL, give them the interactive
command to run from the project directory:

    {{devCommand}}

Verify the project's typecheck passes, adapt the model and provider to the user's
data and use case, and don't commit unless the user asks.
