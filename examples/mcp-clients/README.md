# Local MCP client examples

Copy-paste configuration for independent MCP clients. Every example uses
only the supported installed entrypoints:

- stdio: command `orcel` with arguments `["mcp", "stdio"]`
- loopback HTTP: `http://127.0.0.1:<port>/mcp` from a running
  `orcel mcp serve` listener with a bearer credential

No example requires the OpenAI tunnel. No example contains a secret.
Replace `PORT` with the printed listener port and export a token of at
least 32 characters before serving:

```powershell
$env:ORCEL_LOOPBACK_TOKEN = "<choose-at-least-32-characters>"
orcel mcp serve
```

## Files

- `claude-desktop.json`: paste under `mcpServers` in
  `claude_desktop_config.json`.
- `claude-desktop-mcpb-manifest.json`: manifest for packing a `.mcpb`
  Desktop Extension with the `mcpb` CLI (rename to `manifest.json` at the
  bundle root). Directory listing and review by Anthropic are separate
  external steps and are not claimed here.
- `claude-code.mcp.json`: project-scoped `.mcp.json` for Claude Code (or
  `claude mcp add orcel -- orcel mcp stdio`). Claude Code reaches a remote
  Orcel relay as a custom connector through OAuth with a
  `http://localhost:<port>/callback` redirect; see `docs/p17/CLAUDE.md`.
- `codex-config.toml`: `[mcp_servers.orcel]` for `~/.codex/config.toml`.
  Uncomment the HTTP block to use loopback instead of stdio.
- `vibe-code-config.toml`: `[[mcp_servers]]` for Vibe Code `config.toml`,
  stdio plus a commented loopback block using the documented
  `api_key_env` fields.
- `generic-stdio.json` / `generic-http.json`: provider-neutral shapes for
  any MCP client and for the MCP Inspector `--config` file.
- `inspector.sh`: exact Inspector CLI invocations used to qualify these
  examples (stdio, loopback HTTP, and config-file modes).

## Inspector qualification

```sh
sh examples/mcp-clients/inspector.sh
```

The script drives `tools/list` through three independent client paths and
checks the default local profile (`desktop_structured`) on each. It needs Node.js, the repository
checkout (for `node apps/orcel-mcp/dist`), and a `orceld` binary for
`ORCEL_DAEMON`. stdio and HTTP paths that skip the inspector also work;
see the contract tests for the static guarantees.

## Release qualification

`installed_release_serves_every_client_example`
(`crates/orcel-lifecycle/tests/release_qualification.rs`) reads every
configuration here as a client would and runs it against the installed Windows
release: each file's command must be `orcel`, its arguments are passed to the
installed `orcel.exe` by its full path, and each stdio entrypoint and the loopback
HTTP example must reach the same tools. **This shows the configuration and the
protocol, not the client:** no Claude, Codex or Vibe Code runs in it, their versions
aren't qualified by it, and finding `orcel` on `PATH` isn't tested.
