# SG-000004 source note

The official openai/tunnel-client is supervised as an external executable and is not vendored or reimplemented.

Security-relevant upstream behavior verified on 2026-09-24:
- stdio MCP commands are created with Go exec.Command without an explicit cmd.Env;
- therefore the stdio MCP child inherits tunnel-client's process environment;
- tunnel-client supports control_plane.api_key as file:/path/to/secret;
- Orcel uses file-reference delivery so the runtime key value is absent from the inherited environment.

Canonical upstream pin in docs/research/SOURCE_LEDGER.md remains the provenance reference until a dedicated pin refresh is approved.

## The MCP command's arguments and environment (checked 2026-11-24)

Read in the source (not seen in a real run) at two versions: the pinned commit `cce7a8226654c432ce53c7e05e17a9825a34b6e3` (`pkg/version/VERSION` says 0.0.14) and the tag v0.0.21 (`714f2d67844b660af25754f1d19b0360b346b13b`).

- **Arguments.** `--mcp.command` is `channel=main,command=<command line>`. `parseCommandArgv` (`pkg/runtimeconfig/config.go`), the same at both versions, splits the command line at spaces, with double quotes, single quotes and a backslash that escapes the next character (inside double quotes too), and runs no shell. The child is `exec.Command(args[0], args[1:]...)` (`pkg/mcpclient/stdio_command.go`), so Go quotes the arguments for Windows. Orcel passes the host's path in double quotes and then two plain words, `--launch-pin` and 64 hex digits; a test splits the command the same way.
- **Environment.** Neither version sets the child's environment, so it inherits the client's. Upstream promises nothing about that for later versions, and Orcel's launch pin does not depend on it.
- **A child that exits.** At v0.0.21 the default `--mcp.stdio-failure-policy` is `restart`: a child that exits is started again, after 0.1 s to 5 s, and the client runs on. So a host that refuses looks like a running client; Orcel records the refusal. The client's log, and its loopback pages, show the command line, the pin included; the pin is no secret.
