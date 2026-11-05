# Orcel on macOS: unsigned development tarball

**This is a development build, not a release.** It is unsigned and not notarized. Signing, notarization and an app bundle are XP-16, which waits on FD-05 (a paid Apple Developer ID). It is not a published product: the CI artifact of this public repository can be downloaded, but it is never released or offered as one.

No paid Apple membership is needed to build or run it for local engineering.

## What's in it

| File | Purpose |
|---|---|
| `bin/orceld` | The kernel |
| `bin/orcel-contain`, `bin/orcel-contain.sha256` | The contained-tier helper and its pin, beside `orceld`, where orceld looks |
| `bin/orcel-mcp`, `app/orcel-mcp/` | The MCP server for a local client, and its launcher |
| `doc/` | Licence, third-party notices and this file |

Not in it: a desktop app (waits on FD-03), the `orcel` lifecycle CLI's install flow (it installs on Windows), and the native host. The live browser is refused on macOS until SG-000115 is activated. Node.js 24 is needed, from `PATH`, for the MCP server.

## Run it

```bash
shasum -a 256 -c SHA256SUMS-macos.txt
```

```bash
mkdir -p ~/orcel-dev && tar -xzf orcel-*-macos-*-unsigned-dev.tar.gz --strip-components=1 -C ~/orcel-dev
```

macOS quarantines downloaded files, and Gatekeeper refuses unsigned ones. Clear the attribute on that folder only, and only for an artifact from this repository's own CI. The checksum comes from the same download, so it shows integrity, not origin:

```bash
xattr -dr com.apple.quarantine ~/orcel-dev
```

orceld reads one JSON request per line on stdin. To check it runs:

```bash
mkdir -p ~/orcel-dev-ws && ORCEL_WORKSPACES_JSON="[{\"id\":\"dev\",\"root\":\"$HOME/orcel-dev-ws\"}]" python3 scripts/linux-orceld-probe.py exec ~/orcel-dev/bin/orceld dev
```

The probe is in the repository's `scripts/`; it checks `system.status`.

## Connect a local MCP client

Point the client at the launcher by its full path, and name the folder Orcel may work in. For example, in Claude Code's `.mcp.json`:

```json
{ "mcpServers": { "orcel": { "type": "stdio", "command": "/Users/you/orcel-dev/bin/orcel-mcp", "env": { "ORCEL_WORKSPACE_ROOT": "/Users/you/orcel-dev-ws" } } } }
```

The client sees the same tool list as on Windows, and `orceld` refuses what it can't do on this OS. `orceld` stays the sole authority, and asks you before it writes. Only a short list of variables reaches the server (see the launcher), so a client's other environment doesn't. CI checks this through the launcher with a test client, not with Claude or Codex, and no approval is given there: a report stops at the prompt.

## Update and uninstall

This tarball has no install flow. To update, replace the folder with a newer tarball: the state and the workspace stay as they are. To uninstall, remove the folder and the state in `~/Library/Application Support/Orcel`. The app API's directory, `orcel` under `getconf DARWIN_USER_TEMP_DIR`, can go too. CI checks that a copy of the folder elsewhere writes to the same task journal. It doesn't check a replacement at the same path, or that nothing else is written, and a newer version reading older state isn't tested: CI uses the same version both times.

## Limits

- **Permission grants don't survive a rebuild.** macOS ties Accessibility and Screen Recording to a binary's signature, and an ad-hoc signature changes with each build, so a grant is lost on every rebuild.
- **Unqualified on macOS:** delivered capture and input (XP-07, XP-12) need interactive consent on a real Mac. Approvals were qualified on real hardware (XP-09), but the macOS product as a whole was not.
- CI checks that this tarball unpacks, holds the expected files, carries a matching helper pin, that `orceld` answers `system.status`, and that a test client through `bin/orcel-mcp` lists tools, reads, is refused outside the workspace, stops at the approval, is refused an existing destination and a changed source, and survives `orceld` being killed. No more than that.
