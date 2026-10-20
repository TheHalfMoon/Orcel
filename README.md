# Orcel

<p align="center">
  <img src="assets/brand/orcel-readme-lockup.svg" alt="Orcel Signal: lowercase white orcel wordmark with orange terminal on the letter l" width="630">
</p>

<p align="center"><strong>Your computer, your terms.</strong></p>

<p align="center">
  A local-first, approval-driven MCP gateway that helps AI assistants work within the boundaries <em>you</em> control.
</p>

<p align="center">
  <a href="https://github.com/TheHalfMoon/Orcel/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/TheHalfMoon/Orcel/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/TheHalfMoon/Orcel/actions/workflows/pages.yml"><img alt="Website deployment" src="https://github.com/TheHalfMoon/Orcel/actions/workflows/pages.yml/badge.svg?branch=main"></a>
  <a href="LICENSE"><img alt="Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-FF813E"></a>
  <a href="#requirements"><img alt="Windows x64" src="https://img.shields.io/badge/platform-Windows%20x64-555"></a>
</p>

<p align="center">
  <a href="https://thehalfmoon.github.io/Orcel/">Website</a> ·
  <a href="#install">Get started</a> ·
  <a href="https://github.com/TheHalfMoon/Orcel/releases">Releases</a> ·
  <a href="CONTRIBUTING.md">Contribute</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="https://thehalfmoon.github.io/Orcel/brand.html">Brand kit</a>
</p>

---

## Why Orcel?

Orcel is an **open-source computer-access authority layer** for MCP-compatible AI agents. It connects supported clients, including ChatGPT through the OpenAI Secure MCP Tunnel, to **explicitly trusted local workspaces**. Read operations are bounded; sensitive changes require approval on your own Windows desktop. A client cannot grant itself new privileges.

| Designed for | What you get |
| --- | --- |
| **Your authority** | Workspace trust and narrowly scoped, one-time local approvals; Windows Hello for high-risk actions |
| **Your machine** | Local-first operation without an inbound port for the ChatGPT tunnel integration |
| **Your choice of clients** | Local MCP over stdio or token-protected loopback HTTP, plus the remote 26-tool core profile |
| **Your confidence** | Fail-closed policy, release checksums/provenance, security documentation, and public CI |

**Boundaries matter:** Orcel is **not** an unrestricted remote shell, general-purpose remote desktop, or blanket browser/UI automation service. The local tool surface has **31 tools**; remote clients see a smaller **26-tool core profile**. Desktop observation, clipboard, and web fetch are local-only, and UI actuation is not exposed over MCP. Read the [current limitations](#current-limitations) before installing.

**Website:** https://thehalfmoon.github.io/Orcel/

**Canonical releases:** https://github.com/TheHalfMoon/Orcel/releases

> **Platform & release status:** Orcel's current source targets **Windows 10/11 x64**, but source changes on `main` are not automatically published binaries. The published [v0.1.0 release](https://github.com/TheHalfMoon/Orcel/releases/tag/v0.1.0) is an **archival Cotra-era build, not a qualified Orcel installer**. Check release notes and asset names before following any installation example.

> **Identity migration:** Orcel is the current product and repository name. Existing clients, credentials, and trusted state are not automatically migrated from historical names; consult the [identity migration record](docs/identity/ORCEL_RENAME.md) before updating.

## Explore and contribute

- **Start here:** [Install](#install), [Configure](#configure), [Connect ChatGPT](#connect-chatgpt), or [use local MCP](#connect-local-mcp-clients-no-tunnel-required).
- **Learn the design:** [Architecture and delivery plan](docs/canonical/ARCHITECTURE_AND_DELIVERY_PLAN.md), [threat model](docs/security/THREAT_MODEL.md), and [current state](docs/canonical/CURRENT.md).
- **Help improve Orcel:** [Open issues and proposals](https://github.com/TheHalfMoon/Orcel/issues), [contribution guide](CONTRIBUTING.md), [support](SUPPORT.md), [code of conduct](CODE_OF_CONDUCT.md), and [project stewardship](docs/community/MAINTAINERSHIP.md).
- **Check what ships:** [Changelog](CHANGELOG.md), [release assets](https://github.com/TheHalfMoon/Orcel/releases), [source license](LICENSE), and [required third-party notices](docs/research/DEPENDENCY_LICENSE_REVIEW.md).
- **Use the brand correctly:** [Identity specifications](assets/brand/IDENTITY.md) and [brand media kit](https://thehalfmoon.github.io/Orcel/brand.html).

## What ChatGPT can do through Orcel

Exactly these 31 tools are exposed over local MCP:

| Area | Tools | Approval |
|---|---|---|
| Status | `system_status`, `workspace_get` | none (read-only) |
| Files in a trusted workspace | `fs_stat`, `fs_list`, `fs_read`, `fs_read_range`, `fs_search`, `fs_find` | none (read-only, bounded) |
| File writes | `fs_write_preview`, `fs_write`, `fs_edit`, `fs_mkdir`, `fs_move` | local approval for each write, bound to the exact content and current file hash |
| File removal | `fs_remove` | Windows Hello (STRONG), single files or empty directories only |
| Desktop observation | `desktop_window_list`, `desktop_window_tree` | none (read-only, bounded, local-only) |
| Clipboard | `clipboard_read`, `clipboard_write` | local approval for each use; secrets refused; local-only |
| Network | `web_fetch` | local approval per destination; public HTTPS only; local-only |
| Web search (optional) | `web_search` | off until you enable a provider (`ORCEL_SEARCH_PROVIDERS_JSON`: self-hosted SearXNG, or your own Brave, Tavily, Exa or Serper key stored with `orcel search set-key`); local approval per query; results are untrusted data; local-only; a self-hosted SearXNG must be served on a public HTTPS name (private, loopback and LAN addresses are refused); not available through the ChatGPT tunnel |
| Git (local) | `git_status`, `git_diff`, `git_log` | none (read-only) |
| Git (local changes) | `git_branch_create`, `git_stage`, `git_unstage`, `git_commit` | local approval, bound to the exact repository state |
| Git (network) | `git_fetch_preview`, `git_fetch`, `git_push_preview`, `git_push` | local approval; see limitations |
| Processes | `process_spawn` | local approval; see limitations |

Everything else is denied. Remote clients (ChatGPT through the tunnel or relay, and other providers) see only the 26-tool `core` profile: desktop observation, clipboard, and network fetch are local-only and cannot be reached remotely. Browser automation, screenshots, coordinate input, and UI actuation remain unreachable over MCP entirely.

### Current limitations

- `process_spawn` on Windows launches only locally registered, hash-pinned native executables with constrained argv; adding or changing a registry entry requires Windows Hello on the machine.
- `git_fetch` and `git_push` require destination policies that the current compatibility runtime does not configure yet, so they fail closed in an installed Orcel runtime.
- Release binaries are not code-signed (there is no paid certificate under the project's zero-cost rule). Windows SmartScreen may warn; verify the archive with `SHA256SUMS.txt` and the GitHub build-provenance attestation.
- Orcel runs only while you are signed in, because approvals appear on your desktop.

## How approvals work

- **SOFT approval** — a Orcel dialog appears on your desktop describing the exact action (for example, the file and content hash). Approve or deny it yourself. Each approval is used once, expires quickly, and is bound to that exact action, workspace, and policy.
- **STRONG approval** — Windows Hello (PIN, fingerprint, or face) for trust changes and emergency revoke.
- ChatGPT cannot approve its own actions: approvals come only from the local broker, and Orcel's own windows are excluded from automation.
- `orcel approvals` lists recent decisions; `orcel emergency-revoke` invalidates every pending approval.

## Requirements

- Windows 10 version 1809 (build 17763) or later, or Windows 11, x64.
- Node.js 20 or later.
- The official OpenAI tunnel client executable, and a Secure MCP Tunnel id (`tunnel_…`) and runtime key from OpenAI for your ChatGPT workspace. Follow OpenAI's documentation to create them; Orcel does not create, download, or redistribute them.
- No administrator rights. Do not use "Run as administrator".

## Install

**Release availability:** The historical `v0.1.0` archive contains original Cotra-era assets, not the `orcel.exe` installer described below. Do not rename that archive or assume it supports current Orcel commands. Follow these instructions **only after a qualified Orcel-branded Windows release with matching filenames has been published**.

1. For a published release that actually lists `orcel-<version>-windows-x64.zip` and `SHA256SUMS.txt`, download those exact matching assets from [GitHub Releases](https://github.com/TheHalfMoon/Orcel/releases) and verify the hash:
   ```powershell
   $zip = "orcel-<version>-windows-x64.zip"
   $expected = ((Get-Content .\SHA256SUMS.txt) | Where-Object { $_ -like "*  $zip" } | ForEach-Object { $_.Split(" ")[0] })
   $actual = (Get-FileHash ".\$zip" -Algorithm SHA256).Hash.ToLower()
   if (-not $expected -or $actual -ne $expected) { throw "checksum mismatch: do not extract $zip" } else { "checksum OK" }
   ```
   On Linux or WSL, `sha256sum -c --ignore-missing SHA256SUMS.txt` does the same.
   Optionally verify provenance: `gh attestation verify .\orcel-<version>-windows-x64.zip --repo TheHalfMoon/Orcel`.
2. Extract the archive and run, from the extracted folder:
   `.\orcel.exe install`
   For a qualified Orcel build, the installer checks files against `manifest.json` before copying them. The current source uses `%LOCALAPPDATA%\Orcel` and adds `%LOCALAPPDATA%\Orcel\bin` to your user PATH (`--no-path` to skip). Follow the exact published release notes and open a new terminal afterwards.

## Configure

1. Add a workspace (a folder ChatGPT may use):
   `orcel workspace add myproject C:\path\to\project`
   Folders that contain Orcel's own protected data are refused.
2. Optionally grant workspace trust with Windows Hello: `orcel workspace trust myproject`.
3. Configure the tunnel:
   `orcel tunnel setup --client C:\path\to\tunnel-client.exe --tunnel-id tunnel_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
   You are prompted for the runtime key without echo (or pass `--key-file <path>`). The key is stored only in the protected local folder, passed to the tunnel client by file reference, and never printed or logged.

## Connect ChatGPT

1. `orcel start` — starts the official tunnel client under Orcel's supervisor. It reports `running` only when the tunnel client is alive and its local health endpoint answers.
2. In ChatGPT, connect to your Secure MCP Tunnel as described in OpenAI's documentation. ChatGPT then sees the 26-tool core profile above.

## Connect local MCP clients (no tunnel required)

Local clients that can launch a command use `orcel mcp stdio`. It starts the same authoritative MCP server over standard input and output, with the same 31 tools and the same local approvals. No tunnel setup is needed. Standard output stays the MCP channel, so run it only through the client configuration below, not by hand.

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "orcel": {
      "command": "orcel",
      "args": ["mcp", "stdio"]
    }
  }
}
```

Codex and other command-based clients use the same command and arguments:

```json
{
  "command": "orcel",
  "args": ["mcp", "stdio"]
}
```

Mistral Vibe Code accepts a stdio entry in its MCP server list with command `orcel` and arguments `["mcp", "stdio"]`. Generic MCP clients and the MCP Inspector connect with transport `stdio`, command `orcel`, and arguments `["mcp", "stdio"]`.

`orcel` here is the retained compatibility command at `%LOCALAPPDATA%\Orcel\bin\orcel.exe` on your user PATH after install. It resolves the active verified release on every launch, refuses tampered or inactive payloads, and fails closed when no workspace is configured. Tested per-client files live in [`examples/mcp-clients`](examples/mcp-clients) (Claude Desktop JSON and Desktop Extension manifest, Codex TOML, Vibe Code TOML, generic shapes, and the Inspector qualification script).

## Connect over loopback HTTP (no tunnel required)

`orcel mcp serve` exposes the same 31 tools over Streamable HTTP on `127.0.0.1` only. It never binds a LAN address. Every request needs a per-user bearer credential:

```powershell
$env:ORCEL_LOOPBACK_TOKEN = "<at-least-32-characters-you-choose>"
orcel mcp serve
```

The listener prints its URL, for example `http://127.0.0.1:54321/mcp`, on standard error. Pass `--port <1-65535>` to choose the port instead of an ephemeral one. The credential is required on every request as `Authorization: Bearer <token>`; missing or wrong credentials fail closed, as do forged `Host` or browser `Origin` values. Browser pages on other origins cannot drive the listener. Keep the token on your machine and never commit it.

Mistral Vibe Code HTTP mode and generic Streamable HTTP clients connect to the printed URL with the bearer header. Clients that can launch a command should prefer `orcel mcp stdio` above.

## Everyday commands

| Command | Purpose |
|---|---|
| `orcel status` | Installed version, configuration, and whether the runtime is running |
| `orcel doctor` | Full diagnostics; exits non-zero if any check fails (`--json` for details) |
| `orcel stop` | Stops the tunnel client and everything it started, and confirms they exited |
| `orcel workspace list` | Workspaces and their trust state |
| `orcel tunnel show` | Tunnel configuration (never the key) |
| `orcel help` | All commands |

## Diagnose problems

Run `orcel doctor`. Each check reports `PASS`, `WARN`, `FAIL`, or `????` (could not be checked) with one line of evidence — Orcel never reports health it did not observe. Logs are currently stored in the compatibility path `%LOCALAPPDATA%\Orcel\logs` (`tunnel.log`, `supervisor.log`, `lifecycle.log`); tunnel output is redacted before it is written.

## Update

Orcel never checks for or downloads updates by itself.

1. Download and verify the new release as in Install, then extract it.
2. `orcel update --source C:\path\to\extracted-release --check` shows the version change.
3. `orcel update --source C:\path\to\extracted-release` stops the runtime, switches versions, has the new version verify itself, and restarts it. If the new version fails its own check, the previous version is restored automatically and `orcel doctor` reports why.
4. `orcel rollback` returns to the previous version. Older versions require `--allow-downgrade`.

## Uninstall

- `orcel uninstall` stops Orcel and removes its programs and the PATH entry. Your configuration, tunnel key, logs, and audit/approval/trust history are **kept** and listed.
- `orcel uninstall --purge-data --yes` also deletes that data.
- Your workspaces are never touched.

## Security model and governance

- [Architecture and delivery plan](docs/canonical/ARCHITECTURE_AND_DELIVERY_PLAN.md)
- [Current canonical state](docs/canonical/CURRENT.md)
- [Threat model](docs/security/THREAT_MODEL.md) and [v0.2 regression matrix](docs/security/THREAT_MODEL_REGRESSION_V02.md)
- [Installer and lifecycle design](docs/canonical/P12_INSTALLER_LIFECYCLE_DESIGN.md)
- [Dependency and license review](docs/research/DEPENDENCY_LICENSE_REVIEW.md)
- [Diffcipline](docs/governance/DIFFCIPLINE.md)
- [Orcel identity record](docs/identity/ORCEL_RENAME.md)

## Building from source

`npm ci --ignore-scripts && npm run build`, then `cargo build --release --locked -p orceld -p orcel-lifecycle --bins`, then `node scripts/package-release.mjs --out <dir>` to assemble a release directory and `node scripts/archive-release.mjs --release <dir> --out <dir>.zip` to archive it. CI builds with the deterministic flags in `.github/actions/build-package-qualify/action.yml` and checks that an independent rebuild is byte-identical.

The `orcel*` Cargo and release identifiers in this command are compatibility identifiers retained during the Orcel rename and are not the current product brand.

## License

Apache License 2.0. Third-party components and their licenses are listed in `THIRD_PARTY_NOTICES.txt` in each release.
