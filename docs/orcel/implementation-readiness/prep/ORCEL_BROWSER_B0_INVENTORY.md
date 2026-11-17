# Orcel Browser B0: donor acquisition, inventory and baseline

Date: 2026-11-17.
Status: **source acquired and inventoried. No donor code is copied into Orcel, and no browser was built or run.**
Authorization: OWNER-ASSERTED AUTHORIZATION — 2026-11-17 (`docs/orcel/grants/2026-11-17-founder-attestation.md`,
section "Browser donors (2026-11-17)"). It is not independently verified.

The full reports live outside this repository, in `D:\Orcel-Browser\reports\`:

- `B0_SOURCE_INVENTORY.md`
- `donor_manifest.json`
- `B0_BASELINE.md`
- `B0_ORCEL_OVERLAP.md`
- `REDISTRIBUTION_GRANT_GAPS.md`

The donor clones are in `D:\Orcel-Browser\donors\`. The ledger records are in `TRANSPLANT_LEDGER.json`: the updated
records `browseros`, `stagehand`, `agent_browser`, `obscura` and `browser_use`, the new group K, and `browser_b0`.

## Donors

All donors were shallow-cloned (depth 1) at the exact SHA, and each SHA was verified. Together they take about 575 MB
including `.git`. Chromium was neither fetched nor built.

| Donor | SHA | Class |
|---|---|---|
| browseros-ai/BrowserOS | bd725831273884c4b1aee8425975afa122f720f2 | CORE |
| browseros-ai/BrowserOS-agent | e886782210d1a60da45bf9ec20afc70ddc2eae66 | CORE (legacy; source of controller-ext) |
| browseros-ai/browserclaw-claude-desktop | 474c7ffe5b425ce1b0e1171707b9afc35e0c5a29 | AGENT CONNECTOR |
| browseros-ai/browserclaw-codex-app | c755fd745c091a2bce764cafb6f7728dd3cc8ec5 | AGENT CONNECTOR |
| browseros-ai/skills | c882b80dd4fcbad127c8386cbee7ac191ffa62b1 | AGENT CONNECTOR |
| browseros-ai/homebrew-tap | 51866725f8a79fa904aab13307ba12a8e96f53ef | BUILD+DISTRIBUTION |
| browseros-ai/cla-signatures | 0d56cacd0f9f09cce474e76c1e42a56ffea15225 | BUILD+DISTRIBUTION |
| browseros-ai/docs | 3e4eb91ed75fc0abaf16b5e6d9e1f3e5a832d009 | DOCS (Mintlify starter) |
| browseros-ai/mintlify-docs | 15709293ec0e8797c5d9d6b3198c949a1f473f7d | DOCS (duplicate of docs) |
| browseros-ai/moltyflow | 7d4ebc5e494b2a6760b0a0216d42cfc1af144295 | UNRELATED |
| browseros-ai/tmux-factory | 29026ff73f9e1b5a3e733dbd4d2e53a49f1b4d02 | UNRELATED |
| browser-use/browser-harness | bc274a297d893e94ee05b4901898809651876a2d | SECONDARY: AGENT CONNECTOR |
| browser-use/browser-use | 4b5b1b0aa0ab45a1d6a2a31984d37d3e748c0134 | SECONDARY: CORE (agent loop) |
| vercel-labs/agent-browser | b06e2533ba9b3823b8a96c859d455cb55f4d7893 | SECONDARY: CORE (action engine) |
| browserbase/stagehand | 0f9a64c141d929b0595b4d909d89fb02e37c1ca4 | SECONDARY: CORE (page understanding) |
| h4ckf0r0day/obscura | 0d9a2f764ffdb097269da048002c593865e83a9e | SECONDARY: CORE (headless worker) |

**Not cloned:**

- browseros-ai/codex, openclaw and llama.cpp: UNRELATED forks of openai/codex, openclaw/openclaw and
  ggml-org/llama.cpp, with separately owned contributors.
- browserclaw-skills: an empty repository.
- internal-docs: a private submodule, not accessible.

**Stagehand.** Every path the ledger maps for Orcel is byte-identical between 82827a2 (the W2 clone) and 0f9a64c. No
Stagehand file is in Orcel yet, so the re-pin to 0f9a64c needs no code change.

## BrowserOS map (bd725831)

- **`packages/browseros`:**
  - Chromium 155.0.8059.26 (`BASE_COMMIT` 16c3e554).
  - 425 `chromium_patches` files: ui 104, a new `chrome/browser/browseros` subtree 84, extensions 28, importer 37,
    devtools 20, password_manager 14.
  - 5 BSD-3 ungoogled-chromium Windows quilt patches.
  - The `bos_build` Python build CLI, and the `docker/neo` hosted image.
  - About 100 GB of disk is needed for a Chromium build, which is not feasible on this machine.
- **`packages/browseros-agent`** (a plain tree, not a submodule):
  - Apps:
    - `apps/claw-server`: Rust MCP + HTTP over CDP
    - `apps/claw-app`: the dashboard, cockpit and replay
    - `apps/claw-onboard`: onboarding
    - `apps/server` and `apps/app`: the human-browser agent backend and UI
  - Crates: `browseros-cdp`, `-core`, `-mcp`, `-decide`, `claw-api`, `harness-integrations`, `hosted-api`, and
    `neo-sdk/*` (neo-server, neo-playwright, neo-http, neo-takeover, neo-trace, neo-screencast, neo-captcha).
  - `controller-ext` exists only in BrowserOS-agent.
- **claw-server MCP tools.** The 22 catalog tools are:
  - Browser and profile: `browser_profiles`, `browser_target`, `windows`
  - Tabs and history: `tabs`, `tab_groups`, `history`
  - Saved data: `credentials`, `payment_cards`
  - Navigation and waiting: `navigate`, `wait`
  - Reading pages: `snapshot`, `diff`, `read`, `read_output`, `grep`
  - Acting: `act`, `download`, `upload`
  - Capture: `screenshot`, `pdf`
  - Scripting: `evaluate_in_page`, `run`

  The server adds `pursue`, `run_skill`, `save_skill`, `mark_skill_run`, `name_session`, `request_human_help`,
  `await_human_help` and `solve_captcha`.
- **claw-server auth:**
  - Streamable HTTP `/mcp` bound to `127.0.0.1` only (default port 9200), plus stdio.
  - **No token.** Requests that carry `Origin` or `Sec-Fetch-Site` are refused, and JSON content is required.
  - Some HTTP endpoints accept only the signed extension origin.
  - Hosted neo uses a Unix socket and a bearer token, and that code is Unix-only.

## Baseline (Windows, Rust 1.97.1)

- **Full workspace:** does not compile on Windows. `neo-http` and the `neo-playwright` tests use `std::os::unix`.
- **13 Windows-buildable packages** (claw-server and the other crates):
  - 2,633 passed, 12 failed, 18 ignored. The ignored tests are `*_live` and need a running browser.
  - The failures come from Windows path, permission and error-classification differences:
    - claw-server `dev_mode_provisioning`: 4
    - neo-trace `blob_expiry` and `storage_boundaries`: 7
    - neo-captcha: 1
- **Settings:** telemetry was off. No hosted service was called. The target directory (5.7 GB) was deleted afterwards.
- **TypeScript suites (claw-app and the others):** NOT RUN. The workspace-wide bun install has about 2,491 packages,
  which is over the 700 MB limit.

## Overlap with Orcel main (48ae7a12)

Orcel has these browser components today:

- `crates/orcel-browser-host`: 452 tests
- `apps/orcel-browser-worker`: playwright-core, pipe-only, throwaway profile
- 12 local-only `browser_*` tools in `apps/orcel-mcp`
- Single-use approvals from orceld

| Area | Verdict |
|---|---|
| Policy and authority | **Duplicate.** Keep orceld. BrowserOS `browseros-decide` and `run_policy` are reference only. |
| MCP surface | **Duplicate.** Keep `apps/orcel-mcp`. Do not run claw-server as a second endpoint. |
| Snapshot, actions, verify, downloads | **Duplicate.** Keep Orcel's contracts and adopt donor internals. |
| Network mediation (SG-000075), WebMCP | **Orcel only.** |
| Persistent profiles, tabs and windows, screenshots and PDF, takeover and human help, screencast and replay | **Gap.** Take from BrowserOS. |
| Credentials, payment cards, page scripting | **Gap, high risk.** Out of scope until the credential-broker and Full Access designs land. |
| `solve_captcha` and `neo-captcha` | **Excluded.** It conflicts with the no-CAPTCHA-bypass rule. |
| Human browser (Chromium fork, import, password manager) | **Gap (P1).** Needs a build volume. |

**Decisions needed before B1 code:**

- **CDP attachment.** Orcel refuses a remote-debugging port, and BrowserOS uses a loopback CDP port.
- **Persistent profiles.** These need an SG-000108 amendment.
- **Sidecar token.** If any claw-server code runs as a sidecar, it needs an orceld-held token.

## Recommended B1 first transplant

**Move BrowserOS `neo-takeover` and its human-help flow, plus the claw-server tab-ownership effects, into a Rust
module behind orceld.** Then build the master-decision `browser_pause`, `browser_takeover` and `browser_resume`
tools, with the 3-second quiet timer, on top of Orcel's existing worker and host.

Why this transplant first:

- It builds and passes on Windows today (156 tests, no failures).
- Orcel has no equivalent.
- It is the P0 Shadow Mode and takeover requirement.
- It needs neither a Chromium build nor CDP-port changes, so it can be checked against the existing Edge 157 /
  playwright-core engine.

Second transplant: BrowserOS `tabs`, `screenshot` and `snapshot`/`diff` internals behind the existing
`browser_observe` contract.
