# ORCEL-P20 Donor Ledger

Status: ACTIVE PINNED DONOR INPUT
Program: ORCEL-P20
Owner grain: SG-000092
Date: 2026-10-07

This ledger freezes the initial donor set and reuse boundary for P20. It authorizes no code import by itself. Each implementation grain must enumerate the exact files actually copied or substantially adapted before merge.

## 1. Ledger rules

For every imported file or substantial adapted implementation, the owning grain records:

- exact donor repository and commit;
- exact source path;
- file/package license or durable direct-permission evidence;
- relevant third-party dependency obligations;
- Orcel destination;
- reuse class;
- whether the source was modified;
- tests proving the adapted behavior;
- authority delta;
- SBOM and notice impact.

Allowed reuse classes are `COPY`, `COPY_ADAPT`, `PORT`, `REFERENCE`, and `REJECT`.

A donor implementation never becomes caller authority merely because it is bundled. Orcel remains the only caller-facing tool and authorization surface.

## 2. Open Computer Use

Repository: `opensymph/open-computer-use`
Pinned commit: `5b433b98019c18201a15d11e8c3cb0010879a3d8`
Root license observed at pin: MIT
Primary owner grains: SG-000094, SG-000095

Initial selected boundaries:

| Source path | Class | Intended Orcel use |
| --- | --- | --- |
| `apps/OpenComputerUseWindows/native_actions.go` | COPY_ADAPT | Windows accessibility and input mechanics |
| `apps/OpenComputerUseWindows/native_capture.go` | COPY_ADAPT | window/desktop capture mechanics |
| `apps/OpenComputerUseWindows/native_uia.go` | COPY_ADAPT | UI Automation tree and semantic actions |
| `apps/OpenComputerUseWindows/native_win32.go` | COPY_ADAPT | window/process Win32 integration |
| `apps/OpenComputerUseWindows/desktop_windows.go` | COPY_ADAPT | Windows desktop commands and SendInput integration |
| `apps/OpenComputerUseWindows/input_helpers.go` | COPY_ADAPT | key/input normalization |
| `apps/OpenComputerUseWindows/main.go` | COPY_ADAPT | dispatcher and runtime wiring behind Orcel private-host protocol |
| `docs/ARCHITECTURE.md` | REFERENCE | platform/runtime behavior and packaging evidence |

Rules:

- preserve useful screenshot freshness, window identity, DPI, and coordinate-bound checks;
- remove independent caller-facing MCP authority from the bundled Orcel host;
- password/security-surface policy is owned by Orcel profiles, not copied as an unreviewed donor decision;
- no runtime dependency on the upstream package registry is required.

## 3. Desktop Commander

Repository: `wonderwhy-er/DesktopCommanderMCP`
Pinned commit: `bc1e944e30302e0022d49f418d55563dd74a162c`
Root license observed at pin: MIT
Primary owner grains: SG-000096, SG-000097, SG-000105

Initial selected boundaries:

| Source path | Class | Intended Orcel use |
| --- | --- | --- |
| `src/terminal-manager.ts` | COPY_ADAPT | shell execution, sessions, stdin/stdout, prompt detection, output bounds |
| `src/handlers/terminal-handlers.ts` | COPY_ADAPT | terminal request/response mechanics |
| `src/handlers/process-handlers.ts` | COPY_ADAPT | process lifecycle mechanics |
| `src/tools/process.ts` | REFERENCE | process tool behavior and schemas |
| `src/handlers/filesystem-handlers.ts` | REFERENCE | parity and rich-file behavior where Orcel lacks coverage |
| `src/handlers/search-handlers.ts` | REFERENCE | filesystem/code search parity |
| `src/handlers/edit-search-handlers.ts` | REFERENCE | edit/search parity |
| `src/remote-device/remote-channel.ts` | PORT | reconnect, heartbeat, duplicate-delivery, failure patterns |
| `src/remote-device/device.ts` | PORT | executor recovery and persisted-device lifecycle patterns |

Rules:

- do not adopt Desktop Commander's hosted backend as Orcel authority;
- Orcel relay/device identity remains authoritative;
- terminal execution is governed by Orcel Safe/Full User/Admin profile state;
- do not expose a second MCP server from the bundled shell host.

## 4. Firecrawl

Repository: `firecrawl/firecrawl`
Pinned commit: `7120d16926544483513782b5393ae9850691d52a`
Public root license observed at pin: AGPL-3.0
Founder permission statement: direct permission has been asserted for Firecrawl-owned source.
Primary owner grains: SG-000101, SG-000102

Initial selected boundaries:

| Source path | Class | Intended Orcel use |
| --- | --- | --- |
| `apps/api/src/scraper/scrapeURL/index.ts` | COPY_ADAPT | scrape orchestration, abort, typed result/failure flow |
| `apps/api/src/scraper/scrapeURL/engines/index.ts` | COPY_ADAPT | engine feature/fallback selection |
| `apps/api/src/scraper/WebScraper/crawler.ts` | COPY_ADAPT | crawl discovery and traversal |
| `apps/api/src/lib/scrape-interact/scrape-replay.ts` | COPY_ADAPT | browser action/replay model |
| `apps/api/src/controllers/v2/types.ts` | REFERENCE | bounded scrape/crawl request schema and formats |
| `SELF_HOST.md` | REFERENCE | local deployment boundaries and dependency inventory |

Additional Firecrawl subtrees such as transformers, robots/sitemap helpers, safe-mode/threat checks, HTML-to-Markdown, PDF/document parsing, and selected Playwright/fetch engines may be imported only after the owning grain enumerates their exact file paths and dependencies.

Explicitly excluded from Orcel core:

- billing, credits, Stripe, hosted team/org accounting;
- hosted account/key management;
- hosted telemetry and SIEM product layers;
- GCS or other mandatory cloud persistence;
- mandatory managed proxy infrastructure;
- managed cloud concurrency/accounting;
- Firecrawl-branded hosted API control plane.

Permission gate:

Before any Firecrawl-owned source is copied into a distributable Orcel artifact, the owning grain must reference durable evidence that the direct permission covers the intended copy, modification, combination, redistribution, and commercial distribution. The permission does not supersede third-party dependency licenses.

Evidence on file: the founder authorization of 2026-10-13 (`docs/orcel/grants/2026-10-13-founder-source-authorization.md`) is that durable internal evidence. The founder confirmed the permissions needed to copy, modify, integrate and rebrand Firecrawl-owned source, and that the documents themselves stay confidential. The record reads "integrate into Orcel" (distributed under Apache-2.0), together with the founder's instruction that the authorization is sufficient, as covering redistribution and commercial distribution, and it says so explicitly. The owning grain references that record. Third-party dependency licenses still apply.

## 5. Agent Reach

Repository: `Panniantong/Agent-Reach`
Pinned commit: `a19a171fa980a0785849596492e0af4db800c82f`
Root license observed at pin: MIT
Primary owner grain: SG-000103

Initial selected boundaries:

| Source path | Class | Intended Orcel use |
| --- | --- | --- |
| `agent_reach/channels/base.py` | PORT | ordered backend candidates and user override semantics |
| `agent_reach/probe.py` | PORT | executable health probing |
| `agent_reach/doctor.py` | PORT | capability diagnosis/report model |
| `agent_reach/core.py` | PORT | channel registry and routing orchestration |
| `agent_reach/channels/*` | PORT | capability-specific provider patterns |

Rules:

- do not require Python merely to preserve a small routing abstraction if a Rust/TypeScript port is materially simpler;
- no backend is considered healthy from PATH presence alone;
- credential diagnostics never disclose secret values.

## 6. UI-TARS Desktop

Repository: `bytedance/UI-TARS-desktop`
Pinned commit: `2ff41a9e515828c5bd5b276e493d73aa0bdf4a3a`
Root license observed at pin: Apache-2.0; selected packages require per-package verification.
Primary owner grains: SG-000100, SG-000104

Initial selected boundaries:

| Source path | Class | Intended Orcel use |
| --- | --- | --- |
| `packages/ui-tars/action-parser/src/index.ts` and its package implementation | COPY_ADAPT | UI-TARS-compatible action parsing into ComputerActionProposal |
| `packages/ui-tars/operators/nut-js/src/index.ts` | REFERENCE | action vocabulary, coordinate conversion, model/operator behavior |
| `packages/agent-infra/mcp-servers/browser` | REFERENCE | structured browser engineering only behind Orcel browser authority |
| `apps/ui-tars/src/main/remote/operators.ts` | REFERENCE | remote lifecycle/operator lessons, not authority |

Explicitly rejected as caller authority:

- direct model-to-input execution;
- donor-side approval or target minting;
- arbitrary caller JavaScript/CDP tools;
- personal-profile authority inferred without local Orcel opt-in;
- independent donor remote operator authority.

## 7. gsudo

Repository: `gerardog/gsudo`
Pinned commit: `a4eda9b263d72a3e174f73b6b6b3ecfc5bc6656b`
Root license observed at pin: MIT
Primary owner grains: SG-000098, SG-000099

Initial selected boundaries:

| Source path | Class | Intended Orcel use |
| --- | --- | --- |
| `src/gsudo/Commands/ServiceCommand.cs` | COPY_ADAPT | elevated broker/service request loop |
| `src/gsudo/Helpers/ServiceHelper.cs` | COPY_ADAPT | OS-approved elevation startup and broker discovery |
| `src/gsudo/CredentialsCache/CredentialsCacheLifetimeManager.cs` | COPY_ADAPT | bounded elevated-session lifetime and revoke signal |
| `src/gsudo/CredentialsCache` | COPY_ADAPT | cache lifecycle semantics |
| `src/gsudo/Rpc` | COPY_ADAPT | authenticated local IPC mechanics after per-file audit |

Initial exclusion:

- SYSTEM authority;
- TrustedInstaller authority;
- arbitrary user credential collection;
- generic gsudo CLI compatibility as a Orcel tool;
- any path that bypasses normal Windows elevation consent.

## 8. Orcel-native responsibilities

The following remain Orcel-owned and are not delegated to donors:

- MCP tool contract and discovery;
- Safe, Full User, Full Admin, Persistent Admin, and remote profile semantics;
- FullControlLease, AdminLease, RemoteFullControlLease;
- workspace/device/session identity;
- authorization and policy revision;
- protected-surface decisions;
- audit, redaction, evidence, and revoke;
- private-host protocol and supervision;
- remote OAuth/relay/device binding;
- resource ceilings and failure-state normalization;
- installer/update/rollback integration;
- release qualification and provenance.

## 9. Import gate checklist

No donor code merge proceeds unless all boxes are proven for the exact diff:

- [ ] exact donor revision remains pinned;
- [ ] every copied/adapted source file is listed;
- [ ] applicable license/direct-permission evidence is recorded;
- [ ] third-party dependency obligations are enumerated;
- [ ] destination and modifications are recorded;
- [ ] no independent donor authority surface is exposed;
- [ ] no runtime dynamic donor fetch exists;
- [ ] targeted unit/integration/native tests pass;
- [ ] independent code review of the exact head is recorded on the PR (before 2026-11-23: TypeSafe Jev exact-diff review passes);
- [ ] Alibaba Open Code Review exact-range review passes;
- [ ] excluded files receive manual review;
- [ ] exact-head CI passes with zero unresolved blockers;
- [ ] post-merge verification updates canonical evidence.
