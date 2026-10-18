# Browser intelligence: Browser Use, Playwright, Stagehand, Skyvern, WebMCP → Orcel

Status: PROPOSED (Fable, 2026-10-18). Builds on the adopted SG-000108 design and `BROWSER_AGENT_DONORS_DECISION.md`, which stay authoritative for what is already merged. Donor pins: `donor_registry.json`. Rows: `transplant_matrix.json` `T-BU-*`, `T-PW-*`, `T-SH-*`.

## 1. One browser architecture: who owns what

| # | Responsibility | Owner | Why |
|---|---|---|---|
| 1 | Browser process (discovery, verification, launch, kill, sweep) | Rust browser host (`crates/orcel-browser-host`) | Policy authority; already qualified on Windows (SG-000074..79, 108) |
| 2 | CDP session | The private worker's single `--remote-debugging-pipe`, driven by playwright-core 1.63.0 | One channel; no port, no extension, no second client (Cua's CDP engine, Stagehand extension, chrome-devtools-mcp all rejected as channels) |
| 3 | DOM/accessibility observation | Worker: Playwright `ariaSnapshotJSON({mode: "ai"})` for actionable refs, `DOMSnapshot.captureSnapshot` for extraction and heuristics | Both already in use; no page script |
| 4 | Element target resolution | Host issues identities; worker resolves `aria-ref` and, on staleness, the normalized locator with a role/name/frame equality check (BR-01) | Playwright's `targetLocators` pattern, bound by the host |
| 5 | Authorized action execution | Worker executes one typed frame after the host checks policy and approval; vocabulary from playwright-core's own tool backend (BR-02) | Same library already admitted; no evaluate |
| 6 | Downloads and uploads | Host: staged, held handles; upload only from a host-staged approved file (SG-000078, BR-03) | Unchanged authority |
| 7 | Sessions | Host-owned Orcel profile per workspace; persistent profile is SG-000100 (profile expansion) | No personal-profile attach (Cua `--grant existing-profile` pattern rejected) |
| 8 | Crawling | Host queue over governed navigations (slice 7), scope rules from Firecrawl (WI-01) | One engine |
| 9 | Content extraction | Worker extraction pipeline (browser-use port) + relevance filters (WI-03) + document parser process (WI-05) | Untrusted text, bounded |
| 10 | Outcome verification | Host verifier with read-only worker probes (BR-07) + independent artifact checkers | A model summary is never completion |

There is exactly one engine per lifetime, one CDP pipe, one policy owner. Nothing in this plan adds a listener or a second channel.

## 2. Browser Use (`browser-use/browser-use@c75e8476`, MIT)

What was inspected (VERIFIED SOURCE FACT): `browser_use/browser` (19,235 lines), `dom` (6,188), `agent` (7,759), `tools` (3,603), `actor` (2,377), `filesystem` (1,104). The action implementations live in `browser/watchdogs/default_action_watchdog.py`, which has 27 `Runtime.evaluate`/`callFunctionOn` call sites; `actor/element.py` has 8; `tools/service.py` registers `evaluate` as a tool.

| Module | Verdict | Destination / reason |
|---|---|---|
| `dom/markdown_extractor.py`, `dom/serializer/html_serializer.py`, visibility in `dom/service.py` | **Already ported** (PR #312) | `apps/orcel-browser-worker/src/extract/*` |
| `dom/serializer/clickable_elements.py` | **PORT** (BR-04) | `src/observe/interactive.ts`, computed from the existing DOMSnapshot |
| `dom/serializer/paint_order.py` | **PORT** (BR-04) | `src/observe/occlusion.ts`; occluded target refused with a typed reason |
| `tools/service.py` action semantics | **REFERENCE** (BR-02, BR-03) | input clears then types; dropdown discovery for non-native comboboxes; nearest file input to the target; `terminates_sequence` after navigation |
| `browser/watchdogs/default_action_watchdog.py` | **REJECT as code** | page-context evaluation |
| `browser/watchdogs/{downloads,crash,popups,permissions}` | REFERENCE | host already supervises these |
| `agent/` (loop, message manager, step budgets), `llm/`, `mcp/`, `sandbox/`, `cloud`, `telemetry` | **REJECT** | Orcel serves tools; the planner is the external client or founder AI |
| `agent` loop-detection and step budgets | REFERENCE | ideas for the founder AI service (F7), not the kernel |

No permanent Python runtime is added: every port is TypeScript inside the existing worker.

## 3. Playwright tool backend (`microsoft/playwright@1b025d7e` = tag v1.63.0, Apache-2.0)

Key fact: in 1.63.0 the MCP tool implementations ship inside **playwright-core** at `packages/playwright-core/src/tools/backend/` (snapshot, form, keyboard, mouse, files, tabs, dialogs, wait, verify, tab, navigate, ...). That is the dependency SG-000108 already admitted, so reusing its source adds no new dependency.

| File (blob) | Verdict | Use |
|---|---|---|
| `snapshot.ts` (`cda3d0fa`) | COPY_ADAPT | click/hover/drag/select by ref (BR-02) |
| `form.ts` (`193e2b3d`) | COPY_ADAPT | fill/check/select; secret fields refused (BR-02) |
| `keyboard.ts` (`f8f3abd2`) | COPY_ADAPT | press/type (BR-02) |
| `files.ts` (`44e1f5ee`) | COPY_ADAPT | file chooser with host-staged file (BR-03) |
| `tabs.ts` (`93ad12a0`), `dialogs.ts` (`6d3d0f25`) | COPY_ADAPT | BR-05 |
| `wait.ts` (`11aa2a8d`) | COPY_ADAPT | bounded waits; drop the `page.evaluate` timer |
| `verify.ts` (`a27eb72e`) | COPY_ADAPT | postcondition probes (BR-07) |
| `tab.ts` (`68a10ad6`) `targetLocators` | COPY_ADAPT | stale-ref recovery (BR-01) |
| `evaluate.ts` (`eaaa7843`), `runCode.ts` (`62905a7b`), `cookies.ts`, `route.ts`, `network.ts`, `storage.ts`, `webstorage.ts`, `devtools.ts`, `codegen.ts`, `tools/mcp/*` | REJECT | caller code, cookie/storage export, network rewriting, second MCP server |

Adaptation rules: keep the locator calls and their timeouts; remove zod schemas, the MCP `response` builder and code generation; each tool becomes one closed worker frame with byte bounds; the host decides policy and approval before the frame is sent.

## 4. Stagehand (`browserbase/stagehand@f261c38b`, MIT)

- `packages/extension/understudy/a11y/snapshot` → **COPY_ADAPT** for cross-frame and OOPIF observation (BR-06), without `resolveObjectIdForXPath` (Runtime focus path).
- `packages/extension/understudy/page.ts` WebMCP CDP client → **COPY_ADAPT after FD-08** (argv amendment for the experimental engine flag) (BR-08).
- Extension runtime, in-browser LLM calls, `domainPolicy.ts`, action cache → REJECT (cache idea noted as "deterministic replay of a verified run with fresh approvals").

## 5. Skyvern (`Skyvern-AI/skyvern@f5f3f28a`, AGPL with founder authorization)

Unchanged: no module imported, by architecture (page-injected `domUtils.js`; generated-program replay). REFERENCE only.

## 6. Cua's browser support

Cua Driver contains its own CDP engine (`cua-driver-core/src/browser/*`, `cdp_ws.rs`, pooled loopback WebSocket) and an existing-profile attach grant. **REJECT**: a second browser channel and personal-profile authority. Patch P-03 compiles it out of the native host.

## 7. WebMCP

Declarative discovery and approval-gated execution are merged (slices 4/5; MCP-B pieces adapted). Native imperative WebMCP waits for FD-08. The spec repository stays a reference.

## 8. Chrome DevTools MCP, Playwright MCP package

REFERENCE only. Never a second edge.

## 9. Reliability and performance changes, in priority order

1. **Stale-target recovery** (BR-01): fewer TargetStale aborts on re-rendering apps, never acting on a different element (swap test).
2. **Typed vocabulary** (BR-02, BR-03, BR-05): forms, uploads, tabs, dialogs: the main capability gap today.
3. **Interactivity and occlusion** (BR-04): fewer clicks on covered elements.
4. **Postcondition verifier** (BR-07): success claims backed by evidence.
5. **Relevance filtering** (WI-03): fewer tokens per step for the client model.
6. **Observation batching**: keep one snapshot per step and re-observe only after a mutation (adopted rule).

Do not claim speed or accuracy gains until `BENCHMARK_AND_E2E.md` M-BR metrics are measured against the current baseline with the same planner.

## 10. Security deltas

See SECURITY_INTEGRATION.md rows S-08 (new actions), S-09 (upload egress), S-10 (dialogs), S-11 (frames). No change to the no-evaluate, single-channel, host-decides rules.
