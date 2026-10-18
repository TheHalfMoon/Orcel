# Orcel MVP fast track

Status: ADOPTED planning direction (founder decision, 2026-10-09; Sol revision governs where it differs from the Opus baseline). Grants no authority: every capability still needs its own grain, review and qualification. Current execution state: `EXECUTION_FRONTIER.md`. Evidence baseline of this revision: PR #283 at `87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985`, PR #282 at `10540885f3c52bd0c0d2f00cc23e3cafe067fe36`.

## Roadmap A: Opus's graph, fairly assessed

The original 25 packets are not all MVP prerequisites. Its local Core path is WP00 adoption -> WP01 ledger -> WP04 full shell and WP05 browser -> WP06 tasks -> WP07 filesystem parity -> WP08 app -> WP10 installer -> WP11 E2E. UI and harness can begin early; parallel authority grains require approval. WP12 client qualification comes after installer. WP13–17 build directory, E2E/LAN, DAG/transfer, indicators and remote full control; WP18–23 hosted AI/voice/billing; WP24 later platforms.

Strengths: authority deltas and acceptance gates are explicit; security repair is independently startable; unrelated research/UI/harness work is recognized. Risks: broad shell/parity and custom browser engineering precede a narrow complete task, interoperability is discovered late, LAN is a transfer prerequisite, and UI can drift around mocked events. No validated completion date exists. Preserve the governance order; change scope and dependencies rather than treating every packet as mandatory.

## Roadmap B: increments that users can verify

Effort bands are relative ESTIMATES: S small contained adapter/test work; M several interacting components; L new privilege or platform qualification. They are not dates and exclude unknown reviewer availability. One active authority grain remains the default until explicitly approved otherwise.

| Increment | Dependency / effort | Working milestone and exit test |
|---|---|---|
| F0 read-only app now | PR282 review, small authenticated app API; M | App reports real daemon/capabilities, bounded folder reads and actual events; responsive I/O and visible native keyboard/accessibility tests. No mutations, fabricated chat or model dependencies. |
| F1 approval integrity (DONE: PR #286, `main@1edfa20`) | Independent security grain; M, fault behavior may enlarge scope | All #278 regressions and fault/migration tests pass; independent Windows review; approved normal merge. No dependent privilege activated earlier. |
| F2 first local report task | F0 + F1, existing workspace provider, minimal task records; M | Test planner or one qualified MCP client reads known figures, proposes approved create-only report and independent checker validates saved bytes/hash. Reject overwrite/out-of-scope/stale source. |
| F3 real browser task | Existing contracts + approved grain + F1 before mutations; M/L | Constrained Playwright worker navigates controlled site, downloads exact PDF to approved folder, preserves policy and verifies artifact. Browser work need not depend on full shell. |
| F4 Core MVP qualification | F2 + F3 + existing SG096 terminal progress; M | One supported external client transcript, real app timeline/stop/takeover, native journey tests, clean signed/attested packaging and full installed app <400 MB. Truthfully label unarmed terminal capabilities until SG096 activation passes. |
| F5 complete Windows Core | SG096 independent qualification + required file/Office subset + additional clients; L | Governed interactive sessions, bounded process output and cleanup, spreadsheet journey, client matrix and update/recovery tests. No need for generic fuzzy-edit/PDF feature parity first. |
| F6 two-target devices | F1 + F4, reviewed target grants/transfer contract; L | Controller selects two targets; read/transfer with independent source/destination authorization; verified copy and disconnect/revoke/stop tests. No LAN/QUIC prerequisite. |
| F7 founder AI and voice | Stable proposal/receipt boundary + separately authorized hosting; L | Server-only Hala, optional Reliance ablation, text before voice, then spoken command with local consent and checked outcome. No training/billing dependency. |
| F8 scale/platforms | Measured F6/F7 demand; XL | Directory/load/tenant isolation; optional direct transport, team administration, additional OS hosts only with an approved need. |

MVP First Path is F0/F1/F2/F3/F4. Complete Product Path adds F5/F6/F7 and qualified scale; a browser/file MVP is not marketed as completed full terminal/Office/AI/multi-device support. Basic installer inventory and one-client compatibility begin in F0/F2, so late surprises cannot derail F4. Signing distribution is an open release decision, not a reason to postpone read-only engineering. Trademark review can proceed independently; preserve existing compatibility identities and avoid declaring legal conclusions final.

## Disposition of all original work packets

| WP | Disposition and dependency correction | Gate / authority |
|---|---|---|
| 00 | KEEP planning review; security fix need not wait | Founder adoption, no canonical implementation claim |
| 01 | KEEP first security priority; strengthen repair tests | Repairs authority, independent security review |
| 02 | PARALLEL legal review; not a local engineering prerequisite | Founder/counsel decision before relevant distribution |
| 03 | DEFER broad rename until decision; repository already named Orcel | Compatibility migration, no tool/scope churn |
| 04 | KEEP SG096; narrow slices, do not replace donor without approved amendment | New shell privilege requires existing activation order |
| 05 | REDESIGN wrap Playwright-core; independent of full shell | Live browser authority + F1 and explicit grain |
| 06 | MERGE minimal step/status/cancel/receipt into F2/F3 | Existing result semantics; no generic workflow engine |
| 07 | DEFER parity; ADAPT only required report/Office read and approved save | File identity and destination policy preserved |
| 08 | KEEP WPF; start real read-only API/events immediately | Kernel-owned approvals; new UI methods reviewed |
| 09 | DELETE from MVP; later measured Node optimization only | 40-tool/OAuth compatibility before any replacement |
| 10 | KEEP incremental inventory early, final release gate F4 | No unreviewed installer elevation/update path |
| 11 | KEEP journey harness early, expand per increment | Native independent tests and denial fixtures |
| 12 | MOVE one client to F2; extend matrix later | Per-version evidence, not universal client promise |
| 13 | MERGE bounded controller directory with F6 | Explicit observation grants per target |
| 14 | REDESIGN relay-first; E2E as required; DEFER LAN/QUIC | Cryptography/protocol amendment review |
| 15 | SPLIT narrow transfer first; DEFER DAG/weighted queues | New read/egress/create contracts; no offline mutation |
| 16 | KEEP with F6 before first remote action | Local visible indicator and immediate stop |
| 17 | DEFER arbitrary remote full control until separate activation | SG105/successor locally issued lease |
| 18 | KEEP small control service; skeleton can prepare independently | No device authority; no provisioning in this review |
| 19 | REDESIGN founder-server bounded loop; delete AI BYO pilot | Cloud proposes only; Core external clients separate |
| 20 | KEEP founder-hosted Holo4 adapter; no external API pilot | Runtime/weights/privacy qualification; training separate |
| 21 | DEFER default service until ablations; custom decision adapter | Advice only, stricter/abstain permitted |
| 22 | KEEP after text workflow; offline corpus/harness preparation independent | Voice never authorizes, all speech processing server-side |
| 23 | DELETE billing/allowances from roadmap now; MERGE telemetry/caps with18 | Cost control needed; pricing deferred |
| 24 | DEFER macOS/Linux until funded requirements. **Adopted 2026-10-18: deferral REMOVED** (founder directive: all three OSes first-class); replaced by tracks X0–X6 in `docs/orcel/implementation-readiness/ROADMAP.md` | New platform authority/conformance per task in `docs/orcel/implementation-readiness/backlog/tasks.json` |

Safe parallel preparation: UI reads/events, fixture/checker development, dependency inventory, source/license admission, AI schema mocks and offline voice evaluation can proceed with separate files/owners/tests and no new dispatch. Mocks must be visibly test-only. Simultaneous authority implementation is not automatically authorized by this plan; record independence and obtain the required governance decision.

## Five journeys: exact scope, tests and proof

### 1. Browser report/PDF

Existing: origin/redirect/download/upload policy shapes and supervised browser launch; DOM is a template. Missing: real navigation/search/extraction/download and model/client feedback. Fastest reusable path: constrained Playwright-core with dedicated installed-browser profile, external client or deterministic test planner, staged download and existing folder policy. Dependencies F1/F3 plus one client, not Hala or full shell.

Boundary/consent: allowed origins and actual network egress, explicit approved folder, exact create-only PDF destination; upload is a separate grant. Page content never becomes policy. Acceptance: owned site has a dated report list and a known PDF fixture; choose latest by declared date, download to approved folder, reject redirect to forbidden/private destination and oversized/path-traversal filename. Summary cites source URL/date and fixture facts. Checker validates destination PDF SHA/content and absence of out-of-scope writes. Offline/timeout/navigation drift causes bounded error/re-observation; post-dispatch uncertainty requires destination reconciliation, not blind download retry. Public 'latest' task separately records run time/search coverage; do not pretend a fixture proves global freshness.

### 2. Desktop spreadsheet -> approved report

Existing: window/UIA/capture/input and workspace file primitives. Missing: workbook semantics, task wiring and app approval/progress. First fixture can be CSV for rapid read/create proof; it does not establish XLSX/Excel support. To complete the actual spreadsheet journey, qualify licensed installed Excel via narrow read-only COM/application adapter (macros/external links disabled) or an audited document parser plus UIA opening; no arbitrary Office automation.

Dependencies: F1/F2 then focused F5; existing Full User grant only if desktop input requires it. User selects exact workbook and figures and approves create-only report path after preview. Acceptance: workbook fixture with known cells, formula values and currency totals; open correct process/window, extract requested figures, refuse macros/link refresh, propose report with source cell references, deny save once, then grant a fresh save. Checker independently parses resulting report and verifies expected values/hash and unchanged workbook. Stale workbook hash/unsaved edits require re-observation; existing destination conflicts require new consent; unknown save state is reconciled. Missing Excel/license/parser is an explicit unavailable state.

### 3. Other computer -> permitted copy

Existing: identity/OAuth/relay primitives. Missing: controller UI, target-scoped folder/transfer capability and indicators. Reuse existing relay, not new mesh. Dependencies F6 and qualified ledger, per-target contract/E2E if required. Test A controlling B and C; independently pair both, then transfer B's permitted report to A with source egress and A's destination-write consent. Try C without its matching grant and an unpaired fourth target: denied. Checker compares final hash/bytes, receipts and no credential exports. Drop network before and after final commit; restart/revoke/stop; staging cleans up, and unknown completion is reconciled before another mutation. No generic remote full control needed for the bounded transfer.

### 4. External MCP client task

Existing: 40 tools, stdio/HTTP/relay, OAuth and profile separation. Missing: live product transcript per actual client/version and support configuration. Qualify one available supported Claude/Codex configuration first; ChatGPT availability/scopes depend on plan and supported transport, so do not claim every account or local stdio integration works.

Acceptance: exact client version/config and tool list digest; authorized workspace read -> proposal -> deny save -> fresh request -> approved create-only save; unknown tool/profile denied, scopes expire/revoke correctly, disconnect never duplicates dispatched save. Record MCP exchange with secrets redacted and independent final-file checker. The same local broker remains authoritative regardless of client assertions. Preserve local-only desktop restrictions; wider remote desktop is a separate authorization.

### 5. Spoken Orcel AI command

Existing: execution pipeline and proposed observation schemas, no integrated hosted models/voice. Missing: founder-hosted Hala serving, bounded orchestration, speech, tenancy and UI. Fast path: text workflow with Hala plus deterministic router, then server-side push-to-talk STT/TTS; Reliance optional. Dependencies F7 and model/runtime/privacy qualification, not future fine-tuning or checkout.

Acceptance: Arabic/English/code-switched fixture commands with known intent, founder-side inference logs pinned to model/config revision, no model weights/inference on device; exact local proposal and denied/approved action; checker verifies final artifact. Forged/stale proposal, wrong target/tenant, model outage, budget exhaustion, recorded/spoofed voice and barge-in must not authorize effects. UI shows real cloud state and egress destination. Unclear speech asks for clarification; voice cancellation stops planning/playback, and dispatched effects remain known/unknown under local rules. Cold start/queue time is visible rather than a fake response.

## Next three implementation packets

1. **Security owner, #278, M (DONE via PR #286; see `EXECUTION_FRONTIER.md`):** repair one-writer durable ledger/restart semantics; three regression tests plus fault/migration/rollback matrix; no new capability. Exit only after independent exact-head governance and Windows qualification.
2. **App/API owner, PR282 follow-up, M:** authenticated read-only status/event API, compact WPF shell, async bounded folder/CLI I/O, timeline/stop state presentation; tests for unavailable daemon, huge folder, stalled process, keyboard/Narrator and event gap. No approval minting.
3. **Browser owner, narrow adopted grain, M/L:** wrap stable Playwright-core to navigate one owned site and download one fixture PDF through existing contracts; security denials, stale target/crash/stop and artifact checker. Prepare fixtures/adapter independently; mutations wait for packet1 and the authorized grain frontier.
