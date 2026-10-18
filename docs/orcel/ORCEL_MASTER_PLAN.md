# Orcel master plan — independent Sol revision

Status: ADOPTED planning direction (founder decision, 2026-10-09; Sol revision governs where it differs from the Opus baseline). Grants no authority: every capability still needs its own grain, review and qualification. Current execution state: `EXECUTION_FRONTIER.md`. Evidence baseline of this revision: PR #283 at `87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985`, PR #282 at `10540885f3c52bd0c0d2f00cc23e3cafe067fe36`.

## Judgment

Opus produced a useful research inventory and a defensible authority model. I would not adopt the package unchanged. Its delivery strategy optimizes hypothetical runtime size before proving working tasks, duplicates mature browser engineering, and contradicts the founder's server-only AI and deferred-pricing requirements. The security repair proposal is incomplete. Keep the kernel, simplify everything around it, and ship a Windows app that completes one bounded task before building fleet infrastructure.

These scores assess the proposed plan, not the quality or security of a shipped product. They are engineering judgments, not benchmark measurements.

| Category | /10 | Evidence and reason |
|---|---:|---|
| Research quality | 7 | Exact source pins and honest measurement labels are valuable; REA raw provenance is unavailable, donor conclusions sometimes outrun inspected code. |
| Architecture quality | 7 | One local authority and structured-first execution are strong; Rust CDP and an MCP rewrite add avoidable ownership. |
| Security | 6 | Correct local trust boundary; independently reproduced ledger defects, incomplete crash/concurrency/rollback repair, overconfident redaction. |
| Speed/performance strategy | 6 | Good focus on observations and postconditions; no task baseline, warm-worker or extra Reliance-call measurements. |
| Product UX strategy | 6 | Thin shell and visible approvals are sound; toolkit indecision and broad prerequisite graph postpone an actual workflow. |
| Reuse efficiency | 5 | Keeps existing kernel; rejects the most useful browser runtime on an incorrect incremental Node-size argument. |
| Multi-device design | 6 | Explicit target grants and unknown-outcome handling are strong; LAN, QUIC and DAGs precede the two-target proof. |
| Orcel AI integration | 5 | Cloud proposes/device decides is right; API pilot contradicts founder hosting; d1 is a custom decision head. |
| Cost efficiency | 5 | Script arithmetic reproduces; 300-subscriber crossover is unsupported; price hypotheses become architectural dependencies. |
| Speed to a real MVP | 4 | 25 packets are not all on the MVP path, but shell/browser/task/parity/installer sequencing still delays narrow value. |
| Maintainability | 6 | Typed contracts help; new CDP maintenance, optional edge rewrite and overlapping plan registers increase drift. |
| Competitive potential | 7 | Local authority, native Windows and verified artifacts could differentiate; superiority has not been measured. |

## Verified frontier and evidence ledger

Fresh GitHub reads on 2026-10-09 confirmed public repository identity Orcel, default branch main, and main head `61e664b3c39380a76aede29aa9c2d7fcbc449b08`. PR #283 remains open/draft at the baseline above, 15 changed files: 14 Markdown and the dependency-free economics script. PR #282 remains open/draft, four files. Issues #278/#279/#280/#281/#260 were open when inspected. The active canonical program remains SG-000096; this review does not activate a successor.

Both original PR heads had 11/11 completed successful checks. Actual #283 Jev log: 15 expected and 15 reviewed hunks, PASSED, no reported blocking findings. Actual Alibaba log: one reviewable file, 14 Markdown exclusions with unsupported_ext. Green delegation does not establish review of those documents. No submitted formal reviews or review threads were returned at initial inspection; an earlier independent issue comment existed. This report supplies manual architectural review, not founder adoption.

The live active [main ruleset](https://github.com/TheHalfMoon/Orcel/rules/24456712) has ten required check contexts, no bypass actors, and strict status checks. It permits merge/squash/rebase and does not require thread resolution at API level; project governance is stricter and requires normal merge and resolution. Do not infer absent protection from the legacy branch-protection field or Opus's 404.

| ID / evidence class | Observation and primary evidence |
|---|---|
| E1 VERIFIED FACT | [PR283](https://github.com/TheHalfMoon/Orcel/pull/283), [PR282](https://github.com/TheHalfMoon/Orcel/pull/282), [main](https://github.com/TheHalfMoon/Orcel/tree/61e664b3c39380a76aede29aa9c2d7fcbc449b08). GitHub reports PR283 signature valid; DCO footer present. |
| E2 VERIFIED FACT | [Browser provider](https://github.com/TheHalfMoon/Orcel/blob/87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985/crates/orcel-provider-browser/src/lib.rs#L1730) returns a fixed template; host supervision is not live browser actuation. |
| E3 VERIFIED FACT | [MCP tool contract](https://github.com/TheHalfMoon/Orcel/blob/87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985/apps/orcel-mcp/src/tool_contract.ts) has 40 tools, 26 core plus 14 local-only; OAuth, pairing and relay already exist. |
| E4 EXPERIMENTAL FINDING | Original approval library plus three added tests in an isolated copy: 27 existing passed, three regressions failed, exit 101. Replay after restart, approval C lost, two live brokers accept one token. See security report and retained test log. |
| E5 MEASURED RESULT | PR282 verification compiled a 22,016-byte WPF executable and passed router/layout self-tests. No visible GUI automation, installer, RAM, startup or user-journey qualification was performed. |
| E6 VERIFIED FACT | Twelve public donor source checkouts, licenses and exact HEADs independently read; inventory in reuse matrix. Main snapshots of Playwright are prerelease, not selected production dependency pins. |
| E7 SOURCE-DOCUMENTED CLAIM | Holo4/d1 model cards, Liquid license, Chrome debugging-profile guidance, RunPod billing docs; serving and vendor scores are not Orcel measurements. |
| E8 MEASURED RESULT | Original unit_economics.py executes offline and reproduces tables. At its assumptions, reserved GPU cost is $1,584/month and API-equivalent Hala cost $1.2375/subscriber; crossover is 1,280 subscribers, not 300. This comparison is illustrative only; no third-party AI pilot is planned or permitted. |
| E9 BLOCKED CAPABILITY | REA doctor invocation exits 1: compiled runtime missing. Opus's timings, OOM and analysis artifact remain secondary execution evidence; installed Desktop Commander 0.2.52 and source patterns were independently inspected. |
| E10 VERIFIED FACT / limitation | Authorized private donor code and tests were inspected. Private revision/file evidence is kept in the local reuse-matrix appendix and excluded from public publication. No private code imported. |

Use MEASURED RESULT only for an actual run; SOURCE-DOCUMENTED CLAIM for vendor statements; ENGINEERING INFERENCE for architecture choices; ESTIMATE for effort/budgets; UNPROVEN ASSUMPTION for throughput/size; OPEN DECISION for adoption/legal clearance. A source contract is not an implemented journey. Competitor task performance is NOT MEASURED.

## Direct answers A–O

**A — Is the plan good?** Yes as research and a proposal inventory; insufficient as the adopted execution plan.

**B — Adopt unchanged?** No. Correct ledger recovery, browser reuse, hosting, pricing and milestone sequence first.

**C — Five largest weaknesses:** unnecessary CDP ownership; incomplete approval persistence/recovery; contradictory AI-hosting and subscriber threshold; infrastructure-heavy two-device path; no working-task evidence behind performance/product conclusions.

**D — Five strongest decisions:** orceld remains sole authority; structured methods before pixels; no cloud-granted privilege; explicit per-device grants; unknown-outcome reconciliation rather than automatic mutation retries.

**E — Remove immediately:** MVP MCP rewrite prototype; LAN/QUIC prerequisites; compulsory Reliance calls; subscription allowances/billing gates; rollback to a known-defective ledger. Remove categorical claims that competitors lack authority kernels or that registered-secret filtering finds every screenshot secret.

**F — Redesign:** browser as a constrained Playwright worker; task receipts as a minimal per-step record; two-target orchestration over the existing relay; founder-hosted AI as one control service plus workers; compact WPF shell with real broker events.

**G — Reuse:** keep authority/UIA/capture/input/identity/OAuth/MCP; wrap Playwright-core; adapt bounded file/search and lifecycle behavior; copy small tested parser parts only after provenance review; use fleet and agent frameworks as references. Do not replace the authorized SG096 donor merely on a language preference.

**H — Better browser approach?** Yes: Playwright-core behind a private typed host interface, using installed Edge/Chrome and a dedicated profile. Qualify stable release and policy enforcement. Rust CDP remains a later, measurement-triggered optimization.

**I — WPF or Tauri?** Keep WPF for Windows v1. Reverse only with a funded near-term cross-platform requirement and measured parity on the same functional screens, accessibility/RTL, IPC security, startup, memory, packaging and update tests.

**J — Rewrite MCP now?** No. Preserve the 40-tool contract, OAuth and pairing. Package one pinned Node runtime for edge and worker processes. Measure total installed bytes before reconsidering.

**K — Fastest safe app?** Start the read-only shell/API and harness immediately; repair #278 independently; deliver approved create-only report generation and real browser download; qualify one actual MCP client; finish terminal activation under SG096 rather than making every shell feature a browser dependency.

**L — Faster/more reliable than rivals?** Possibly through generation-bound structured observations, direct APIs, event-driven waits, minimal model calls and independent artifact verification. Prove paired task-time distributions, success and unauthorized effects with the same planner and workload. Present advantage is a hypothesis.

**M — Scale without bloat?** Yes in design: same thin app, paginated directory, lazy device subscriptions, bounded queues and per-target grants. Fleet load, revocation propagation and staffing remain unmeasured.

**N — Overengineered?** Governance is necessary and must be preserved. The execution dependency graph and proposed networking/serving decomposition are overbuilt for the initial product. Evidence collection can be automated; review cannot be bypassed.

**O — My company first?** A Windows app that finds a real document and creates a verified approved report, with truthful progress and stop. Refuse a browser-engine rewrite, edge rewrite, enterprise mesh, payment system, mandatory router model or broad unattended privileges before that proof.

## Adoption and next work

The founder adopted this revised direction on 2026-10-09; it is adopted as planning only (merged through PR #283). Update 2026-10-10: #278 is repaired by PR #286 (merged as `main@1edfa20`, post-merge CI green, issue closed). Design, qualification evidence and residual risks: `docs/security/ISSUE-278_APPROVAL_LEDGER_INTEGRITY_NOTE.md`. (Historical text at review time: keep #283 draft and #278 open.) No production source, permissions, CI, canonical state, models or infrastructure were changed by this review.

Next three executable packets at review time (current next grains: `EXECUTION_FRONTIER.md`): (1) #278 isolated security repair (done, PR #286) with durable one-writer append and full fault tests; (2) WPF read-only app API/timeline and truthful daemon status, correcting UI-blocking I/O; (3) narrow live-browser adapter behind existing contracts with real download and denial fixtures. Packet 2 can develop read-only functionality independently; packet 3's mutations wait for qualified ledger repair and authorized grain sequencing. See `IMPLEMENTATION_ROADMAP.md` for estimates and exact exit tests.

## Cross-platform revision (2026-10-18)

Status: ADOPTED planning direction (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. Where it differs from the text above, this section governs.

The founder directed on 2026-10-18 that Windows, macOS and Linux are all first-class targets, and that authorized donor code be reused before anything is rebuilt. A source-level review of every recorded donor, at exact pins, produced `docs/orcel/implementation-readiness/` (entry `OPUS_HANDOFF.md`). Summary of what it changes here:

- Answer O ("A Windows app ... first") stays the first release. macOS and Linux are no longer deferred: they follow on a parallel track, X0 (foundation) to X5 (packaging), plus X6 (measurement).
- Answer I ("Keep WPF for Windows v1") meets its own reversal condition (a) as a founder-directed requirement (funding is not separately recorded). The proposed direction is a Tauri 2 Control Room on all three OSes, gated by the measured condition (c); WPF stays until that gate passes.
- Answer G ("Reuse") becomes file-level. macOS/Linux desktop control comes from vendored Cua Driver platform crates inside an Orcel-owned host. Browser actions come from playwright-core's own tool backend. UI events use AgentKit. Optional sandboxes use cua-vmm and SPACE. Firecrawl, crawl4ai and Stagehand contribute specific units. Every row is in `SOURCE_TRANSPLANT_MATRIX.md` with git object SHAs.
- Security deltas found during the review: the approval/audit shared-temp fallback off Windows, and the `0.0.0.0` no-route proxy, which reaches loopback on Unix (`SECURITY_INTEGRATION.md` S-01, S-06).
- Unchanged: the single authority, tool names, the browser engine choice, relay and multi-device shape, server-side founder AI, and the no-paid-dependency rule.

## Open decisions

| Decision | Owner | Where discussed |
|---|---|---|
| (Resolved 2026-10-18) Adopt the cross-platform revision and run it in parallel (FD-01, FD-02); FSL and AGPL distribution scope (FD-04, FD-06) | Founder, `docs/orcel/grants/2026-10-18-founder-attestation.md` | `docs/orcel/implementation-readiness/IMPLEMENTATION_BACKLOG.md` |
| Tauri 2 Control Room direction (FD-03); macOS runner and Apple Developer ID (FD-05); Windows host consolidation (FD-07); WebMCP engine flag (FD-08) | Founder | `docs/orcel/implementation-readiness/IMPLEMENTATION_BACKLOG.md` |
| Whether approvals should be invalidated on broker restart, or a trust anchor added against tail rollback | Founder + security review | SECURITY_THREAT_MODEL.md; residual risk in the #278 note |
| Whether relay-blind (end-to-end) encryption is required before confidential transfer | Founder + security review | MULTI_DEVICE_ARCHITECTURE.md |
| Code signing and distribution channel for releases | Founder | IMPLEMENTATION_ROADMAP.md (F4) |
| Retention of screen/audio observations for Orcel AI | Founder (privacy) | ORCEL_AI_SERVER_ARCHITECTURE.md |
| Tauri reversal (only on the stated measured conditions) | Founder | UI_UX_AND_APP_SIZE_BUDGET.md |
| Written rights grants for Firecrawl and the Hala/Reliance models (source-code permission for all donors attested by the founder 2026-10-12, `SOURCE_PERMISSIONS.md`; the source-code part is closed by the founder authorization of 2026-10-13 (`docs/orcel/grants/2026-10-13-founder-source-authorization.md`), without committing the confidential documents; only the model grants remain open) | Founder + counsel | SOURCE_REUSE_MATRIX.md, ORCEL_AI_SERVER_ARCHITECTURE.md |
| Trademark/naming clearance | Founder + counsel | OPUS_TO_SOL_CHANGELOG.md (D14) |
| Whether a Rust PTY engine should replace the authorized SG-000096 terminal donor | Founder | IMPLEMENTATION_ROADMAP.md (WP04) |

## Revision provenance

This proposed revision corrects the Opus planning package at the baseline above. Original research/decisions remain available at that immutable Git revision; Opus execution claims are attributed and are not relabeled as Sol measurements. OPUS_TO_SOL_CHANGELOG.md records decision changes. No canonical adoption or implementation is claimed.
