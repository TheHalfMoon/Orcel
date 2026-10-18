# Orcel execution frontier

Status: EXECUTION FRONTIER (a working summary that mirrors grain state; it does not set it — canonical grain state lives in `.specgrain/` and `docs/canonical/`). Update this file whenever a grain merges, blocks, or the next grain changes. It serves implementation; it grants no authority. Planning detail lives in the adopted documents listed below; evidence lives in PRs, issues and CI runs.

Last verified: 2026-10-18 · main `40fc9f0a17b158188d20084126e2742b1632002c` (Merge PR #343; CI green). Previous verification: 2026-10-10 · `37a1a0f`.

**Cross-platform revision (2026-10-18, ADOPTED by the founder, `docs/orcel/grants/2026-10-18-founder-attestation.md`):** the founder directed that Windows, macOS and Linux are all first-class targets. The implementation-ready plan, donor registry, transplant matrix and backlog are in `docs/orcel/implementation-readiness/` (entry: `OPUS_HANDOFF.md`). It keeps every adopted decision below except the macOS/Linux deferral and the WPF-only UI decision; see its `ARCHITECTURE_DECISIONS.md` section 2.

## Adopted decisions

The founder adopted the Sol app-first revision of the Opus plan on 2026-10-09. Where Sol and Opus differ, Sol governs. Adoption sets direction only: every capability still needs its own grain, review and qualification.

| Area | Decision | Source |
|---|---|---|
| Authority | `orceld` stays the sole local authority; no peer policy daemon; cloud and UI never mint approvals | ARCHITECTURE.md |
| Windows app | WPF for Windows v1 (PR #282 foundation); authenticated private app API; reversal only on the stated measured criteria | UI_UX_AND_APP_SIZE_BUDGET.md |
| Browser | Constrained Playwright-core worker behind existing browser contracts; dedicated installed-browser profile; no public CDP, no generic evaluate; Rust CDP deferred | ARCHITECTURE.md, SOURCE_REUSE_MATRIX.md |
| MCP | Keep the 40-tool Node edge, OAuth and pairing; no rewrite | ORCEL_MASTER_PLAN.md (D7) |
| Multi-device | Existing identity/OAuth/outbound relay first; per-target grants; no LAN/QUIC prerequisite; `orcel-relay/1` frames frozen | MULTI_DEVICE_ARCHITECTURE.md |
| Orcel AI | All inference, orchestration and speech on founder-controlled servers; Core needs no founder inference; Reliance optional until ablations; no third-party per-token pilot | ORCEL_AI_SERVER_ARCHITECTURE.md |
| Pricing | Deferred; cost telemetry and caps instead of billing milestones | INFRASTRUCTURE_AND_UNIT_ECONOMICS.md |
| Delivery order | F0 read-only app → F1 approval integrity → F2 local report task → F3 real browser task → F4 Core MVP qualification; then F5 Windows Core, F6 two targets, F7 AI and voice, F8 scale | IMPLEMENTATION_ROADMAP.md |

## Grain status

| Grain | Status | Evidence / blocker |
|---|---|---|
| F1 · #278 approval ledger repair | MERGED, QUALIFIED | PR #286 → `1edfa20`; exact-head CI `38027857177`, post-merge CI `38028514439`; review evidence on #286 and the #278 closeout comment; #278 closed. Residual risks (tail rollback, lock bypass, path aliases) in `docs/security/ISSUE-278_APPROVAL_LEDGER_INTEGRITY_NOTE.md` |
| Git 2.56 compatibility | MERGED | PR #287 → `50982e7`: governed git and git tests work with Git for Windows 2.56 |
| F0 · WPF read-only shell | MERGED (first slice) | PR #282 → `37a1a0f`: truthful runtime status from the runtime's JSON, bounded non-blocking I/O, accessibility ids, native UI Automation E2E (13/13 against a real install; evidence on PR #282). Open: idle memory higher than expected (#288) |
| F0 · app API (status/events/tasks) | NOT IMPLEMENTED | Next executable grain |
| F2 · local report task | NOT IMPLEMENTED | Needs F0 + F1 |
| F3 · Playwright browser worker | GRAIN, IMPLEMENTATION IN PROGRESS (SG-000108, #289, tracking #290) | Parallel with SG-000096 by founder decision (2026-10-10). Merged since 2026-10-10: worker package, native probes, launcher, HTTPS probes, navigation, observation and activation, PDF download, typed outcomes, WebMCP discovery and execution, browser-use extraction port, native extraction, map/crawl, robots/sitemaps, download hardening, crash recovery, TesterArmy E2E, loopback-only confinement, profile sweep, engine window, product-caller slices 1a-3a (#294-#335). Open: #336 slice 3b-i runtime pin (checks green, merge conflict with main since 2026-10-14) |
| F4 · Core MVP qualification | NOT STARTED | F2 + F3, one real MCP client, installer < 400 MB |
| SG-000096 privileged shell (#260) | GRAIN (spec state) | #278 prerequisite removed; T02 hardening records in `docs/p20/`; T02–T05 issues #264–#267 and #271 open; Full User shell stays unarmed |
| F5–F8 | NOT STARTED | See roadmap dependencies |
| Cross-platform track (X0–X6) | ADOPTED, IN PROGRESS | `docs/orcel/implementation-readiness/ROADMAP.md`; XP-01 PR #345, XP-02 PR #346; parallel with SG-000096/108 approved (FD-02) |

## Next executable grain

1. F3 / SG-000108: rebase and finish #336 (slice 3b-i), then slice 3b-ii and the remaining product-caller slices to canonical closeout.
2. F0 next slice: authenticated read-only app API in `orceld` (status/events/tasks). The proposed revision specifies it cross-platform from the start (backlog CR-01: named pipe with DACL on Windows, Unix socket with peer credentials on macOS/Linux); memory investigation (#288).
3. F2: first local report task through the kernel with create-only approval and an independent checker.
4. Cross-platform foundation (adopted): XP-01 (#345) → XP-02 (#346) → XP-04 → XP-03 (`docs/orcel/implementation-readiness/OPUS_HANDOFF.md` section 5).

## Review pathway

Alibaba OpenCodeReview runs in **delegation mode** (founder decision, 2026-10-10) until a working OCR-managed provider is available: `ocr delegate preview` + `ocr delegate rule` per exact range, fresh-context reviewers, re-review of every head delta, evidence posted on each PR. OCR-managed runs on the current host are UNPROVEN. Jev runs in CI (hunk coverage) and locally (bounded judgments); PStack review and close-out judges run before merge.

## Known gates outside engineering

- Founder: production release decision, signing/distribution, hosted AI infrastructure budget, written model and Firecrawl rights records.
- External: real hosted inference, second and third Windows machines for multi-device journeys.
