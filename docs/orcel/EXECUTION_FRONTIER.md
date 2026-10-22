# Orcel execution frontier

Status: EXECUTION FRONTIER (a working summary that mirrors grain state; it does not set it — canonical grain state lives in `.specgrain/` and `docs/canonical/`). Update this file whenever a grain merges, blocks, or the next grain changes. It serves implementation; it grants no authority. Planning detail lives in the adopted documents listed below; evidence lives in PRs, issues and CI runs.

Last macOS hardware-lane verification: 2026-10-22 · main `55d445af0b2b` (PR #425), with successful exact-merge CI [run 39780007087](https://github.com/TheHalfMoon/Orcel/actions/runs/39780007087). The broader roadmap ledger below was last reconciled at main `c2ee2cb51b7e`; it is not a current inventory of Opus's browser and shell PRs. Earlier: `4a6dc9e371a1` (2026-10-20), `8225d9f79bea` (2026-10-19), `0157688` (2026-10-18).

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
| Cross-platform track (X0–X6) | ADOPTED; IN PROGRESS (grain SG-000109 not yet activated as a spec). **The XP backlog is done through XP-12; nothing here is release-qualified.** | Merged: plan #344 (`e11f629`), XP-02 macOS CI #346, BM-01 report schema #347, XP-01 private state root #345, XP-04 host protocol /2 #348, macOS test-flake fix #349, XP-05 vendored Cua Driver in `apps/orcel-native-host` #354, XP-15 macOS/Linux clipboard #353, XP-01B remaining state stores on the private root #357, XP-03 identity primitives #360, XP-09 macOS approvals #361 (real-hardware qualification #365 covers XP-09 approvals only; the macOS product is not qualified), XP-17 Linux packaging #363, XP-10 Linux approvals #364, orcel-policy macOS flake fix #368 (#366), CR-01 read-only app API #370, XP-13 contained tier #371, XP-13b #378 and #380 (XP-13 complete), XP-06 native-host observation on macOS and Linux #372, CR-02 Control Room client #377, XP-19 per-OS secret storage #379, then (since #385) XP-08 conformance fixtures #386, XP-07 exact-window capture #387, WI-05 confined document parser #388, XP-11 semantic actions #392, WI-06 search adapters #394, XP-12 bounded raw input #402. Follow-up fixes merged: app API #393 (#381, #375) #410 (#400) #414 (#398), WI-05 #396 (#391) #406 (#399) #411 (#389), ChatGPT tunnel core-only #397 (#395), MCP SDK advisories #403, temp names and askpass directory #405 (#350, #351), native host #407 (#404, #401) #408 (#383, #390) #409 (#355), paths, identity and confinement #412 (#384, #358 items 1-4, #367), secrets #413 (#382, #369 item 3), Linux helper hardening #415 (#373, #369), clipboard X11 #416 (#356), CI timeout #418. **Hardware evidence update (#425):** real-Mac XP-06 observation and XP-11 semantic-action suites passed through both native host and kernel adapter; XP-09 approval evidence remains separately recorded. **Not qualified:** macOS XP-07 screenshot delivery, XP-12 raw input delivery (separate direct-capture consent not granted), and Linux XP-10 GNOME/KDE desktop approvals. Report-mode safety refusals for XP-07/12 passed; these are NOT delivery results. No overall macOS or Linux release qualification. **Still blocked:** CR-03 on FD-03 (Tauri); XP-16 on FD-05 (paid Mac runner and Apple Developer ID); BR-*, WI-01..04, RJ-*, SX-* and XP-14 on SG-000108 closeout. Founder decisions still open: FD-03, FD-05, FD-07, FD-08. Open follow-ups: #417 and #419 (nits, PR #420), #358 item 5 (test flake, PR #421), #374 (browser-worker flake, SG-000108 territory) |

## macOS hardware qualification (independent lane, 2026-10-22)

- **Merged evidence:** PR #425 at main `55d445af0b2b`; post-merge CI passed (run 39780007087); exact native-host/kernel XP-06 observation and XP-11 semantic-action tests passed on real macOS 26.6.2 Apple Silicon. XP-07 and XP-12 report-mode refusal checks passed, not delivery checks.
- **Outstanding macOS consent:** the real native host reports `accessibility=true`, `screen_recording=true`, but `direct_capture_consent=false`. This separate OS-recorded grant cannot be inferred from Screen Recording and must not be spoofed or requested noninteractively. XP-07/XP-12 delivery stays unqualified until legitimate user-approved consent and successful controlled-window tests.
- **Reproducible non-prompting preflight:** `python3 scripts/macos_native_capability_preflight.py --host /absolute/path/to/orcel-native-host` uses only the protocol /2 `hello` frame. `--require XP-07` or `--require XP-12` exits 3 when not ready. It performs **no screen reads or input**; an eligible result is not evidence of capability delivery.
- **External platform gate:** XP-10 still needs actual interactive GNOME and KDE approval/refusal sessions. XP-16 signing/packaging remains a separate founder decision. More details: `docs/orcel/qualification/2026-10-22-mac-hardware/README.md`.

## Next executable grain

1. F3 / SG-000108: rebase and finish #336 (slice 3b-i), then slice 3b-ii and the remaining product-caller slices to canonical closeout.
2. F0 next slice: authenticated read-only app API in `orceld` (status/events/tasks). The adopted revision specifies it cross-platform from the start (backlog CR-01: named pipe with DACL on Windows, Unix socket with peer credentials on macOS/Linux); memory investigation (#288).
3. F2: first local report task through the kernel with create-only approval and an independent checker.
4. Cross-platform (adopted): the XP backlog is done through XP-12, with WI-05, WI-06, CR-01, CR-02 and XP-19 (see the track row). Next: macOS direct-capture consent and XP-07/XP-12 delivered capture/input checks, plus real GNOME/KDE XP-10 approval checks; XP-06/XP-11 Mac hardware tests passed under #425 and must not be repeated without a material change; FD-05 gates macOS signing and packaging (XP-16) and FD-03 gates CR-03. BR-*, WI-01..04, RJ-*, SX-* and XP-14 wait on SG-000108 closeout (`docs/orcel/implementation-readiness/OPUS_HANDOFF.md` section 5).

## Review pathway

Alibaba OpenCodeReview runs in **delegation mode** (founder decision, 2026-10-10) until a working OCR-managed provider is available: `ocr delegate preview` + `ocr delegate rule` per exact range, fresh-context reviewers, re-review of every head delta, evidence posted on each PR. OCR-managed runs on the current host are UNPROVEN. Jev runs in CI (hunk coverage) and locally (bounded judgments); PStack review and close-out judges run before merge.

## Known gates outside engineering

- Founder: production release decision, signing/distribution, hosted AI infrastructure budget, written model and Firecrawl rights records.
- External: real hosted inference, second and third Windows machines for multi-device journeys.
