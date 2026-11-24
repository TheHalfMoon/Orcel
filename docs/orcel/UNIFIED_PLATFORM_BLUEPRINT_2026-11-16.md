# Orcel unified platform: founder direction and integration plan

**Date:** 2026-11-16  
**Status:** PROPOSED — no implementation, authorization, compatibility, licensing exception or release is conferred by this document.  
**Founder target:** One local-first, cross-platform **Computer + Browser + Web Intelligence + Remote Access + Device Management + Agent** product with **App, MCP, CLI, SDK and API** entry points; zero mandatory founder-hosted infrastructure or paid runtime.

## Decisions requested for adoption

1. **Full capability, owner authorized.** Orcel should not impose arbitrary product limits on the scope of a user's *own* machine. Implement an **opt-in Full Control** mode, granting an identified agent/client a revocable, device-local, session-scoped authorization with clear disclosure, audit, interrupt/kill switch, and appropriate OS permission prompts. Do not conflate full functionality with unauthenticated remote control or silently bypass host OS security.
2. **Obscura-first, not Obscura-only.** Evaluate [Obscura](https://github.com/h4ckf0r0day/obscura) as the first browser engine. Keep an isolated Chromium/Playwright compatibility engine, since Obscura is an emerging implementation and feature parity is unproven. Both must implement one Orcel engine contract and the same authority boundary.
3. **Whole-feature parity is the objective, not a claim.** Audit every donor capability and implement, adapt, or compose it into Orcel. A transplanted directory alone is not an integrated feature. Maintain reproducible source pins and tests.
4. **Three desktop OSes as first-class:** Windows 10/11 x64, macOS arm64/x64 (where supported by dependencies), and Linux x64/arm64 as qualified (GNOME/KDE, X11/Wayland where available).
5. **Multiple interfaces, one runtime.** Desktop app, local/remote MCP, CLI, SDKs, and local REST/streaming API must share the same runtime, permission model and job queue. Device ownership and authorization must remain enforceable regardless of interface.
6. **Local zero-cost baseline.** No required commercial browser, cloud inference, third-party scraping API, SaaS database, payment, or founder-paid relay. Users may add their own API keys, self-host a relay, or purchase optional services. P2P connectivity and self-hosting are preferred; guaranteed free global TURN/relay bandwidth is not realistic.
7. **Copyright/permission hygiene.** Founder reports permission to reuse source. Record the grant's actual scope and copyright-holder signatures per donor/version *before* representing it as permission to relicense or strip notices. Keep copyright, NOTICE, license, patent, trademark and third-party obligations unless a documented grant explicitly modifies them. Publicly visible open source does not include proprietary hosted service components.

## Capability domains and interfaces

| Domain | Required feature families | Primary evidence of done |
| --- | --- | --- |
| Computer use | unrestricted-by-product *authorized* terminal, process, filesystem, Git, keyboard, pointer, windows, app launch, screenshots, document actions, permissions | Real desktop journeys with approved Full Control on three OSes, logs, abort/revoke |
| Browser | Obscura/Chromium engines; tabs, navigation, forms, uploads/downloads, frames, screenshots/PDF, persistent session, accessible snapshots, verified actions, multi-step agents | Same task corpus passes against both engines or differences explicitly marked |
| Web intelligence | scrape, map, crawl, search, extract, structured JSON/Markdown/HTML, PDF/docs, queues, scheduler, sessions, change tracking, retry/backoff, exports, rate/robots compliance | Firecrawl-compatible API contract suites plus crawler/extraction golden corpus |
| Remote | user-authorized peer pairing, screen/view/control, clipboard/file transfer, device presence, reconnection, streaming, interactive approval, session revocation | End-to-end over LAN and remote VPN or owner-hosted relay, no anonymous control |
| Fleet/device | inventory, packages, OS/hardware reports, software install/update, patch/compliance jobs, device groups, policies, agent rollout, reporting | Multi-device Linux/macOS/Windows test lab; no stealth enrollment |
| Mobile companion | Android ADB local on Windows/macOS/Linux; iPhone Mirroring local on supported Macs; screenshots, gestures, OCR, accessibility tree (where supported), device selection and tasks | Device-owner-connected phone with cross-platform adapter tests; iPhone Mirroring needs macOS 15+ and iOS 18+; no generic iPhone access claimed on Linux/Windows |
| Agent | planner/provider selection, local models, checkpoints, memory opt-in, retries, scheduling, task monitoring, interrupt/resume, output verification | Real tasks completed with evidence, no simulated consent |
| Distribution | GUI app, MCP stdio/Streamable HTTP, REST API, OpenAPI, CLI, JS/Python SDKs, release installers, auto update | Versioned protocols, cross-platform clean install tests, release provenance |

## Source-of-truth donor inventory

| Donor | Repo / status | Capability target | Working reuse recommendation |
| --- | --- | --- | --- |
| Obscura | https://github.com/h4ckf0r0day/obscura ; Apache-2.0 reported by upstream | Rust headless browser, V8/DOM/CDP, screenshot/PDF, local MCP | **Preferred engine plugin**, qualify per website corpus; never assume full Chrome parity |
| Browser Use | https://github.com/browser-use/browser-use ; MIT | AI browser execution, DOM, action/agent loops | Adapt interactions and agent loop where useful, avoid duplicate browser ownership |
| Vercel agent-browser (interpreted as "Vercel browser use") | https://github.com/vercel-labs/agent-browser ; Apache-2.0 | CLI/daemon, element refs, sessions, browser providers | Browser action tooling and compatibility suite; Obscura backend currently experimental upstream |
| Vercel remote-agent-browser | https://github.com/vercel-labs/remote-agent-browser ; optional reference | Remote session client/provider boundary | Reference contract only for zero-cost core; Vercel Sandbox is cloud infrastructure |
| Crawlee | https://github.com/apify/crawlee ; Apache-2.0 | Request queues, autoscaling, browser/HTTP crawling, retries, sessions | Compose/adapt crawl orchestration under Orcel API |
| Scrapling | https://github.com/D4Vinci/Scrapling ; BSD-3-Clause | Adaptive selectors, spiders, parser, structured extraction | Independent extractor/parser adapter |
| Firecrawl | https://github.com/firecrawl/firecrawl ; primarily AGPL-3.0 with MIT subtrees | **Full open-source feature parity** for scrape/map/crawl/search/extract, batch jobs, SDK/API, document handling | Maintain endpoint parity tests; track AGPL obligations and independently verify claimed additional relicensing grant; cloud-only proprietary features are not automatically in source |
| Mika | https://github.com/wangzan101/Mika ; Apache-2.0 | Android background control, agent tasks, phone MCP, schedules, local sandbox | **Android companion**, not a desktop kernel replacement |
| Phone Harness | https://github.com/phone-harness/phone-harness ; MIT (copyright © 2026 shawn pana); main `4bebff105af853215fb74c958c2c5e78bc275be2` | Android ADB local control on Windows/macOS/Linux; iPhone via macOS iPhone Mirroring + Apple Vision OCR; screenshots, text/UI discovery, gestures, keyboard, device-independent Python helpers | **Mobile device backend** to integrate alongside Mika, maintaining the MIT copyright/license notice. Hosted Phone Harness Cloud is not part of the repository's free local-device runtime and must not become a mandatory Orcel dependency |
| Fleet | https://github.com/fleetdm/fleet ; free components MIT; commercial licensing applies elsewhere | OS/device inventory, policy, MDM, software deployment | Separate Fleet extension/service, only reuse correctly granted modules |
| UU Remote | **No single verified upstream source/permission identified**; NetEase product and various unofficial Linux bridges | Remote desktop transport, video, input, NAT/relay | Study functionality and protocol; don't import a proprietary client or bridge blindly |
| "Vercel agent-use" | **Exact repository not verified** | TBD after exact source identified | No copied code or feature-complete claim until disambiguated |

Notes: URLs are identification, not pinned SHAs. Every admission packet needs a commit SHA, file/directory license matrix, third-party inventory, tests, and maintenance owner. Prior founder directions/docs remain historical evidence rather than proof of transferred IP rights.

## Target architecture

```text
  Orcel Desktop App / CLI / MCP / OpenAPI REST + Streams / JS + Python SDKs
                            |
             Authenticated Orcel Gateway + job/event API
                            |
           Owner consent + profiles + audit + revoke + policy
                            |
     +----------------------+----------------------+------------------+
     |                      |                      |                  |
  Computer Host         Browser Engine         Web Intelligence   Device/Fleet
  Win/macOS/Linux       Obscura (primary)       Crawl/Map/Scrape    Agents
  PTY/files/GUI         Chromium (fallback)     Extract/Index       Inventory
     |                      |                      |                  |
     +----------------------+----------------------+------------------+
                            |
                   Agent task runtime
                plan/execute/verify/retry
                            |
              Local persistence + optional sync
```

Keep one policy/identity authority; do not let a donor's internal MCP server, HTTP listener, browser CDP port, or administrator feature silently become a second authorization channel.

## Proposed permission modes

- **Observe:** status and limited read-only tools.
- **Workspace:** read/write/process privileges for explicit workspaces.
- **Full Control (local, opt-in):** the user may authorize OS-wide actions and shell, including home drives, installed browsers and desktop UI; show the target device/client clearly. Never silently elevate privileges or expose secrets through logs.
- **Full Control (remote, opt-in):** explicitly paired device/client, protected transport, short revocable leases, presence indicator, emergency stop and audit. Cannot silently enroll devices or spoof OS permissions.
- **Headless jobs:** delegated scopes/duration/allowed targets; high-risk exceptions and external financial transactions need explicit policy decisions.

Default mode need not block routine work with a dialog per click; enable trusted sessions with explicit scope, expiry and a running indication. High-risk actions can be previewed/reviewed without imposing arbitrary file counts, crawl-size marketing quotas or mandatory per-step prompts.

## Implementation track and proof gates

### Track 0 — Audit and clean dependency boundary
- Snapshot current `main`, identify active PRs and ownership; don't overwrite ongoing SG-000119 or macOS work.
- Pin all 10+ donor repositories, capture source licenses + license grants, inventory extracted capabilities at function/module level and compare against Orcel implementation.
- Publish machine-readable parity matrix with `existing | imported | integrated | tested | released | blocked`. Every item must cite test evidence. Locate exact Vercel agent-use and UU Remote repos before admission.

### Track 1 — Authority and cross-platform computer access
- Add opted-in Full Control sessions with authenticated local/remote capability grants; expand PTY and shell beyond hash-pinned executable allowlists **only for expressly trusted mode**.
- Build Windows, macOS, Linux providers for filesystem, process, terminal, browser attachment, GUI observe/act, clipboard and file transfer.
- Preserve revoke and OS-mediated protections. Add three-OS benchmark tasks and real user/QA approval evidence.

### Track 2 — Dual browser engine
- Introduce internal engine abstraction; integrate Obscura in isolated execution with pinned releases and checks.
- Qualify page navigation, JS, forms, frames, screenshot, PDF, uploads/downloads, session storage and performance.
- Retain Chromium fallback for unsupported features; one job API chooses engine transparently and reports which ran.

### Track 3 — Firecrawl + Crawlee + Scrapling capability parity
- Expose versioned API endpoints for scrape, crawl, map, search, extract, jobs, batches, change tracking and document processing.
- Use real queues, storage and export formats. Reuse Apache/MIT/BSD code and separately licensed Firecrawl modules under validated rights/grants.
- Integrate robots, rate limiting, retries, structured extraction, provenance and deterministic E2E datasets.
- Publish parity tests against both local Orcel and supported upstream open-source Firecrawl API contracts. Do not claim cloud-only feature parity until built.

### Track 4 — Agent UX and remote access
- Merge planning/checkpoints/schedules into Orcel app and remote MCP client flows; session replay and user interruption.
- Implement owner-mediated remote screen/control and local or owner-hosted relay; no required founder cloud, no publicly reachable unauthenticated listener.
- Add Fleet-style multi-device inventory/management to an optional service, not mandatory to single-device install.

### Track 5 — Mobile and packaging
- Integrate phone-harness's MIT-licensed local device backends alongside Mika as one Orcel Mobile API: Android ADB on Windows/macOS/Linux and iPhone via Apple's iPhone Mirroring on macOS 15+ with iOS 18+. Normalize screenshots, visual/OCR observations, touch, swipe, keyboard, app opening, device selection and supported capability detection.
- iPhone Mirroring requires the owner to pair their device and allow OS Accessibility/Screen Recording; no bypass of device lock, Face ID or camera and no unsupported cross-OS iPhone promise.
- Mika-derived Android companion when its independent runtime is qualified; no promise of desktop feature parity on phones. Keep hosted-phone providers optional and BYOK, not a dependency of local control.
- Installer/source distribution for Windows/macOS/Linux, native CI and tests, accessibility audits and security release gates.
- Publish MCP/REST/SDK contract tests and user task evidence; demo and documentation in Orcel branding.

## Acceptance criteria

- Every capability of the **in-scope accessible open-source** donor versions appears as supported, intentionally redesigned, or known-gap with an explicit closure task; all supported claims need a real test.
- The same user intent works via App, MCP and API with consistent permission decisions; missing privileges are reported precisely.
- Browser workloads run using Obscura when qualified and Chromium fallback otherwise; no false success claims.
- One owner-authorized task can use terminal + files + browser + GUI on every supported desktop OS, with stop/revoke.
- Local first-run has **no mandatory usage bill**. Only elective hosted AI, proxy, TURN relay, paid API or hardware consumes external resources.
- No release uses missing/untested binaries, unauthorized proprietary donor code, removed legal notices, or unqualified claims about macOS/Linux parity.

## Current baseline and compatibility note

Orcel already has a working Rust-based policy authority, MCP tool surfaces, Windows computer control, a development-only isolated Chromium browser, native scrape/crawl pieces and active cross-platform work. Do **not** discard this work or replace the repository root with all donor trees. The new architecture must extend the existing trusted runtime through tested adapters.

Existing `README.md` and canonical security/grain documents describe the current shipping limits. Adoption of this plan does not mean those limits have been removed; implementation and explicitly tracked canonical amendments are required before a release advertises them.

## First executable packets (small, mergeable PRs)

1. **UP-001**: exact donor pin/rights/provenance inventory + capability parity JSON (all sources).
2. **UP-002**: gateway + versioned computer/browser/web tool contract and engine selection.
3. **UP-003**: Full Control local trusted-session design and tests on three OSes; privilege changes explicitly reviewed.
4. **UP-004**: Obscura/Chromium engine adapter spike with a public test corpus and fallback report.
5. **UP-005**: Firecrawl-compatible scrape/map/crawl API parity harness and first endpoint release.
6. **UP-006**: macOS/Linux computer-use provider qualification, remote access and application test journeys.
7. **UP-007**: Mobile provider contract (phone-harness + Mika), local Android ADB on 3 desktop OSes, real iPhone-Mirroring journey on macOS, visible user consent, and parity tests via App/MCP/API.

Each packet requires implementation, reproducible tests, CI, and a factual release/readiness update. No unbounded mass donor import as a substitute for functionality.
