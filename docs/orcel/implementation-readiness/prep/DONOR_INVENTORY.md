# Unified-platform donor inventory (Wave 1, UP-001 prep)

**Status: INVENTORY ONLY.** This document imports, copies or sublicenses no donor code. It records what
each donor repository contains at an exact commit, what licence terms its files carry, and how each
capability could reach Orcel. It makes no legal decision. The machine-readable companion is
[`capability_inventory.json`](capability_inventory.json) (96 records, one per feature).

- **Orcel base:** `origin/main` at `4dd5cfc93b524e3e99eed9097c3e81917676bee8`. Orcel is Apache-2.0.
- **Planning input:** founder PR #785, `docs/orcel/UNIFIED_PLATFORM_BLUEPRINT_2026-11-16.md` and
  `docs/orcel/UNIFIED_SOURCE_PINS_2026-11-16.json`.
- **Method:** no clones. The commit SHA comes from `git ls-remote <repo> HEAD` on 2026-11-16. Repository
  metadata, languages, the full recursive tree and the licence, notice and manifest files come from the
  GitHub API at that SHA. The Orcel side comes from a read-only sweep of `origin/main`. Every Orcel test
  named below was found in the tree at that commit.
- **What was not done:** donor tests were not run, and no donor binary was executed. Per-file licence
  headers inside the donors were not read one by one. Only the root, directory-level and manifest
  licences were read.

## 1. Pins and licences

| Donor | HEAD SHA (2026-11-16) | Licence at that SHA | Language / size | Upstream tests |
| --- | --- | --- | --- | --- |
| h4ckf0r0day/obscura | `0d9a2f764ffdb097269da048002c593865e83a9e` | Apache-2.0. Vendored: taffy MIT, cosmic-text MIT/Apache-2.0, wreq-util Apache-2.0. Noto Color Emoji font OFL-1.1 | Rust (V8 embedded), 526 files, 26.8 MB | 12 integration files in `crates/obscura/tests`, plus MCP, CDP and render tests (about 114 test paths) |
| browser-use/browser-use | `4b5b1b0aa0ab45a1d6a2a31984d37d3e748c0134` | MIT, Copyright (c) 2024 Gregor Zunic | Python, 144 files | `tests/ci` (24) |
| vercel-labs/agent-browser | `53384771fbafc261ba67608ac806dd5aa70b84f0` | Apache-2.0. `cli/src/native/a11y/axe.min.js` is **MPL-2.0** (axe-core) | Rust CLI plus TypeScript dashboard, 574 files | `cli/tests` (23), `parity_tests.rs`, `e2e_tests.rs`, `evals/` |
| vercel-labs/remote-agent-browser | `8770ea28f3ab0e8822e104e12e0efb65339d235b` | **No LICENSE file.** `package.json` declares MIT; GitHub detects no licence | TypeScript, 40 files | `tests/` (7: unit plus integration) |
| apify/crawlee | `7bec9ad5631f8e529ae067494f6841dba3c12683` (branch `master`) | Apache-2.0 (`LICENSE.md`) | TypeScript monorepo, 3,024 files | `test/` (about 445 paths, including e2e) |
| D4Vinci/Scrapling | `bb223f2f5fc8f743772751a5ce283ef7851ca6be` | BSD-3-Clause, Copyright (c) 2024 Karim Shoair | Python, 699 files | `tests/` (about 104) |
| firecrawl/firecrawl | `42f4d669954649ce33466a2a50e8215c7f1f4d1c` | **AGPL-3.0** at the root. MIT for the SDKs (see section 3) | TypeScript, Rust and many SDK languages, 2,224 files | about 660 test paths |
| wangzan101/Mika | `e956f5529ad4cfd7881aafaa630318097949f56a` | Apache-2.0 plus NOTICE. Bundles **GPL-2.0+** PRoot, **LGPL-3.0+** talloc and a mixed-licence Alpine rootfs | Kotlin (Android), 3,318 files | about 968 test paths, plus `eval/tasks` (128) |
| fleetdm/fleet | `99e64e6bbee9e7a9b5334fea2527303992f747f7` | MIT outside `ee/`. **`ee/` is under the Fleet EE licence.** `docs/` is CC BY-SA 4.0 | Go plus TypeScript, 20,974 files | about 1,286 `_test.go` files |
| phone-harness/phone-harness | `4bebff105af853215fb74c958c2c5e78bc275be2` | MIT, Copyright (c) 2026 shawn pana | Python, 80 files | `tests/` (19) |
| "Vercel agent-use" | not identified | unknown | n/a | n/a |
| UU Remote (NetEase) | no official source | proprietary | n/a | n/a |

**Drift from the PR #785 pins.** Nine donors still match the pinned SHA. The tenth, **Firecrawl**, has
moved from `25a92fc3175babbd75fd50a0e8122aaa44b068ad` to `42f4d669954649ce33466a2a50e8215c7f1f4d1c`;
the inventory uses the newer SHA. Orcel's existing Firecrawl ports were taken at `f84845c8`.
`remote-agent-browser`, pinned as `verify`, has no licence file. That state is recorded rather than
resolved.

**Founder attestations, kept separate from upstream terms.**

- `docs/orcel/grants/2026-10-13-founder-source-authorization.md` and
  `docs/orcel/grants/2026-10-18-founder-attestation.md` record the founder's statement that copying,
  modification, commercial distribution and relicensing of grantor-owned code are authorized. This
  covers Firecrawl (FD-06: redistribution inside Apache-2.0 Orcel), Browser Use, Cua, Skyvern and the
  other sources previously recorded in Orcel.
- No copyright-holder-signed grant is in the repository. These are founder statements, not upstream
  licence terms.
- Obscura, agent-browser, remote-agent-browser, Crawlee, Scrapling, Mika, Fleet and phone-harness are
  **not** named in either grant document. PR #785 records them as
  `founder_attestation_only_scope_not_verified`.
- By the attestation's own words, a grant reaches only code its grantor owns. Third-party files,
  dependencies, fonts and models keep their licences.

## 2. Legal and policy blockers (precise, undecided)

1. **Firecrawl AGPL-3.0 (root).**
   - The root licence covers `apps/api` (its `package.json` says `"license": "ISC"`, which conflicts
     with the root LICENSE), `apps/local`, `apps/playwright-service-ts` (`ISC` in its manifest),
     `apps/test-site`, `apps/test-suite`, `apps/go-html-to-md-service` and `apps/nuq-postgres`.
   - Under the upstream terms alone, distributing AGPL-derived code inside Apache-2.0 Orcel would put
     the combined work under AGPL. Section 13 would also apply: offering the source to network users
     of a modified version.
   - Orcel already ships Firecrawl-derived code (`crawl_scope.rs`, `map_rank.rs`, `change_tracking.rs`,
     `apps/orcel-doc-parser`). For that code it relies on the FD-06 founder attestation, with notice
     `docs/orcel/notices/firecrawl-AGPL-3.0.txt`.
   - **Open item:** a durable, copyright-holder-signed grant, or a record of its scope. The grant
     reaches only Firecrawl-owned files. `apps/api/native` depends on third-party crates (`lopdf` is
     already vendored under MIT), and their licences stand.
2. **Firecrawl SDK licence gaps.**
   - js, python, elixir and ruby carry an MIT `LICENSE` file. rust, java and php declare MIT in their
     manifests.
   - `apps/go-sdk` and `apps/dot-net-sdk` have no LICENSE file and no licence field, so they default to
     the root AGPL-3.0 until upstream clarifies. The README says "SDKs ... MIT".
3. **Firecrawl cloud-only features.** fire-engine, Alexandria data providers, `/agent`, `/monitor`,
   hosted browser sessions and the hosted map index are not in the source. In self-hosted Firecrawl
   they answer `CLOUD_ONLY` or are forwarded to Firecrawl cloud. Search in Firecrawl Local is
   cloud-forwarded too (`apps/local/README.md`). Parity with these features is unavailable at any
   licence.
4. **Fleet `ee/` commercial licence.**
   - The Fleet EE licence allows production use only with a paid Fleet subscription. It forbids
     copying, distribution and sublicensing, except copying and modifying for development and testing.
   - It covers software installers, Fleet-maintained apps, VPP, patch deadlines, MDM profiles, setup
     experience, CIS benchmarks, host identity/TPM, SCEP proxy, `fleetd-chrome` and the vulnerability
     dashboard.
   - Under upstream terms this is outside Orcel's rights. Any founder grant would need Fleet Device
     Management Inc. as signatory.
   - MIT parts are reusable: `server/`, `orbit/`, `cmd/`, `pkg/` and client-side JS. Third-party MIT
     code (`server/mdm/nanomdm`, `nanodep`, `scep`) keeps its own copyright lines.
   - `docs/` is CC BY-SA 4.0 (share-alike).
5. **remote-agent-browser has no licence text.**
   - The manifest declares MIT, but the repository has no LICENSE file and no copyright notice. GitHub
     treats it as unlicensed.
   - Its only runtime dependency is `@vercel/sandbox`, a paid cloud service, which conflicts with the
     zero-cost baseline.
   - Treat it as a contract reference only until the licence is confirmed.
6. **agent-browser bundles axe-core under MPL-2.0.** This is file-level copyleft. The file must stay
   unmodified, or its modifications must be published. The MPL notice travels with it.
7. **Mika bundles copyleft binaries.**
   - PRoot 5.4.0 (GPL-2.0-or-later) carries four Mika patches. talloc 2.4.3 (LGPL-3.0-or-later) is
     statically linked into `libproot.so`. The Alpine rootfs mixes GPL, LGPL and MPL packages.
   - Mika runs these as subprocesses and ships corresponding source separately.
   - Redistributing that sandbox would carry the same source-offer duties. On desktop it is unneeded,
     because `apps/orcel-contain` already sandboxes on three OSes.
   - Mika's calls (Volcengine) and WeChat binding depend on third-party cloud services.
8. **Stealth and anti-detection features (policy, not licence).** Obscura `--stealth` (fingerprint
   randomisation, BoringSSL TLS impersonation), Scrapling stealth and `curl_cffi` fetchers, and
   Crawlee fingerprints and impersonating clients are bot-detection evasion capabilities. Orcel has no
   adopted policy that permits them, so they are marked BLOCKED pending a founder decision. Plain
   rendering, robots obedience and tracker blocking can be separated from them.
9. **UU Remote is proprietary.**
   - No official source repository exists.
   - The only NetEase-named GitHub organisation, `netease-uuyc` (not GitHub-verified, created
     2026-09-09), publishes one MIT repository. `uuremote-integration-guide` at `181dee45` is a URL
     scheme for launching the proprietary UU client from iOS and Android apps.
   - Community projects are unofficial reverse-engineered hosts or Wine wrappers:
     `VallierDev/uu-remote-linux` (GPL-3.0), `GaryOAO/UUWay` (AGPL-3.0), `Alex-Yori/linux-uuremote`
     (MIT, "protocol reverse-engineered") and others.
   - Importing them carries copyright, terms-of-service and anti-circumvention risk. Remote
     screen/control must be implemented independently.
10. **"Vercel agent-use" is unidentified.** No repository can be admitted until the founder names it
    (section 4).
11. **Donor telemetry and second authority channels.** browser-use and phone-harness ship telemetry.
    Obscura, agent-browser, Scrapling, Mika and Fleet ship their own MCP servers or HTTP listeners.
    Obscura's HTTP MCP has only an optional token. The blueprint forbids any of these from becoming a
    second authorization channel, and no telemetry is imported.

## 3. Per-donor module maps and classification

Classification vocabulary:

- *directly reusable*
- *reusable with adaptation*
- *best via adapter* (separate process or service behind an Orcel contract)
- *already in Orcel*
- *needs new implementation*
- *unavailable or outside rights*

Every row is a record in the JSON.

### 3.1 Obscura (preferred engine candidate)

- **Module map:**
  - `crates/obscura-browser` (page, lifecycle, accessibility, PDF, profiles)
  - `obscura-js` (V8)
  - `obscura-dom` (html5ever tree, selectors)
  - `obscura-net` (HTTP client, cookies, robots, interceptor, blocklist, `wreq` stealth client)
  - `obscura-cdp` (CDP domains Target, Page, Runtime, DOM, DOMSnapshot, Network, Fetch, IO, Storage,
    Input, Emulation, Accessibility, and the custom `LP.getMarkdown`)
  - `obscura-render` (taffy layout, cosmic-text, paint → screenshot and screencast)
  - `obscura-mcp` (38 `browser_*` tools, stdio or HTTP)
  - `obscura-cli` (`fetch`, `scrape`, `serve` with worker pool and recycling)
  - `obscura-ssrf`
- **Platforms:** release binaries for Linux x64/arm64, macOS arm64/x64 and Windows x64. The stealth
  build compiles BoringSSL.
- **Classification:**
  - Best via adapter: the engine, CDP, screenshot, PDF, accessibility snapshot and interception. Run a
    pinned release as a contained sidecar and drive it through the existing playwright-core worker
    (`connectOverCDP`) behind a new engine contract (UP-002/UP-004).
  - Reusable with adaptation: DOM-to-Markdown, as a comparison oracle for the existing extractor; and
    the worker pool.
  - Already in Orcel: robots (`crates/orcel-browser-host/src/robots.rs`) and the SSRF guard
    (`crates/orcel-provider-network`).
  - Needs new implementation: the MCP surface. Map it onto Orcel's `browser_structured` tools and
    never expose Obscura's listener.
  - BLOCKED: stealth (policy).
- **Gaps an adapter must close in Orcel:** no page screenshot tool, no page-to-PDF and no multi-tab
  contract exist today.

### 3.2 Browser Use

- **Module map at `4b5b1b0`:** `browser_use/agent` (loop, prompt, judge, service), `browser/`
  (browser, local), `mcp/`, `tools.py`, `ax.py`, `skills/`, `telemetry/`, `harness_cloud.py`.
  - The CDP and browser layer has moved into the `browser-harness` dependency (MIT, separate
    repository, pinned `==0.1.13`). That repository needs its own pin before any further port.
- **Already in Orcel:** the extraction pipeline, ported at `c75e8476` (PR #312), lives in
  `apps/orcel-browser-worker/src/extract`.
  - Test: `extract.test.ts`, "headings, paragraphs, emphasis, lists, quotes, code and rules become
    Markdown".
  - Notice: `docs/orcel/notices/browser-use-MIT.txt`.
- **Reusable with adaptation:** action semantics and judge ideas.
- **Rejected as code** by the existing registry: the agent loop, LLM layer, cloud and telemetry.

### 3.3 agent-browser (Vercel)

- **Module map (`cli/src/native`):**
  - `snapshot.rs` and `element.rs` (accessibility refs)
  - `actions.rs`, `interaction.rs`, `pointer.rs`
  - `screenshot.rs`, `recording.rs`, `diff.rs`
  - `downloads.rs`
  - `cookies.rs`, `storage.rs`, `state.rs`, `auth.rs` (vault)
  - `network.rs`, `tab_binding.rs`, `policy.rs`, `providers.rs` (Browserbase, Browserless, Browser
    Use, Kernel, AgentCore)
  - `webdriver` (iOS Simulator), `webmcp.rs`, `daemon.rs`, `stream`
  - `parity_tests.rs`, `e2e_tests.rs`
  - Outside `native`: `cli/src/mcp.rs`, and `evals/` plus `benchmarks/`.
- **Engines:** Chrome for Testing by default. Lightpanda and Obscura are selectable with `--engine`.
  Native binaries ship for macOS, Linux (glibc and musl) and Windows x64.
- **Reusable with adaptation:** this is the closest architectural match to Orcel (Rust, CDP, refs).
  Candidates are snapshot refs, actions, capture, tabs and frames, network and engine selection.
  Sessions and the auth vault need an Orcel policy change, because profiles are ephemeral today.
- **Already in Orcel:** approval-bound downloads (`transfers.rs`) and action policy (`orcel-policy`).
- **Directly reusable:** the parity, e2e and eval corpus.
- **Licence note:** axe-core is MPL-2.0.

### 3.4 remote-agent-browser (Vercel)

- **Module map:** `src/browser.ts`, `create.ts`, `vercel.ts`, `types.ts` and `index.ts`, plus
  `tests/`. It runs agent-browser inside a Vercel Sandbox.
- **Classification:** reference contract only, covering session create, command, close, named
  resumable runtime, heartbeat and sandboxed transfers. Sandbox provisioning is unavailable (cloud).
  The licence is unconfirmed.

### 3.5 Crawlee

- **Module map:**
  - `packages/core/src/storages`: request queue, dedup cache, request list, dataset, key-value store
  - `packages/basic-crawler/src/internals`: autoscaling (CPU, memory and event-loop signals), session
    pool, throttling request manager, enqueue-links, request timeout, sitemap loader, router
  - `packages/utils/src/internals`: robots, sitemap, microdata, OpenGraph, social
  - `packages/fs-storage`, `browser-pool`, and the http, cheerio, playwright and puppeteer crawlers
  - `impit-client` and `got-scraping-client`
- **Reusable with adaptation:** port the logic into Rust rather than embedding Node. Candidates are the
  durable queue, autoscaling, retry and session handling, the rate limit (missing in Orcel today),
  storage, adaptive HTTP-versus-browser crawling and the extractors.
- **Already in Orcel:** enqueue scope (`crawl_scope.rs`) and robots and sitemaps (`robots.rs`).
- **BLOCKED:** fingerprints and impersonating clients (policy).

### 3.6 Scrapling

- **Module map:**
  - `scrapling/parser.py` and `core/storage.py` (adaptive relocation), `core/translator.py`
  - `spiders/` (scheduler, checkpoint, throttle, robots, cache, session)
  - `engines/static.py` (`curl_cffi`), `fetchers/stealth_chrome.py`, `engines/_browsers/_stealth.py`
  - `toolbelt/` (fingerprints, proxy rotation, ad domains)
  - `cli.py` MCP command
- **Best via adapter:** adaptive selectors, behind the extractor in an `orcel-contain` sidecar, or
  ported.
- **Reusable with adaptation:** spider checkpoint and resume ideas.
- **Directly reusable:** the ad-domain list.
- **BLOCKED:** static TLS impersonation and the stealth browser (policy).

### 3.7 Firecrawl

- **Module map:**
  - `apps/api/src/controllers/v2`: scrape, crawl (status, cancel, errors, WebSocket), map, search,
    batch-scrape, extract, parse, agent, monitor, browser and more
  - `apps/api/src/scraper/scrapeURL/engines`: fetch, playwright, pdf, document, fire-engine, index,
    wikipedia
  - `apps/api/native/src`: `crawler.rs`, `html.rs`, `pdf.rs`, `document.rs`, `xml.rs`, `engpicker.rs`
  - `apps/local` (Rust Firecrawl Local: fetch, browser, crawl, documents, netguard, serve)
  - `apps/go-html-to-md-service`, `apps/playwright-service-ts`, `apps/nuq-postgres`, `apps/redis`
  - nine SDKs, `apps/test-site`, `apps/test-suite`
- **Already in Orcel (TESTED, library-level, not exposed via MCP or API):**

  | Capability | Orcel location | Test |
  | --- | --- | --- |
  | Crawl and scope | `crates/orcel-browser-host/src/crawl.rs`, `crawl_scope.rs` | `a_crawl_stays_on_its_origin_and_directory_and_reads_each_page_once`, `wi01_regex_patterns_and_canonical_urls_through_a_crawl` |
  | Map ranking | `map_rank.rs` | `wi02_the_most_relevant_urls_come_first` |
  | Change tracking | `change_tracking.rs` | `wi04_a_changed_page_returns_its_diff` |
  | Documents (FD-06) | `apps/orcel-doc-parser` | `pdf_tests.rs::nesting_is_bounded`; `document_parse_tests.rs::wi05_a_changed_or_moved_download_is_refused_before_any_approval` |

- **Exposed through MCP:** search (`crates/orceld/src/search.rs`, BYOK providers, off by default),
  as `web_search`. Test: `wi06_search.rs::wi06_real_orceld_search_is_off_and_never_leaks_a_key`.
- **NOT STARTED:**
  - a Firecrawl-compatible scrape, crawl, map and batch API
  - an async job queue and status
  - a crawl rate limit
  - extract (needs a model provider)
- **Directly reusable:** the MIT SDKs as contract clients for a parity harness.
- **Unavailable:** cloud-only features.
- **Registry correction:** `DONOR_REGISTRY.md` and `donor_registry.json` still say
  `REFERENCE_ONLY_SO_FAR` for Firecrawl. The code now contains Firecrawl ports, so this correction is
  owed in a follow-up.

### 3.8 Mika

- **Module map:** the `core` Kotlin module, in 53 packages including `agent`, `run`, `verify`, `adb`,
  `shell`, `uistate`, `action`, `observation`, `vision`, `mcp` (`McpServer`, `McpDeviceTools`,
  `McpTaskTools`, `McpUsb`), `trigger`, `proactive`, `memory`, `remote`, `calls` and `wechat`.
  - The `app` module adds an accessibility service, shell, terminal, sandbox, browser and voice.
  - Tooling: `tools/relay` (Go, Apache-2.0 plus NOTICE), `tools/sandbox` (PRoot build) and
    `tools/mika` (Python skill).
- **Classification:**
  - Best via adapter: an Android companion paired to Orcel. Its agent, UI control and phone MCP all
    reach Orcel through the Orcel authority.
  - Reusable with adaptation: ADB and shell control, schedules, and relay ideas.
  - Directly reusable: the eval corpus.
  - BLOCKED: the sandbox (copyleft binaries, and the need is already covered) and calls/WeChat (cloud
    services).

### 3.9 Fleet

- **MIT module map (relevant parts):**
  - `server/service` (`hosts.go`, `global_policies.go`, `team_policies.go`, `live_queries.go`,
    `scripts.go`, `software.go`, `vulnerabilities.go`)
  - `server/datastore`, `server/live_query`, `server/vulnerabilities`
  - `server/fleetmcp` and `cmd/fleet-mcp` (MCP: hosts, inventory, policies, vetted queries)
  - `orbit/` (agent: osquery launcher, TUF update, OS services, Windows/macOS/Linux)
  - `schema/tables` (osquery tables)
- **EE module map:** `ee/server/service` covers software installers, maintained apps, VPP, MDM,
  profiles, setup experience, SCIM, certificate authorities and BitLocker PIN. Also EE: `ee/cis`,
  `ee/orbit` (host identity, TPM, SCEP), `ee/fleetd-chrome`, `ee/maintained-apps` and
  `ee/vulnerability-dashboard`.
- **Classification:**
  - Best via adapter: the MIT parts, as an optional Orcel fleet service. They are never mandatory and
    never enroll devices stealthily.
  - Teams-scoped and script features may be premium-gated in MIT files (`license.IsPremium`), so they
    must be verified per call site.
  - BLOCKED: EE features.
- **Orcel today:** nothing. `devices.list` answers `METHOD_UNAVAILABLE`, and
  `docs/orcel/MULTI_DEVICE_ARCHITECTURE.md` is planning only.

### 3.10 phone-harness

- **Module map (`src/phone_harness`):**
  - `android.py` (adb), `transport.py`
  - `mirror.py` and `ios.py` (macOS iPhone Mirroring through Quartz and ApplicationServices)
  - `ocr.py` (Apple Vision)
  - `helpers.py` and `run.py` (device-independent API)
  - `transfer.py`, `cloud.py`, `remote.py`, `telemetry.py`
  - `integrations/openclaw` (approval plugin)
  - Tests include `test_backend_contract.py`, `test_android.py` and `test_ios_session.py`.
- **Classification:**
  - Reusable with adaptation: Android ADB. Port it into a new `orcel-provider-mobile`, which works
    on all three desktop OSes.
  - Best via adapter: iPhone Mirroring and Vision OCR (macOS only, through `apps/orcel-native-host`).
  - Directly reusable: the backend contract, as the shape of the Orcel Mobile API contract tests.
  - BLOCKED: the cloud and telemetry.
- **Orcel today:** no mobile code at all.

## 4. "Vercel agent-use" search results

| Query | Result |
| --- | --- |
| `gh search repos agent-use --owner vercel-labs` | Fuzzy matches only: `vercel-labs/agent-desktop` (Apache-2.0, "Computer use CLI for AI agents"), `vercel-labs/ai-sdk-computer-use` (no licence), `vercel-labs/design-systems-to-agent-skills` (MIT), `vercel-labs/tau-agent` (other) |
| `gh search repos agent-use --owner vercel` | No results |
| `gh search repos "agent use"` / `agentuse` under both owners | No results |
| `repos/vercel-labs/agent-use`, `repos/vercel/agent-use` | 404 |

- **Most plausible candidate:** `vercel-labs/agent-desktop` at
  `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad`, under Apache-2.0.
  - It drives macOS AX, Windows UI Automation and Linux AT-SPI through one `PlatformAdapter`, and has
    MCP over stdio.
  - It has e2e suites for Windows and Linux.
  - Its homepage is `agent-browser.dev/desktop`, a sibling of agent-browser.
- **Not substituted.** It is recorded as `agent_desktop.candidate`, BLOCKED until the founder confirms
  the name. If confirmed, it is a strong donor for Track 1, because Orcel's macOS and Linux computer
  host today wraps vendored Cua driver crates.
- `vercel-labs/ai-sdk-computer-use` is a small Next.js demo with no licence.

## 5. Recommended first implementation packets

The ranking weighs reuse available, licence clarity, fit with Orcel's architecture, and testability.

1. **Dual-engine browser contract with an Obscura sidecar adapter (UP-002 plus UP-004).**
   - Reuse: Obscura is Apache-2.0, and its CDP surface is designed for playwright-core. Orcel already
     drives Chromium through playwright-core in `apps/orcel-browser-worker`, so `connectOverCDP` to a
     contained, loopback, token-bound Obscura process reuses the existing worker and snapshot refs.
   - Licence: clear, without adopting stealth.
   - Testable: run the same task corpus on both engines with explicit difference reports.
   - Hard prerequisite: the live browser must leave the Windows-only dev gate.
2. **Firecrawl-compatible web API over the existing ports (UP-005 first slice).**
   - Orcel already has tested crawl, scope, map ranking, change tracking, documents and search at the
     library level. The gap is exposure: MCP `web_scrape`, `web_crawl` and `web_map` tools, plus a
     versioned local API.
   - Tests: the MIT JS and Python SDKs act as black-box contract clients.
   - Licence: needs no new AGPL import. The existing FD-06 status is unchanged.
3. **Durable local job queue and crawl politeness (orcel-jobs).**
   - Port Crawlee's request queue, dedup, retry and backoff, throttling and autoscaling (all Apache-2.0)
     into an embedded Rust queue with no server database. Scrapling's checkpoint and resume ideas
     (BSD-3) can join them.
   - It unblocks async crawl and batch, the missing rate limit and the scheduler that Mika-style
     schedules need.
   - Testable: deterministic unit tests plus the Crawlee test vectors as an oracle.
4. **Orcel Mobile API with a local Android ADB backend (UP-007 first slice).**
   - Reuse: phone-harness is MIT, small (80 files) and has an explicit backend contract test. Its
     Android path is plain adb, so it runs on Windows, macOS and Linux.
   - Fit: a new `orcel-provider-mobile` behind Orcel policy, approval and audit, with `mobile_*` MCP
     tools.
   - Testable: contract tests with a fake adb, plus a real device-owner journey.
   - Follow-ups: iPhone Mirroring (macOS) and the Mika companion.
5. **agent-browser parity port: snapshot refs, extra actions and capture.**
   - agent-browser is Rust and Apache-2.0, with `parity_tests.rs`, `e2e_tests.rs` and an eval corpus.
   - It closes concrete Orcel gaps: page screenshot, page-to-PDF, hover, drag, scroll, double-click,
     tabs and frames.
   - It provides the shared test corpus that packet 1 needs. Keep axe-core out, or isolated under its
     MPL notice.

**Deliberately not in the top five:**

- Fleet: needs a separate service, and the EE boundary must be policed.
- UU Remote: proprietary.
- remote-agent-browser: no licence, and depends on the cloud.
- All stealth features: need a policy decision.

## 6. Status summary (from the JSON)

- **96 records:** 13 TESTED (existing Orcel capabilities, each citing a test), 64 NOT STARTED and
  19 BLOCKED. None is IMPORTED, INTEGRATED or RELEASED in the sense of this inventory.
- **No browser capability is released.** The live browser compiles only in Windows
  `live-browser-test` and `live-browser-dev` builds (`crates/orcel-browser-host/src/exposure.rs`).
- **The macOS and Linux browser modules are inert stubs.** Crawl, map, change tracking and the
  document parser are platform-independent Rust and run in CI on three OSes, but none is exposed as an
  MCP tool.
