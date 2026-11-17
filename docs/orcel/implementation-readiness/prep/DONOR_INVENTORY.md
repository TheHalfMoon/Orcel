# Unified-platform donor inventory (Wave 1, UP-001 prep)

**Status: INVENTORY ONLY.** This document imports, copies or sublicenses no donor code. It records what
each donor repository contains at an exact commit, what licence terms its files carry, and how each
capability could reach Orcel. It makes no legal decision. The machine-readable companion is
[`capability_inventory.json`](capability_inventory.json) (96 records at first; 140 after section 8; 182 after section 8.7). The master
donor-to-feature transplant ledger for the 2026-11-17 master directive is section 8 and
[`TRANSPLANT_LEDGER.json`](TRANSPLANT_LEDGER.json).

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
- **Resolved 2026-11-17:** the founder named both `vercel-labs/agent-desktop` and `browser-use/desktop` as separate donors
  (section 8.7).

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

## 7. Founder decisions of 2026-11-17 (applied)

The founder answered FD-UP-1 to FD-UP-13 on 2026-11-17 (`UNIFIED_INTEGRATION_SPEC.md` section 11). Effects on this
inventory, also applied to `capability_inventory.json` (now 98 records: 13 TESTED, 71 NOT STARTED, 14 BLOCKED):

- **Founder attestation.** Recorded in `docs/orcel/grants/2026-11-17-founder-attestation.md`: full permission to copy and
  adapt authorized donor code (Firecrawl, Browser Use, others, including authorized private repositories). It sits
  beside, not in place of, the upstream licence terms in sections 1 and 2. Firecrawl is copied first into the isolated
  AGPL-3.0 component `apps/orcel-firecrawl`; the Apache-2.0 core keeps only its own code and the FD-06 files.
- **Stealth and fingerprinting** (blocker 8) are no longer BLOCKED: `obscura.stealth`, `crawlee.fingerprints`,
  `scrapling.static_fetcher` and `scrapling.stealth_browser` are NOT STARTED behind an opt-in policy gate (off by
  default, per-client permission, audited, no security bypass).
- **"Vercel agent-use"** (blocker 10): `vercel-labs/agent-desktop` at `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad` is
  admitted as a candidate donor (NOT STARTED, source admission pending); the search for the original continues
  (`agent_use.unresolved` stays BLOCKED). The verified Vercel projects already listed (agent-browser,
  remote-agent-browser) stay in scope on their recorded terms; `vercel-labs/ai-sdk-computer-use` (no licence) is a
  reference only.
- **Extended inventory:** Exa Browser (`exa_browser.unverified`) and TinyFish (`tinyfish.unverified`) are added as NOT
  STARTED with `SOURCE_UNVERIFIED`. The founder's separate REA effort (`D:\Orcel-REA`) has produced no outputs yet, so
  no repository, licence or SHA is recorded for either.

## 8. Master transplant ledger (2026-11-17)

The founder's master directive of 2026-11-17 names 50 sources in eight groups (A browser and web engines, B Exa, C TinyFish,
D computer use and agents, E mobile, F remote and infrastructure, G agents and screen history, H evaluation). This section
is the human-readable view of [`TRANSPLANT_LEDGER.json`](TRANSPLANT_LEDGER.json) (one record per source, plus the donors
Orcel already tracks). `capability_inventory.json` gains one record per newly inventoried source (now 140 records:
15 TESTED, 114 NOT STARTED, 11 BLOCKED, none BLOCKED for licence reasons). Nothing here imports, copies or sublicenses
donor code.

- **Method.** No clones. SHAs are `git ls-remote <repo> HEAD` on 2026-11-17. Metadata, languages, the recursive tree and
  every LICENSE, NOTICE, THIRD_PARTY and manifest file at that SHA come from the GitHub API. Wave 1 and Wave 2 clone and
  test evidence comes from the REA workspaces `D:\Orcel-REA` and `D:\Orcel-REA-W2` (read-only); every REA clone SHA
  matches the HEAD read here. Model weights, datasets and binaries are recorded separately and were not downloaded.
- **Statuses** (highest stage any part of the source has reached): NOT_ACQUIRED (API pin only), SOURCE_ACQUIRED (local
  clone at the SHA), REA_VERIFIED (donor tests run by the REA), TRANSPLANTED, INTEGRATED, TESTED (Orcel tests on main),
  RELEASE_QUALIFIED (none). Downloading never makes a source INTEGRATED.
- **Rights (founder decision, 2026-11-17).** Licence type no longer blocks copying, renaming or publishing any source
  the founder sent or any source in the repository. Each record carries `public_licence` as informational facts (kept
  for notices and provenance) and `authorization: OWNER-ASSERTED (founder, 2026-11-17)`, recorded in
  `docs/orcel/grants/2026-11-17-founder-attestation.md`. The authorization is owner-asserted and has not been independently
  verified. Every copy keeps the upstream copyright, licence and NOTICE texts and a provenance record (repository, SHA,
  paths). This supersedes the licence-based blocker classifications in sections 2 and 7; their licence facts stand.
- **One owner per feature.** Each ledger module names one Orcel owner; "(new)" owners do not exist on main yet.

### 8.1 Per-source table

| Grp | Source | Repository | Pinned SHA | Public licence (informational) | Status | Authorization | Orcel owner | P |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | Obscura | h4ckf0r0day/obscura | `0d9a2f764ffdb097269da048002c593865e83a9e` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | third_party/obscura + crates/orcel-browser-host (engine contract) | P2 |
| A | browser-use | browser-use/browser-use | `4b5b1b0aa0ab45a1d6a2a31984d37d3e748c0134` | MIT | TESTED | OWNER-ASSERTED | apps/orcel-browser-worker | P1 |
| A | Vercel browser-use/agent-desktop | vercel-labs/agent-desktop (RESOLVED 2026-11-17; browser-use/desktop is a separate record, section 8.7) | `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED AUTHORIZATION — 2026-11-17 | apps/orcel-native-host + apps/orcel-computer-host (Windows) | P0 |
| A | Crawlee | apify/crawlee | `7bec9ad5631f8e529ae067494f6841dba3c12683` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED | crates/orcel-jobs (new) | P2 |
| A | Scrapling | D4Vinci/Scrapling | `bb223f2f5fc8f743772751a5ce283ef7851ca6be` | BSD-3-Clause | NOT_ACQUIRED | OWNER-ASSERTED | crates/orcel-browser-host | P2 |
| A | Firecrawl | firecrawl/firecrawl | `98a5630a0b7ad3d58653dfe4ceb21d444dd8e2d2` | AGPL-3.0 + per-directory terms | TESTED | OWNER-ASSERTED | apps/orcel-firecrawl (new) | P1 |
| A | Fleet | fleetdm/fleet | `6070ad340095cd9dbfdef75fb6d18c9ba14c4b82` | MIT + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | crates/orcel-fleet-report (new) | P3 |
| A | Playwright | microsoft/playwright | `76b6fa645744699e982a54c48c3fc7971f4a1eef` | Apache-2.0 + per-directory terms | TESTED | OWNER-ASSERTED | apps/orcel-browser-worker | P1 |
| B | exa-labs/exa-js | exa-labs/exa-js | `ec25f4016f5a7b514fae9947ca9fd191885eabab` | MIT | REA_VERIFIED | OWNER-ASSERTED | tests/exa-compat (new) | P1 |
| B | exa-labs/exa-py | exa-labs/exa-py | `95647c10282cacc3f030440442805f337257d29f` | MIT | REA_VERIFIED | OWNER-ASSERTED | tests/exa-compat (new) | P2 |
| B | exa-labs/exa-mcp-server | exa-labs/exa-mcp-server | `93c0d5e1fecfc1ec9bf70fa9f3633962a1f2fa8a` | MIT | REA_VERIFIED | OWNER-ASSERTED | apps/orcel-mcp | P1 |
| B | exa-labs/agent-skills | exa-labs/agent-skills | `9d220cc035f17bc01ca707ffae4ea1114af081fd` | MIT | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-mcp | P3 |
| B | exa-labs/benchmarks | exa-labs/benchmarks | `a6a9590b1634fd4bf6f6ea7fd80b0084489c8e2b` | MIT | SOURCE_ACQUIRED | OWNER-ASSERTED | tests/benchmarks | P2 |
| B | exa-labs/openapi-spec | exa-labs/openapi-spec | `ebdf275f7272274a8d8592d62c80f7dd0196e6aa` | NONE | SOURCE_ACQUIRED | OWNER-ASSERTED | crates/orcel-web (new) | P2 |
| B | exa-labs/exa-deepseek-chat | exa-labs/exa-deepseek-chat | `f76f8e2f01d1bbfbea82af41011c102678156c30` | NONE | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-control-room (reference only) | P3 |
| B | adisinghstudent/exa-browser | adisinghstudent/exa-browser | `20a0cf9100879f234bd0036a3d9cae58e135265d` | NONE | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-control-room (reference only) | P3 |
| C | tinyfish-mcp-server | tinyfish-io/tinyfish-mcp-server | `7517089ca909fcdc61a083759f1729407de1a667` | MIT | REA_VERIFIED | OWNER-ASSERTED | apps/orcel-mcp | P1 |
| C | tinyfish-cookbook | tinyfish-io/tinyfish-cookbook | `b7d98b7a69dc681aca30ffb369bfd78ba059862c` | MIT | SOURCE_ACQUIRED | OWNER-ASSERTED | tests/benchmarks | P3 |
| C | tinyfish-web-agent-integrations | tinyfish-io/tinyfish-web-agent-integrations | `73402549446f4fb739a8a3b93073c0b0b1155a45` | MIT + per-directory terms | SOURCE_ACQUIRED | OWNER-ASSERTED | packages/orcel-sdk-py (new) | P3 |
| C | agentql | tinyfish-io/agentql | `d6951d214c7ed84f1a53657f801f2a8dd65c91c7` | MIT | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-browser-worker (reference only) | P3 |
| C | agentql-mcp | tinyfish-io/agentql-mcp | `8d3ea0f04af7fae065b53cdde9e5effaafdc0b6a` | MIT | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-mcp | P3 |
| C | agentql-integrations | tinyfish-io/agentql-integrations | `cbb97f094c08a191dcab015a218afd1d91ed09c1` | MIT + per-directory terms | SOURCE_ACQUIRED | OWNER-ASSERTED | packages/orcel-sdk-py (new) | P3 |
| C | bigset-oss | tinyfish-io/bigset-oss | `c6611085e2527bc0a5419db400caafa95abc751f` | AGPL-3.0 | SOURCE_ACQUIRED | OWNER-ASSERTED | none (reference only) | P3 |
| C | tf-playwright-stealth | tinyfish-io/tf-playwright-stealth | `e9adc20a53253d2043bd12b1d73f75bdb1fe5271` | MIT | REA_VERIFIED | OWNER-ASSERTED | apps/orcel-browser-worker | P2 |
| D | microsoft Hybrid-Computer-Use | microsoft/Hybrid-Computer-Use | `00eaeebe8ac0d275e46f875bdb5347e5f326faa1` | MIT + per-directory terms | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-computer-host | P0 |
| D | simular-ai Agent-S (S2/S3/S4) | simular-ai/Agent-S | `0fff0e634869dab72027435b4586e62300185d41` | Apache-2.0 + per-directory terms | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-agent | P0 |
| D | browserbase/stagehand | browserbase/stagehand | `82827a219512f0399cb159720a63f7d271d21480` | MIT + per-directory terms | SOURCE_ACQUIRED | OWNER-ASSERTED | apps/orcel-browser-worker | P0 |
| D | trycua/cua | trycua/cua | `494c3cdcc2768033bd75ba34745ce810fc55052d` | MIT + per-directory terms | TESTED | OWNER-ASSERTED | apps/orcel-native-host | P1 |
| D | microsoft/OmniParser | microsoft/OmniParser | `354021201345a96178360b28733573e27269f2de` | CC-BY-4.0 | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-vision (new) | P0 |
| D | microsoft/playwright-mcp | microsoft/playwright-mcp | `a62ea28698af6d9bc89438bcec50c63377cef957` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-mcp | P0 |
| D | OpenAdaptAI/OpenAdapt | OpenAdaptAI/OpenAdapt | `2e98be86a802b0867b9513491c5f368ba98811d0` | MIT + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-agent | P1 |
| D | OpenAdaptAI/openadapt-flow | OpenAdaptAI/openadapt-flow (archived) | `a8ef4744c47af5f17eaf946e6f5b945b97aa2457` | MIT + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-agent | P0 |
| D | anthropics/claude-quickstarts | anthropics/claude-quickstarts | `4a4224bdf0e9cfb3332167b69c90457403813625` | MIT + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-agent | P2 |
| D | alibaba/page-agent | alibaba/page-agent | `9eb6b6646500264d9034dd466a4270cb9fc1ef1e` | MIT | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-browser-worker | P1 |
| D | lightpanda-io/browser | lightpanda-io/browser | `88fb36db0a6ce4c0011c6cb31cf53e3d3b4a4fbf` | AGPL-3.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | third_party/lightpanda (new) | P2 |
| D | browseros-ai/BrowserOS | browseros-ai/BrowserOS | `81c8f6a35c0ae5a2fe8c7a1d3f7e871aa207f24c` | AGPL-3.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-mcp | P2 |
| D | Skyvern-AI/skyvern | Skyvern-AI/skyvern | `3e8571338011b8df1c9c9db8fb20856de7b9d13f` | AGPL-3.0 | NOT_ACQUIRED | OWNER-ASSERTED | none (reference only) | P3 |
| E | Genymobile/scrcpy | Genymobile/scrcpy | `a60891aea193d92e7e5c3942700eca63f9d19a5f` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED | crates/orcel-provider-mobile (new) | P1 |
| E | appium/appium | appium/appium | `51cfc7b292ab834a4155525927139a62e1e67aec` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | crates/orcel-provider-mobile (new) | P1 |
| E | X-PLUG/MobileAgent | X-PLUG/MobileAgent | `c4cd0a8f9ddedad24dd8a3daf3a56ca69343849f` | MIT + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-agent | P1 |
| E | droidrun (verify org) | droidrun/mobilerun | `e34004270a9d7b68824b94a3a5ba6698cefea69d` | MIT | NOT_ACQUIRED | OWNER-ASSERTED | crates/orcel-provider-mobile (new) | P1 |
| E | mobile-dev-inc/Maestro | mobile-dev-inc/Maestro | `0ccf5a9c5b1c48d4cb6211d9060d537e04745107` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED | tests/mobile-flows (new) | P1 |
| F | Ylianst/MeshCentral | Ylianst/MeshCentral | `03fe8529dc8ef0607ea6af78152dba8c70969464` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-relay | P2 |
| F | rustdesk/rustdesk | rustdesk/rustdesk | `3e953e886a874956d8351d6c25e340ea82dd2343` | AGPL-3.0 + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | third_party/rustdesk (new) | P2 |
| F | OpenSandbox (verify org) | opensandbox-group/OpenSandbox | `44e79a2dc3c99e26d82aa87fe13a73537d7e7812` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-sandbox (new) | P0 |
| F | CopilotKit/OpenBot | CopilotKit/OpenBot | `d88ff75ed691ab7a415c5c2d099371865c8ff61b` | MIT | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-control-room | P2 |
| G | NousResearch/hermes-agent | NousResearch/hermes-agent | `081e8d9b75b2bedae297a89232b04ef9be7b26a0` | MIT + per-directory terms | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-agent | P1 |
| G | screenpipe | screenpipe/screenpipe | `b8f09c879fddc807e9fd3aae7aae4f1a0accb1f6` | Screenpipe Commercial License | NOT_ACQUIRED | OWNER-ASSERTED | apps/orcel-native-host | P3 |
| H | xlang-ai/OSWorld | xlang-ai/OSWorld | `5123bfdbbc34b947bcffcff564abc62d0ab7072d` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED | tests/benchmarks | P1 |
| H | ServiceNow/BrowserGym | ServiceNow/BrowserGym | `27a90ce815098f43414e93491e06907af468e45b` | Apache-2.0 | NOT_ACQUIRED | OWNER-ASSERTED | tests/benchmarks | P2 |

Donors already tracked by Orcel (outside the 50):

| Donor | Pin | Public licence (informational) | Status | Authorization | Orcel |
| --- | --- | --- | --- | --- | --- |
| vercel-labs/agent-browser | `b06e2533ba9b3823b8a96c859d455cb55f4d7893` | Apache-2.0; cli/src/native/a11y/axe.min.js MPL-2.0 | NOT_ACQUIRED | OWNER-ASSERTED AUTHORIZATION — 2026-11-17 | Promoted to a full record (section 8.7, V2) |
| vercel-labs/remote-agent-browser | `8770ea28f3ab0e8822e104e12e0efb65339d235b` | No LICENSE file; package.json declares MIT; GitHub reports no licence | NOT_ACQUIRED | OWNER-ASSERTED AUTHORIZATION — 2026-11-17 | Promoted to a full record (section 8.7, V2) |
| wangzan101/Mika | `e956f5529ad4cfd7881aafaa630318097949f56a` | Apache-2.0 + NOTICE; bundled PRoot GPL-2.0-or-later, talloc LGPL-3.0-or-later, Alpine rootfs mixed | NOT_ACQUIRED | OWNER-ASSERTED | none |
| phone-harness/phone-harness | `4bebff105af853215fb74c958c2c5e78bc275be2` | MIT | NOT_ACQUIRED | OWNER-ASSERTED | none |
| netease-uuyc/uuremote-integration-guide | `181dee4540a8e4161a65e1053fbcf6ad223d24f8` | MIT (org not GitHub-verified) | NOT_ACQUIRED | OWNER-ASSERTED | none |
| UU Remote (NetEase) | none | Proprietary; no official source repository found | NOT_ACQUIRED | OWNER-ASSERTED | none |
| Vercel agent-use | none | RESOLVED 2026-11-17: vercel-labs/agent-desktop + browser-use/desktop (section 8.7) | NOT_ACQUIRED | OWNER-ASSERTED AUTHORIZATION — 2026-11-17 | see agent_desktop, browser_use_desktop |
| bytedance/deer-flow | `81e1ab8dcc86574cfac0ecdfe3636b775a08c567` | MIT | TESTED | OWNER-ASSERTED | apps/orcel-agent/orcel_agent (tests: apps/orcel-agent/tests) |
| BuilderIO/agent-native | `9c277b79cb87eb27da538e572dd710986e2fa06d` | MIT | TESTED | OWNER-ASSERTED | apps/orcel-control-room/src/agentkit; crates/orcel-journal/src/resume.rs (unit tests in the file) |
| unclecode/crawl4ai | `94b67888ca8b335ff2121423a50e06dd27661922` | Apache-2.0 with an attribution requirement | TESTED | OWNER-ASSERTED | apps/orcel-browser-worker/src/extract/relevance.ts (relevance.test.ts) |
| Panniantong/Agent-Reach | `a19a171fa980a0785849596492e0af4db800c82f` | MIT | TESTED | OWNER-ASSERTED | crates/orceld/src/search.rs (crates/orceld/tests/wi06_search.rs) |
| WebMCP-org/npm-packages | `7db816b5a280c2d1d4b86559696e993c497c021a` | MIT | TESTED | OWNER-ASSERTED | apps/orcel-browser-worker/src/webmcp (declarative.test.ts) |
| J-F-Liu/lopdf | `version 0.45.0` | MIT | TESTED | OWNER-ASSERTED | apps/orcel-doc-parser/third_party/lopdf (apps/orcel-doc-parser tests) |

### 8.2 Resolution notes

- **Vercel browser-use/agent-desktop** (RESOLVED by the founder on 2026-11-17: both repositories, as separate donors; see section
  8.7. The original note follows.) The name mixes two organisations. Candidates: vercel-labs/agent-desktop (Apache-2.0, Rust computer-use CLI; admitted as a candidate by FD-UP-3) and browser-use/desktop (MIT, TypeScript desktop app, pinned f073b7574f7927185ebbebd87556391d5cb0cfd1). Neither is substituted for the other; vercel-labs/agent-desktop is the recorded candidate until the founder confirms.
  - Candidate `vercel-labs/agent-desktop` at `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad`: Apache-2.0, 3801 files.
  - Candidate `browser-use/desktop` at `f073b7574f7927185ebbebd87556391d5cb0cfd1`: MIT, 554 files.
- **Firecrawl** (RESOLVED): Founder pin in PR #785. HEAD moved again (2026-11-16 inventory: 42f4d669954649ce33466a2a50e8215c7f1f4d1c).
- **Fleet** (RESOLVED): Founder pin in PR #785 (fleetdm/fleet). HEAD moved (2026-11-16 inventory: 99e64e6bbee9e7a9b5334fea2527303992f747f7).
- **adisinghstudent/exa-browser** (RESOLVED): Named exactly in the directive. Third-party project, not Exa Labs; Exa Labs ships no product called Exa Browser (D:\Orcel-REA\reports\CURRENT_STATE.md).
- **microsoft/playwright-mcp** (RESOLVED): Canonical Microsoft repository. It is a thin package (cli.js, index.js); the implementation lives in microsoft/playwright at 76b6fa645744699e982a54c48c3fc7971f4a1eef.
- **OpenAdaptAI/openadapt-flow** (RESOLVED): Repository exists and is ARCHIVED; its README says the code now lives in OpenAdaptAI/OpenAdapt packages/flow. Transplant from OpenAdapt at 2e98be86a802b0867b9513491c5f368ba98811d0.
- **droidrun (verify org)** (RESOLVED): droidrun/droidrun redirects (GitHub rename) to droidrun/mobilerun; the org is droidrun. qdrk/droidrun, named in REA_WAVE3_COPY_FIRST_PLAN.md, is a fork of droidrun/mobilerun and is not used.
- **OpenSandbox (verify org)** (RESOLVED): alibaba/OpenSandbox redirects to opensandbox-group/OpenSandbox (GitHub transfer); REA_WAVE3_COPY_FIRST_PLAN.md names the same repository.
- **CopilotKit/OpenBot** (RESOLVED): CopilotKit/OpenBot exists. Not to be confused with ob-f/OpenBot (formerly isl-org/OpenBot, a robotics project), which is not used.
- **screenpipe** (RESOLVED): screenpipe/screenpipe (mediar-ai/screenpipe redirects here).
- **Vercel agent-use** (tracked; RESOLVED 2026-11-17): the founder named `vercel-labs/agent-desktop` and `browser-use/desktop`;
  `vercel-labs/agent-use` itself returns 404.

### 8.3 Access blockers

- **No private source is accessible.** The configured GitHub identity has no membership in `exa-labs` or `tinyfish-io`
  and sees no private repositories there (`D:\Orcel-REA\reports\CURRENT_STATE.md` section 5). Unblocking needs an org
  invitation or a fine-grained token with `Contents: read` on those orgs, and the exact `owner/repo` names. The hosted
  Exa and TinyFish backends (ranking models, agent runtime, browser fleet, Websets, monitors) are not public.
- **Not in any public repository:** Firecrawl's Fire-engine, AgentQL's query engine and SDK, Browserbase, Cua cloud,
  Simular API, Skyvern cloud, Maestro Cloud, RustDesk Pro server, UU Remote. The Appium platform drivers, the droidrun
  Portal app and the RustDesk relay server live in separate repositories that are not pinned here.
- **Model weights are not in the trees:** OmniParser (Hugging Face), GUI-Owl for MobileAgent, Agent S grounding models.
  Their model-card licences were not read and must be checked before any download.
- **Disk:** no full clones were made for this ledger; the three Wave 2 clones and the Wave 1 clones stay outside the repo.

### 8.4 Non-permissive public licences (informational)

Under the founder decision these licences no longer block copying, renaming or publishing. They are kept so that copies
carry the right notices, and so that the record states what the upstream terms say. Authorization for each: OWNER-ASSERTED
(founder, 2026-11-17), not independently verified.

- **firecrawl/firecrawl**: copyleft (AGPL/GPL) (AGPL-3.0 + per-directory terms).
- **fleetdm/fleet**: mixed per directory (MIT + per-directory terms). Notes: ee/: Fleet Enterprise Edition licence; docs/: CC BY-SA 4.0 (share-alike notice applies to copied docs).
- **exa-labs/openapi-spec**: no licence, proprietary or source-available (NONE).
- **exa-labs/exa-deepseek-chat**: no licence, proprietary or source-available (NONE).
- **adisinghstudent/exa-browser**: no licence, proprietary or source-available (NONE).
- **tinyfish-io/bigset-oss**: copyleft (AGPL/GPL) (AGPL-3.0).
- **trycua/cua**: mixed per directory (MIT + per-directory terms). Notes: apps/cua-spaces*, examples/{cua-bots-ios,cua-bots-macos,infinite-canvas-swift,openkoalabot-example-swift,openkoalabot-example-tauri}, libs/{cua-driver-bench,cua-spacesd,spaces-app-swift,spaces-notch-swift}, libs/cua/bench/streaming, libs/cua/crates/* (20 crates listed): FSL-1.1-MIT; libs/python/som: AGPL-3.0.
- **microsoft/OmniParser**: mixed per directory (CC-BY-4.0). Notes: Ultralytics-based icon_detect weights (v1, v1.5, v2) and the ultralytics==8.3.70 dependency: AGPL-3.0; Repository code and docs: CC-BY-4.0 (attribution required; README badge says MIT).
- **lightpanda-io/browser**: copyleft (AGPL/GPL) (AGPL-3.0 + per-directory terms).
- **browseros-ai/BrowserOS**: copyleft (AGPL/GPL) (AGPL-3.0 + per-directory terms).
- **Skyvern-AI/skyvern**: copyleft (AGPL/GPL) (AGPL-3.0).
- **Ylianst/MeshCentral**: mixed per directory (Apache-2.0 + per-directory terms). Notes: rdp/, public/mstsc/: GPL-3.0; public/novnc/: MPL-2.0 (file-level copyleft); agents/ prebuilt binaries: Not verified.
- **rustdesk/rustdesk**: copyleft (AGPL/GPL) (AGPL-3.0 + per-directory terms).
- **screenpipe/screenpipe**: no licence, proprietary or source-available (Screenpipe Commercial License).
- **vercel-labs/remote-agent-browser**: no licence, proprietary or source-available (No LICENSE file; package.json declares MIT; GitHub reports no licence).
- **wangzan101/Mika**: mixed per directory (Apache-2.0 + NOTICE; bundled PRoot GPL-2.0-or-later, talloc LGPL-3.0-or-later, Alpine rootfs mixed). Notes: PRoot, talloc, Alpine rootfs: GPL-2.0+, LGPL-3.0+, mixed.
- **UU Remote (NetEase)**: no licence, proprietary or source-available (Proprietary; no official source repository found).
- **Vercel agent-use**: resolved on 2026-11-17 to vercel-labs/agent-desktop (Apache-2.0) and browser-use/desktop (MIT); section 8.7.

### 8.5 Priority 0: highest-value immediately transplantable modules

Ordered by value against Orcel's current gaps. Each still needs its own activated grain, provenance file and tests before
any copy lands on main.

1. **Stale-reference rejection and reference minting for desktop elements** (hcu, `microsoft/Hybrid-Computer-Use` at `00eaeebe8ac0d275e46f875bdb5347e5f326faa1`, SOURCE_ACQUIRED) to apps/orcel-computer-host (Go to Go, same language; denied by default, test UI only first):
   `computer-use/internal/core/ax_ref_registry.go`, `computer-use/internal/core/ax_ref_minting.go`, `computer-use/internal/core/ax_ref_provider_continuity.go`, `computer-use/internal/core/ax_window_ref_registry.go`, `computer-use/internal/core/ax_app_ref_registry.go`, `computer-use/internal/core/ax_ref_snapshot_assignment.go`.
2. **Compact AX diff after each action, batched actions with readback** (hcu, `microsoft/Hybrid-Computer-Use` at `00eaeebe8ac0d275e46f875bdb5347e5f326faa1`, SOURCE_ACQUIRED) to apps/orcel-computer-host:
   `computer-use/internal/core/ax_semantic_diff.go`, `computer-use/internal/core/ax_semantic_diff_render.go`, `computer-use/internal/core/ax_batch.go`, `computer-use/internal/core/ax_batch_plan.go`, `computer-use/internal/core/ax_batch_observation.go`, `computer-use/internal/core/ax_action_readback.go`, `computer-use/internal/core/ax_action_stabilization.go`.
3. **Local screen parsing for vision fallback (icon detection, OCR, set-of-marks)** (omniparser, `microsoft/OmniParser` at `354021201345a96178360b28733573e27269f2de`, NOT_ACQUIRED) to apps/orcel-vision (new, contained sidecar; keep notices for ultralytics (AGPL-3.0) and the detector and caption weights; read each model card before downloading weights):
   `util/omniparser.py`, `util/utils.py`, `util/box_annotator.py`, `util/yolov9.py`, `omnitool/omniparserserver/omniparserserver.py`.
4. **Worker loop, procedural memory and behaviour judging** (agent_s, `simular-ai/Agent-S` at `0fff0e634869dab72027435b4586e62300185d41`, SOURCE_ACQUIRED) to apps/orcel-agent (provider-agnostic; paid providers opt-in):
   `gui_agents/s3/agents/worker.py`, `gui_agents/s3/agents/agent_s.py`, `gui_agents/s3/core/engine.py`, `gui_agents/s3/core/mllm.py`, `gui_agents/s3/memory/procedural_memory.py`, `gui_agents/s3/bbon/behavior_narrator.py`, `gui_agents/s3/bbon/comparative_judge.py`, `gui_agents/s3/agents/grounding.py`.
5. **Hybrid a11y/DOM snapshot and act/observe/extract with action cache** (stagehand, `browserbase/stagehand` at `82827a219512f0399cb159720a63f7d271d21480`, SOURCE_ACQUIRED) to apps/orcel-browser-worker (no Browserbase transport):
   `packages/extension/understudy/a11y/snapshot/capture.ts`, `packages/extension/understudy/a11y/snapshot/a11yTree.ts`, `packages/extension/understudy/a11y/snapshot/domTree.ts`, `packages/extension/understudy/a11y/snapshot/xpathUtils.ts`, `packages/extension/services/actService.ts`, `packages/extension/services/observeService.ts`, `packages/extension/services/extractService.ts`, `packages/extension/services/cacheService.ts`.
6. **Snapshot-ref MCP browser tools and tool registry** (playwright_mcp, `microsoft/playwright` at `76b6fa645744699e982a54c48c3fc7971f4a1eef`, NOT_ACQUIRED) to apps/orcel-mcp (tools) over apps/orcel-browser-worker:
   `packages/playwright-core/src/tools/mcp`, `packages/playwright-core/src/tools/backend`, `packages/playwright-core/src/tools/utils`, `packages/playwright-core/src/entry/mcp.ts`, `tests/mcp`.
7. **Record, compile, replay, verify and repair workflows** (openadapt_flow, `OpenAdaptAI/OpenAdapt` at `2e98be86a802b0867b9513491c5f368ba98811d0`, NOT_ACQUIRED) to apps/orcel-agent (flow package, new):
   `packages/flow/openadapt_flow/ir.py`, `packages/flow/openadapt_flow/recorder.py`, `packages/flow/openadapt_flow/compiler`, `packages/flow/openadapt_flow/backend.py`, `packages/flow/openadapt_flow/backends`, `packages/flow/openadapt_flow/verify.py`, `packages/flow/openadapt_flow/verify_run.py`, `packages/flow/openadapt_flow/repair`.
8. **Sandbox execution daemon and egress policy** (opensandbox, `opensandbox-group/OpenSandbox` at `44e79a2dc3c99e26d82aa87fe13a73537d7e7812`, NOT_ACQUIRED) to apps/orcel-sandbox (new; launched under apps/orcel-contain policy and the Orcel stop control):
   `components/execd/pkg/runtime`, `components/execd/pkg/isolation`, `components/execd/pkg/lifecycle`, `components/egress`, `server/opensandbox_server/services`.

Notices and facts for this list: OmniParser's repository is CC-BY-4.0 (attribution), its `requirements.txt` pins
`ultralytics==8.3.70` (AGPL-3.0), and its weights are not in the repository: they come from Hugging Face, so each model
card's terms must be read before download (older icon detectors are AGPL-3.0; icon_detect_v3 and the caption models are
MIT per the README). HCU files under `osworld-overlay/` and `ax_records.py` carry Apache-2.0 and a Playwright NOTICE.
OpenAdapt Flow is taken from `OpenAdaptAI/OpenAdapt` `packages/flow` because `openadapt-flow` is archived; its benchmark
configuration is fetched from third parties at run time and is not in the repository.

### 8.6 Pin drift since 2026-11-16

- `firecrawl/firecrawl`: `42f4d669954649ce33466a2a50e8215c7f1f4d1c` to `98a5630a0b7ad3d58653dfe4ceb21d444dd8e2d2`.
- `fleetdm/fleet`: `99e64e6bbee9e7a9b5334fea2527303992f747f7` to `6070ad340095cd9dbfdef75fb6d18c9ba14c4b82`.
- `vercel-labs/agent-browser`: `53384771fbafc261ba67608ac806dd5aa70b84f0` to `b06e2533ba9b3823b8a96c859d455cb55f4d7893`.
- Sections 1 to 7 keep the 2026-11-16 pins; the ledger records the new HEADs. Every other pre-existing pin is unchanged.

### 8.7 Vercel source expansion (2026-11-17)

The founder resolved "Vercel agent-use" as **both** `vercel-labs/agent-desktop` and `browser-use/desktop` (separate donors;
`browser-use/desktop` belongs to the browser-use organisation, not Vercel) and put every useful `vercel` and `vercel-labs` repository
in scope. Authorization for every record below: **OWNER-ASSERTED AUTHORIZATION — 2026-11-17**, recorded in
`docs/orcel/grants/2026-11-17-founder-attestation.md` (section "Vercel source expansion (2026-11-17)"). It is owner-asserted and
not independently verified; the public licence stays as information, provenance and notices. Machine-readable data:
`TRANSPLANT_LEDGER.json` records in groups I and J, and `vercel_expansion`; `capability_inventory.json` gains one record per new source
(now 182 records: 15 TESTED, 156 NOT STARTED, 11 BLOCKED).

- **Method.** No clones. SHAs from `git ls-remote <repo> HEAD` on 2026-11-17; metadata, languages, the recursive tree, licence files,
  manifests and key source files from the GitHub API at that SHA. Functionality below comes from the source tree and files, not only
  the README. Nothing is acquired: every record is NOT_ACQUIRED.
- **Not found or redirected:** none. All 25 founder-named repositories exist under the named owner with no redirect.
- **One runtime.** `apps/orcel-agent` stays the single agent runtime. Eve, Workflow and durable-harness supply patterns and tests that
  are ported into it; `crates/orcel-journal` stays the privileged operation journal and takes no model-conversation durability (the
  ruling of the unmerged 2026-09-30 Eve donor plan on branch `plan/eve-donor-integration`, kept).
- **Personal Agent plan.** The Nod-derived Orcel Personal Agent plan named in the directive is not in this repository or its
  remote branches (searched 2026-11-17). Targets were compared with apps/orcel-agent, which stays the single agent runtime.

#### 8.7.1 Founder-named repositories

| Repository | Pinned SHA | Public licence (informational) | Status | V | Orcel target | P |
| --- | --- | --- | --- | --- | --- | --- |
| vercel-labs/agent-desktop | `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad` | Apache-2.0 | NOT_ACQUIRED | V1 | apps/orcel-native-host (macOS, Linux, cross-platform core) + apps/orcel-computer-host (Windows) | P0 |
| browser-use/desktop | `f073b7574f7927185ebbebd87556391d5cb0cfd1` | MIT | NOT_ACQUIRED | V1 | apps/orcel-browser-worker (sessions) + apps/orcel-control-room (takeover UI) | P1 |
| vercel-labs/agent-browser | `b06e2533ba9b3823b8a96c859d455cb55f4d7893` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | V2 | crates/orcel-browser-host | P0 |
| vercel-labs/ai-sdk-computer-use | `ed103da5ebe75112850fbba39872206dd3c439de` | NONE | NOT_ACQUIRED | V1 | none (reference only) | P3 |
| vercel-labs/remote-agent-browser | `8770ea28f3ab0e8822e104e12e0efb65339d235b` | no LICENSE file (package.json: MIT) | NOT_ACQUIRED | V2 | crates/orcel-browser-host (reference contract only) | P3 |
| vercel/eve | `ac1a15c36d95ae6d0d73d68d20008a8da4a5625a` | Apache-2.0 + NOTICE + per-directory terms | NOT_ACQUIRED | V3 | apps/orcel-agent | P1 |
| vercel/workflow | `47697fe1b7af0d7da695a17f2f34d2394ebdef90` | Apache-2.0 | NOT_ACQUIRED | V3 | apps/orcel-agent | P1 |
| vercel-labs/durable-harness | `badd648db763e7d9121917b5c35732cd334e01be` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | V3 | apps/orcel-agent | P0 |
| vercel-labs/open-agents | `cf865e94de7729751c747171785b6ce57e7b178c` | MIT | NOT_ACQUIRED | V3 | apps/orcel-agent (reference only) | P3 |
| vercel-labs/personal-agent-template | `c0a09b7a2cb62563d7f945f3b30cc65279cf5417` | MIT | NOT_ACQUIRED | V3 | apps/orcel-agent (memory) | P2 |
| vercel-labs/coding-agent-template | `e753e1b6d28b2d64446dd5f9ef33a93909cc7a09` | Apache-2.0 | NOT_ACQUIRED | V3 | none (reference only) | P3 |
| vercel/ai | `3bea041f28e65f371e640d2c70c302776a46387f` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | V4 | apps/orcel-mcp (MCP client conformance) + crates/orcel-policy (shadow policy) | P2 |
| vercel-labs/mcp-handler | `57181555cbef0de65bdaa041db69f8434266ed66` | no LICENSE file (package.json: Apache-2.0) | NOT_ACQUIRED | V4 | apps/orcel-mcp | P1 |
| vercel-labs/mcp-to-ai-sdk | `3287f6ff08b2574530818b8b75ecd1ed129efd06` | Apache-2.0 | NOT_ACQUIRED | V4 | apps/orcel-mcp | P1 |
| vercel-labs/just-bash | `5b8297908ef921bbd83a94ad5b7ba82340c0a74a` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | V5 | apps/orcel-sandbox (new): virtual-shell tier | P0 |
| vercel-labs/opensrc | `b51de60867e806da1839b33dd29c29424f12521b` | Apache-2.0 | NOT_ACQUIRED | - | none (reference only) | P3 |
| vercel-labs/skills | `50894c1d98bc45ca1ab127213e59d6525065b5e7` | MIT + per-directory terms | NOT_ACQUIRED | - | apps/orcel-agent (reference only) | P3 |
| vercel-labs/agent-skills | `1a2c79d4e6c4a2283dc2c614b6538cbe1ed5ca62` | NONE | NOT_ACQUIRED | - | none | P3 |
| vercel/sandbox | `58c48661a4ff5f994739eede59769f03b50c6d89` | Apache-2.0 | NOT_ACQUIRED | V5 | apps/orcel-sandbox (new) (API reference only) | P2 |
| vercel-labs/emulate | `ad7b0dea9287ac7bdfe94bf7056522b90a736e2a` | Apache-2.0 + THIRD_PARTY_NOTICES.md | NOT_ACQUIRED | V5 | tests/emulators (new) | P0 |
| vercel-labs/workflow-builder-template | `3ed5b14af3194d75ad686bfe1da50d42d4ce1b77` | Apache-2.0 | NOT_ACQUIRED | - | none (reference only) | P3 |
| vercel-labs/agent-eval | `9ff2ea3e9f14c14e5123b215c3f695d3b4f9955d` | MIT + per-directory terms | NOT_ACQUIRED | V5 | tests/benchmarks | P1 |
| vercel/next-evals-oss | `3bd644b26e69e3d89cefb33680b4f28ff7cc0eab` | MIT | NOT_ACQUIRED | - | none (reference only) | P3 |
| vercel-labs/native | `4d47c2cfcd256e7835a31342058cb321d5c75217` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | V1 | none (reference only) | P3 |
| vercel-labs/sandcastle | `85b678c10defa2b7220a37418f96f4410c4fe1d4` | MIT | NOT_ACQUIRED | V5 | none (reference only) | P3 |

Notes on the named set:

- `vercel-labs/agent-desktop` keeps its group A record (now RESOLVED, priority P0 for V1); `browser-use/desktop` is a new record.
- `vercel-labs/agent-browser` and `vercel-labs/remote-agent-browser` moved from the tracked-donor table into full records; their
  HEADs are unchanged since the ledger pin, and their feature rows in `capability_inventory.json` stand.
- `vercel/sandbox` is the client SDK, CLI, a local test double and base images for hosted Vercel Sandbox. The microVM backend is not public.
- `vercel-labs/native` says it is experimental; `vercel-labs/sandcastle` calls itself a proof of concept not meant for production;
  `vercel-labs/durable-harness` is experimental (0.0.x).
- No licence file at all: `vercel-labs/ai-sdk-computer-use`, `vercel-labs/agent-skills`. Licence only in package.json:
  `vercel-labs/mcp-handler` (Apache-2.0), `vercel-labs/agent-eval` (MIT), `vercel-labs/remote-agent-browser` (MIT);
  `vercel-labs/just-bash` has Apache-2.0 in `packages/just-bash/LICENSE` only, plus GPL-2.0 and GPL-3.0 test fixtures.
- `vercel/next-evals-oss` is about 1.8 GB in the tree (results per model) and must not be cloned.

#### 8.7.2 Discovered repositories

Sweep: `gh api orgs/vercel/repos` (244 public) and `gh api orgs/vercel-labs/repos` (398 public), paginated; 467 are active and not
forks. Selected by capability (computer use, browser agents, agent runtimes, durable execution, sandboxing, remote sessions, MCP,
evaluation, orchestration, memory, security), then checked against each tree and key files.

| Repository | Pinned SHA | Public licence | What the code does | Orcel target | V | P |
| --- | --- | --- | --- | --- | --- | --- |
| vercel-labs/fx | `3fe7377e290fff22d287118db8058a3c89e8cbee` | Apache-2.0 + THIRD_PARTY_NOTICES.md | A coding agent in Zig: agent loop, permission gate with approval prompts, an auto classifier and command admission (src/core/permissions), a session store with event... | apps/orcel-agent (reference) | V3 | P2 |
| vercel-labs/ralph-loop-agent | `8a37af8390c7bd6fac81f746776b52ce6d5001b4` | Apache-2.0 | Wraps an AI SDK agent in an outer loop that repeats until a verifier or stop condition passes (ralph-loop-agent.ts, ralph-loop-agent-evaluator.ts,... | apps/orcel-agent (reference) | V3 | P3 |
| vercel-labs/knowledge-agent-template | `fab8f3076de22e79f731525456c1151efa6f48de` | MIT + per-directory terms | Knowledge agent: a router sends questions to source agents over a file system synced from GitHub (packages/agent/src/router, agents/source.ts), with sanitising and... | apps/orcel-agent (reference) | - | P3 |
| vercel-labs/eve-memory-agent-template | `fd414324954dff3f88bb7af547e4b1fc197f4dd2` | MIT | eve agent with long-term memory kept as files: user and channel preference memories (agent/memory), memory helpers (agent/lib/memory), write and edit tools that... | apps/orcel-agent (memory) | V3 | P2 |
| vercel/chat | `990411ea2b6b3aeb01ef0bcf44cd2e0ccb320b93` | MIT | One bot or agent across Slack, Teams, Discord, Google Chat, GitHub, GitLab, Linear, Telegram, WhatsApp, Messenger, Instagram, X, Twilio, Gmail, Notion, Twitch and web... | apps/orcel-relay | - | P2 |
| vercel/resumable-stream | `770cdeb4b6e4b3838b294b0565591f3d75930897` | MIT-style LICENSE text | Lets a client reconnect to an in-progress HTTP stream and resume from where it left off, buffering through Redis (src/runtime.ts, redis and ioredis adapters) | apps/orcel-relay | - | P3 |
| vercel-labs/steve | `09c105e7751f89365c15e3ddf405f1ddeeba5fe5` | NONE | Self-hosted eve proof of concept: an eve agent (bash, run_python, web fetch and search tools) on @workflow/world-postgres, deployed with Ansible roles (hardening,... | apps/orcel-agent (reference) | V3 | P2 |
| vercel-labs/run | `6c146567b19d96b4164550314875ed55eb2366ce` | Apache-2.0 + per-directory terms | Secure alternative to eval for agents: runs JavaScript in QuickJS inside workers with host functions (host-function-invocation.ts), CPU and wall timeouts, interrupts,... | apps/orcel-sandbox (new) | V5 | P1 |
| vercel-labs/quickjs-wasi | `2d8504c47bbb22bced32ec3c9e93e8c51ed73cac` | MIT + per-directory terms | QuickJS-NG compiled to WASI with whole-VM snapshot and restore, including pending promises (src/index.ts, wasi-shim.ts), and crypto and URL extensions | apps/orcel-sandbox (new) | V5 | P2 |
| vercel-labs/bash-tool | `70ba5ad4d01be465e76acb5b6bd0c6221a2af1b9` | MIT | AI SDK tools bash, readFile, writeFile and a skill tool over either just-bash or Vercel Sandbox (src/sandbox, src/tools, src/skills) | apps/orcel-sandbox (new) (reference) | V5 | P3 |
| vercel-labs/guarded-fetch | `74b7a293472a44b4d02bbcd842c6694e41594e7c` | Apache-2.0 | SSRF-safe fetch: resolves and pins DNS (guarded-lookup.ts, resolve-host.ts), blocks private and special IP ranges (ip-address.ts, url-blocked.ts, hostname-safety.ts),... | crates/orcel-provider-network (test vectors; compare with apps/orcel-browser-worker/src/resolve-guard.ts) | - | P1 |
| vercel-labs/just-secrets | `31719436bccf5ecfee621391e94c771b7484c0cf` | MIT | Reads and writes OS secret stores from Node with no dependencies: macOS security CLI, Linux secret-tool and Windows Credential Manager through PowerShell... | none (reference only) | - | P3 |
| vercel-labs/deepsec | `aed5d06de8940c1fea4e6bef3600d875dd35007c` | Apache-2.0 + NOTICE | Security review harness: a scanner with about 200 declarative matchers (packages/scanner/src/matchers) finds candidate issues, a processor hands them to coding agents... | tests/security-scan (new) | - | P2 |
| vercel-labs/dev3000 | `e5573ae23a62fad58194881ef8642a7ee2b273fe` | MIT | Records a unified, timestamped development timeline: managed CDP Chrome with isolation (managed-cdp.ts, chrome-isolation.ts), browser events, console, network... | apps/orcel-browser-worker (compare with navigation-trace.ts) | V2 | P2 |
| vercel-labs/webreel | `1504682685514107e48a1696490666eb9ed7da14` | Apache-2.0 | Records scripted browser sessions as video (packages/@webreel/core) from step scripts | crates/orcel-browser-host (reference) | V2 | P3 |
| vercel-labs/wterm | `b00ad0b7786cc9031d45d878bb9ad9bc75016850` | Apache-2.0 | Web terminal emulator: VT parser, grid, scrollback, graphemes and widths in Zig compiled to WASM (src/*.zig, wasm_api.zig); DOM renderer and React, Vue and Svelte... | apps/orcel-control-room | - | P2 |
| vercel-labs/specli | `6dbe06908948847fad5c2e9617150a49c14b43a2` | NONE | Turns an OpenAPI spec into an agent-oriented CLI: parses and validates the spec (src/cli/parse, spec), builds a command model, executes requests (runtime/) and can... | apps/orcel-mcp (reference) | V4 | P3 |
| vercel-labs/lat.md | `370a9a8c13787d83a52d9f437d5812a2aaaac808` | MIT + per-directory terms | Markdown knowledge graph for a codebase: documents with code references (code-refs.ts), validation, search with a stemmer and MiniLM embeddings... | apps/orcel-agent (reference) | - | P3 |
| vercel-labs/ai-python | `07aaf34f985ec378b5e3b998db6c66468935875c` | Apache-2.0 | AI SDK for Python: provider adapters (src/ai/providers), agents, a durable-step helper (durable.py), ops, UI message streaming and telemetry, with tests per provider | apps/orcel-agent | V3 | P1 |
| vercel/detect-agent | `3ab1df1e4eaae153cf66f4a5018e4c5854855212` | no LICENSE file (package.json: Apache-2.0) | Detects which AI agent is running a process from environment conditions defined in agents.json (TypeScript src/ and Go detect.go, evaluate_condition.go), with shared... | apps/orcel-mcp (reference) | - | P3 |

Inspected and skipped:

- `vercel-labs/npx-mcp`: Empty repository (size 0, git ls-remote returns no HEAD); nothing to record.
- `vercel-labs/harness-agent-eve-extension`: Thin glue exposing @ai-sdk/harness packages to eve; the substance is in vercel/ai packages/harness*.
- `vercel-labs/sandboxed-issue-triage-agent`: 23-file app over @ai-sdk/harness and Vercel Sandbox; covered by vercel/ai and durable-harness.
- `vercel-labs/ai-sdk-tool-code-execution`: 9-file demo that calls the hosted Vercel Sandbox; covered by vercel-labs/run and just-bash.
- `vercel-labs/rex-cloud`: Cloud terminals for a third-party tool on Vercel Sandbox; hosted only.
- `vercel-labs/skills-handler`: 15-file early version of the skills tooling; superseded by vercel-labs/skills.
- `vercel-labs/tau-agent`: 15-file coding-agent demo of ai-python; ai-python itself is recorded.
- `vercel-labs/openreview`: Code-review bot template on Vercel Sandbox and Workflow; deepsec and durable-harness cover the useful parts.
- `vercel/next-devtools-mcp`: Next.js-specific MCP server (dev-server discovery, Next.js docs); not a general capability.

Skipped as clearly irrelevant (one line per category):

- **Web frameworks and build tools:** vercel/next.js, turborepo, ncc, nft, swr, styled-jsx, satori, edge-runtime, microfrontends, serve, micro and similar: application frameworks and build tooling, not agent capabilities.
- **Starters, demos and examples:** vercel/examples, next-learn, *-starter, *-demo, *-template repositories for commerce, CMS, databases and AWS services, workshop and academy repositories: sample apps unrelated to agents.
- **Workflow pattern examples:** About 60 vercel-labs/workflow-* repositories (saga, retry-backoff, circuit-breaker and others): single-pattern examples of vercel/workflow, which is recorded.
- **eve templates:** vercel-labs/eve-*-template, *-eve-template and eve-examples: application templates on vercel/eve; eve-memory-agent-template is recorded, the rest add no capability.
- **Platform SDKs, deploy tooling and integrations:** vercel/vercel, vercel-py, sdk, terraform-provider-vercel, storage, flags, analytics, speed-insights, otel, ai-gateway providers, vcr-action, Codex/Cursor/Claude deploy plugins: Vercel platform clients.
- **AI chat UI and generative UI:** vercel/chatbot, ai-elements, streamdown, v0-sdk, json-render, ui, vercel-labs/ai-chatbot-svelte and ai-sdk-preview-*: chat front ends and UI kits; Orcel's control room is separate.
- **Design, fonts, media and misc:** geist-font, geist-pixel-font, vgpu, gpu-lexer, reel0, ship26-*, arcade, hyper*, zsh-theme and similar: unrelated to agents.
- **Language and compiler experiments:** zerolang, scriptc, tsc-ts, python-typemap, bincode-fork, ggt, ggbuild: compiler or language projects, not agent capabilities.
- **Forks and archived repositories:** 57 active forks, 109 archived repositories and 9 archived forks (175 in all) were excluded from selection.

#### 8.7.3 V1 to V5: first modules to transplant

Each still needs its own activated grain, provenance file and tests before any copy lands on main.

**V1 Desktop (agent-desktop + browser-use/desktop + HCU).**

1. Windows element ref minting and stale-ref rejection (ledger P0 order 1) (`hcu`) to apps/orcel-computer-host:
   `computer-use/internal/core/ax_ref_registry.go`, `computer-use/internal/core/ax_ref_minting.go`, `computer-use/internal/core/ax_ref_provider_continuity.go`.
2. Cross-platform ref store with identity matching and saved-ref resolution (macOS and Linux) (`agent_desktop`) to apps/orcel-native-host:
   `crates/core/src/refs/refs_store.rs`, `crates/core/src/refs/ref_alloc.rs`, `crates/core/src/refs/ref_identity.rs`, `crates/core/src/refs/ref_identity_match.rs`, `crates/core/src/refs/resolve_saved_ref.rs`, `crates/core/src/refs/refs_validate.rs`.
3. Actionability gates before any ref action (`agent_desktop`) to apps/orcel-native-host:
   `crates/core/src/actionability/gates.rs`, `crates/core/src/actionability/evaluate.rs`, `crates/core/src/actionability/hit_test_evidence.rs`, `crates/core/src/actionability/occluder.rs`, `crates/core/src/actionability/stability_sampler.rs`.
4. Compact AX diff and batched actions with readback (ledger P0 order 2) (`hcu`) to apps/orcel-computer-host:
   `computer-use/internal/core/ax_semantic_diff.go`, `computer-use/internal/core/ax_batch.go`, `computer-use/internal/core/ax_action_readback.go`.
5. Parallel browser sessions with pooled Chromium and live screencast (`browser_use_desktop`) to apps/orcel-browser-worker:
   `app/src/main/sessions/SessionManager.ts`, `app/src/main/sessions/BrowserPool.ts`, `app/src/main/sessions/SessionScreencast.ts`.
6. Human takeover of a running session (`browser_use_desktop`) to apps/orcel-control-room:
   `app/src/main/takeoverOverlay.ts`.
7. Desktop e2e scenarios as qualification tests (`agent_desktop`) to apps/orcel-computer-host (Windows) and apps/orcel-native-host/tests (Linux):
   `tests/e2e-windows/scenarios`, `tests/e2e-linux/scenarios`.

**V2 Browser (agent-browser + Obscura, Stagehand, Playwright).**

1. Accessibility snapshot with stable refs (Rust to Rust) (`agent_browser`) to crates/orcel-browser-host:
   `cli/src/native/snapshot.rs`, `cli/src/native/element.rs`.
2. Ref-addressed actions and multi-tab binding (`agent_browser`) to crates/orcel-browser-host:
   `cli/src/native/actions.rs`, `cli/src/native/interaction.rs`, `cli/src/native/tab_binding.rs`.
3. Hybrid a11y/DOM snapshot, act/observe with action cache (ledger P0 order 5) (`stagehand`) to apps/orcel-browser-worker:
   `packages/extension/understudy/a11y/snapshot/capture.ts`, `packages/extension/understudy/a11y/snapshot/a11yTree.ts`, `packages/extension/services/actService.ts`, `packages/extension/services/observeService.ts`, `packages/extension/services/cacheService.ts`.
4. Snapshot-ref MCP browser tools (ledger P0 order 6; source in microsoft/playwright) (`playwright_mcp`) to apps/orcel-mcp:
   `packages/playwright-core/src/tools/mcp`, `packages/playwright-core/src/tools/backend`.
5. Second engine behind the engine contract (`obscura`) to third_party/obscura (new) via crates/orcel-browser-host engine contract:
   `crates/obscura-browser/src`, `crates/obscura-dom/src`.
6. Parity and e2e corpus for dual-engine qualification (`agent_browser`) to tests/browser-corpus (new):
   `cli/src/native/parity_tests.rs`, `cli/src/native/e2e_tests.rs`.

**V3 Agent reliability (durable-harness + workflow + eve, against Orcel's runtime).** apps/orcel-agent stays the one agent runtime; crates/orcel-journal stays the privileged operation journal and receives no model-conversation durability (ruling of the 2026-09-30 Eve donor plan, kept).

1. Exactly-once tool effects and crash resume from the session log (`durable_harness`) to apps/orcel-agent:
   `packages/harness-world/src/fence.ts`, `packages/harness-world/src/recover.ts`, `packages/harness-world/src/session-log.ts`, `packages/harness-process/src/ledger.ts`, `packages/harness-process/src/journal.ts`, `packages/harness-process/src/recovery.ts`.
2. Deterministic replay with step memoisation and divergence detection (`workflow`) to apps/orcel-agent:
   `packages/core/src/replay-divergence.ts`, `packages/core/src/events-consumer.ts`, `packages/core/src/step.ts`, `packages/core/src/state.ts`, `packages/world/src/interfaces.ts`, `packages/world/src/events.ts`.
3. Tool authorization, approvals and interrupted-attempt handling in the loop (`eve`) to apps/orcel-agent:
   `packages/eve/src/harness/authorization.ts`, `packages/eve/src/harness/clearance.ts`, `packages/eve/src/harness/approval-outcome.ts`, `packages/eve/src/harness/interrupted-attempt.ts`, `packages/eve/src/harness/hitl`.
4. Context compaction (`eve`) to apps/orcel-agent (orcel_agent/compaction.py):
   `packages/eve/src/harness/compaction`.
5. Chaos, drill and invariant tests (with workflow packages/world-testing) (`durable_harness`) to apps/orcel-agent/tests:
   `packages/harness-world/src/chaos.test.ts`, `packages/harness-world/src/drills.test.ts`, `packages/harness-world/src/invariants.test.ts`.

**V4 MCP (mcp-handler + mcp-to-ai-sdk).**

1. Pinned, reviewed tool-schema snapshots (`mcp_to_ai_sdk`) to apps/orcel-mcp:
   `lib/tool-generator.ts`, `lib/mcp-client.ts`, `lib/client-generator.ts`.
2. OAuth protected-resource metadata and bearer verification (`mcp_handler`) to apps/orcel-mcp (compare with src/oauth_authorization.ts):
   `src/auth/auth-metadata.ts`, `src/auth/auth-wrapper.ts`.
3. Streamable HTTP and SSE transport handling (`mcp_handler`) to apps/orcel-mcp:
   `src/handler/mcp-api-handler.ts`.
4. Per-message and per-tool spans (`mcp_handler`) to apps/orcel-mcp:
   `src/telemetry`.
5. Shadow-mode policy decisions per tool (`vercel_ai`) to crates/orcel-policy (reference):
   `packages/policy-opa/src/shadow.ts`, `packages/policy-opa/src/wrap-mcp-tools.ts`.

**V5 Sandbox and testing (just-bash + emulate + agent-eval).**

1. Virtual-shell tier with no host access (`just_bash`) to apps/orcel-sandbox (new):
   `packages/just-bash/src/Bash.ts`, `packages/just-bash/src/parser`, `packages/just-bash/src/interpreter`, `packages/just-bash/src/fs`, `packages/just-bash/src/limits.ts`, `packages/just-bash/src/security`, `packages/just-bash/src/network`.
2. No-network GitHub API emulator for git and OAuth tests (`emulate`) to tests/emulators (new):
   `packages/@emulators/core/src`, `packages/@emulators/github/src`.
3. Sandboxed eval runs with failure classes and fingerprints (`agent_eval`) to tests/benchmarks:
   `packages/agent-eval/src/lib/runner.ts`, `packages/agent-eval/src/lib/docker-sandbox.ts`, `packages/agent-eval/src/lib/classifier.ts`, `packages/agent-eval/src/lib/fingerprint.ts`.
4. Code-mode tier with host functions and continuations (`vercel_run`) to apps/orcel-sandbox (new):
   `packages/run/src/run.ts`, `packages/run/src/host-function-invocation.ts`, `packages/run/src/continuation-codec.ts`.
5. Shell conformance tests (`just_bash`) to apps/orcel-sandbox/tests (new):
   `packages/just-bash/src/spec-tests`, `packages/just-bash/src/comparison-tests`.
