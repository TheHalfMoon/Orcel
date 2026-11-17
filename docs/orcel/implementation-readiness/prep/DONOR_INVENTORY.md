# Unified-platform donor inventory (Wave 1, UP-001 prep)

**Status: INVENTORY ONLY.** This document imports, copies or sublicenses no donor code. It records what
each donor repository contains at an exact commit, what licence terms its files carry, and how each
capability could reach Orcel. It makes no legal decision. The machine-readable companion is
[`capability_inventory.json`](capability_inventory.json) (96 records at first; 140 after section 8). The master
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
15 TESTED, 111 NOT STARTED, 14 BLOCKED). Nothing here imports, copies or sublicenses donor code.

- **Method.** No clones. SHAs are `git ls-remote <repo> HEAD` on 2026-11-17. Metadata, languages, the recursive tree and
  every LICENSE, NOTICE, THIRD_PARTY and manifest file at that SHA come from the GitHub API. Wave 1 and Wave 2 clone and
  test evidence comes from the REA workspaces `D:\Orcel-REA` and `D:\Orcel-REA-W2` (read-only); every REA clone SHA
  matches the HEAD read here. Model weights, datasets and binaries are recorded separately and were not downloaded.
- **Statuses** (highest stage any part of the source has reached): NOT_ACQUIRED (API pin only), SOURCE_ACQUIRED (local
  clone at the SHA), REA_VERIFIED (donor tests run by the REA), TRANSPLANTED, INTEGRATED, TESTED (Orcel tests on main),
  RELEASE_QUALIFIED (none). Downloading never makes a source INTEGRATED.
- **Rights** are recorded in two separate fields: the public licence, and the owner-asserted authorization recorded in
  `docs/orcel/grants/2026-11-17-founder-attestation.md` (section "Master directive"), which is owner-asserted and not
  independent legal verification. A public-redistribution flag never blocks private or local engineering.
- **One owner per feature.** Each ledger module names one Orcel owner; "(new)" owners do not exist on main yet.

### 8.1 Per-source table

| Grp | Source | Repository | Pinned SHA | Licence | Status | Public redistribution | Orcel owner | P |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A | Obscura | h4ckf0r0day/obscura | `0d9a2f764ffdb097269da048002c593865e83a9e` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | permissive | third_party/obscura + crates/orcel-browser-host (engine contract) | P2 |
| A | browser-use | browser-use/browser-use | `4b5b1b0aa0ab45a1d6a2a31984d37d3e748c0134` | MIT | TESTED | permissive | apps/orcel-browser-worker | P1 |
| A | Vercel browser-use/agent-desktop | vercel-labs/agent-desktop (NEEDS_FOUNDER_CONFIRMATION) | `8ffecc1d3d088727f8d84baf4dde0224aab2e8ad` | Apache-2.0 (candidate 2: MIT) | NOT_ACQUIRED | permissive | apps/orcel-native-host | P2 |
| A | Crawlee | apify/crawlee | `7bec9ad5631f8e529ae067494f6841dba3c12683` | Apache-2.0 | NOT_ACQUIRED | permissive | crates/orcel-jobs (new) | P2 |
| A | Scrapling | D4Vinci/Scrapling | `bb223f2f5fc8f743772751a5ce283ef7851ca6be` | BSD-3-Clause | NOT_ACQUIRED | permissive | crates/orcel-browser-host | P2 |
| A | Firecrawl | firecrawl/firecrawl | `98a5630a0b7ad3d58653dfe4ceb21d444dd8e2d2` | AGPL-3.0 + per-directory terms | TESTED | copyleft, separate component | apps/orcel-firecrawl (new) | P1 |
| A | Fleet | fleetdm/fleet | `6070ad340095cd9dbfdef75fb6d18c9ba14c4b82` | MIT + per-directory terms | NOT_ACQUIRED | mixed per directory | crates/orcel-fleet-report (new) | P3 |
| A | Playwright | microsoft/playwright | `76b6fa645744699e982a54c48c3fc7971f4a1eef` | Apache-2.0 + per-directory terms | TESTED | permissive | apps/orcel-browser-worker | P1 |
| B | exa-labs/exa-js | exa-labs/exa-js | `ec25f4016f5a7b514fae9947ca9fd191885eabab` | MIT | REA_VERIFIED | permissive | tests/exa-compat (new) | P1 |
| B | exa-labs/exa-py | exa-labs/exa-py | `95647c10282cacc3f030440442805f337257d29f` | MIT | REA_VERIFIED | permissive | tests/exa-compat (new) | P2 |
| B | exa-labs/exa-mcp-server | exa-labs/exa-mcp-server | `93c0d5e1fecfc1ec9bf70fa9f3633962a1f2fa8a` | MIT | REA_VERIFIED | permissive | apps/orcel-mcp | P1 |
| B | exa-labs/agent-skills | exa-labs/agent-skills | `9d220cc035f17bc01ca707ffae4ea1114af081fd` | MIT | SOURCE_ACQUIRED | permissive | apps/orcel-mcp | P3 |
| B | exa-labs/benchmarks | exa-labs/benchmarks | `a6a9590b1634fd4bf6f6ea7fd80b0084489c8e2b` | MIT | SOURCE_ACQUIRED | permissive | tests/benchmarks | P2 |
| B | exa-labs/openapi-spec | exa-labs/openapi-spec | `ebdf275f7272274a8d8592d62c80f7dd0196e6aa` | NONE | SOURCE_ACQUIRED | **needs grant evidence** | crates/orcel-web (new) | P2 |
| B | exa-labs/exa-deepseek-chat | exa-labs/exa-deepseek-chat | `f76f8e2f01d1bbfbea82af41011c102678156c30` | NONE | SOURCE_ACQUIRED | **needs grant evidence** | apps/orcel-control-room (reference only) | P3 |
| B | adisinghstudent/exa-browser | adisinghstudent/exa-browser | `20a0cf9100879f234bd0036a3d9cae58e135265d` | NONE | SOURCE_ACQUIRED | **needs grant evidence** | apps/orcel-control-room (reference only) | P3 |
| C | tinyfish-mcp-server | tinyfish-io/tinyfish-mcp-server | `7517089ca909fcdc61a083759f1729407de1a667` | MIT | REA_VERIFIED | permissive | apps/orcel-mcp | P1 |
| C | tinyfish-cookbook | tinyfish-io/tinyfish-cookbook | `b7d98b7a69dc681aca30ffb369bfd78ba059862c` | MIT | SOURCE_ACQUIRED | permissive | tests/benchmarks | P3 |
| C | tinyfish-web-agent-integrations | tinyfish-io/tinyfish-web-agent-integrations | `73402549446f4fb739a8a3b93073c0b0b1155a45` | MIT + per-directory terms | SOURCE_ACQUIRED | permissive | packages/orcel-sdk-py (new) | P3 |
| C | agentql | tinyfish-io/agentql | `d6951d214c7ed84f1a53657f801f2a8dd65c91c7` | MIT | SOURCE_ACQUIRED | permissive | apps/orcel-browser-worker (reference only) | P3 |
| C | agentql-mcp | tinyfish-io/agentql-mcp | `8d3ea0f04af7fae065b53cdde9e5effaafdc0b6a` | MIT | SOURCE_ACQUIRED | permissive | apps/orcel-mcp | P3 |
| C | agentql-integrations | tinyfish-io/agentql-integrations | `cbb97f094c08a191dcab015a218afd1d91ed09c1` | MIT + per-directory terms | SOURCE_ACQUIRED | permissive | packages/orcel-sdk-py (new) | P3 |
| C | bigset-oss | tinyfish-io/bigset-oss | `c6611085e2527bc0a5419db400caafa95abc751f` | AGPL-3.0 | SOURCE_ACQUIRED | copyleft, separate component | none (reference only) | P3 |
| C | tf-playwright-stealth | tinyfish-io/tf-playwright-stealth | `e9adc20a53253d2043bd12b1d73f75bdb1fe5271` | MIT | REA_VERIFIED | permissive | apps/orcel-browser-worker | P2 |
| D | microsoft Hybrid-Computer-Use | microsoft/Hybrid-Computer-Use | `00eaeebe8ac0d275e46f875bdb5347e5f326faa1` | MIT + per-directory terms | SOURCE_ACQUIRED | permissive | apps/orcel-computer-host | P0 |
| D | simular-ai Agent-S (S2/S3/S4) | simular-ai/Agent-S | `0fff0e634869dab72027435b4586e62300185d41` | Apache-2.0 + per-directory terms | SOURCE_ACQUIRED | permissive | apps/orcel-agent | P0 |
| D | browserbase/stagehand | browserbase/stagehand | `82827a219512f0399cb159720a63f7d271d21480` | MIT + per-directory terms | SOURCE_ACQUIRED | permissive | apps/orcel-browser-worker | P0 |
| D | trycua/cua | trycua/cua | `494c3cdcc2768033bd75ba34745ce810fc55052d` | MIT + per-directory terms | TESTED | mixed per directory | apps/orcel-native-host | P1 |
| D | microsoft/OmniParser | microsoft/OmniParser | `354021201345a96178360b28733573e27269f2de` | CC-BY-4.0 | NOT_ACQUIRED | mixed per directory | apps/orcel-vision (new) | P0 |
| D | microsoft/playwright-mcp | microsoft/playwright-mcp | `a62ea28698af6d9bc89438bcec50c63377cef957` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | permissive | apps/orcel-mcp | P0 |
| D | OpenAdaptAI/OpenAdapt | OpenAdaptAI/OpenAdapt | `2e98be86a802b0867b9513491c5f368ba98811d0` | MIT + per-directory terms | NOT_ACQUIRED | permissive | apps/orcel-agent | P1 |
| D | OpenAdaptAI/openadapt-flow | OpenAdaptAI/openadapt-flow (archived) | `a8ef4744c47af5f17eaf946e6f5b945b97aa2457` | MIT + per-directory terms | NOT_ACQUIRED | permissive | apps/orcel-agent | P0 |
| D | anthropics/claude-quickstarts | anthropics/claude-quickstarts | `4a4224bdf0e9cfb3332167b69c90457403813625` | MIT + per-directory terms | NOT_ACQUIRED | permissive | apps/orcel-agent | P2 |
| D | alibaba/page-agent | alibaba/page-agent | `9eb6b6646500264d9034dd466a4270cb9fc1ef1e` | MIT | NOT_ACQUIRED | permissive | apps/orcel-browser-worker | P1 |
| D | lightpanda-io/browser | lightpanda-io/browser | `88fb36db0a6ce4c0011c6cb31cf53e3d3b4a4fbf` | AGPL-3.0 + per-directory terms | NOT_ACQUIRED | copyleft, separate component | third_party/lightpanda (new) | P2 |
| D | browseros-ai/BrowserOS | browseros-ai/BrowserOS | `81c8f6a35c0ae5a2fe8c7a1d3f7e871aa207f24c` | AGPL-3.0 + per-directory terms | NOT_ACQUIRED | copyleft, separate component | apps/orcel-mcp (MIT subpackages only) | P2 |
| D | Skyvern-AI/skyvern | Skyvern-AI/skyvern | `3e8571338011b8df1c9c9db8fb20856de7b9d13f` | AGPL-3.0 | NOT_ACQUIRED | copyleft, separate component | none (reference only) | P3 |
| E | Genymobile/scrcpy | Genymobile/scrcpy | `a60891aea193d92e7e5c3942700eca63f9d19a5f` | Apache-2.0 | NOT_ACQUIRED | permissive | crates/orcel-provider-mobile (new) | P1 |
| E | appium/appium | appium/appium | `51cfc7b292ab834a4155525927139a62e1e67aec` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | permissive | crates/orcel-provider-mobile (new) | P1 |
| E | X-PLUG/MobileAgent | X-PLUG/MobileAgent | `c4cd0a8f9ddedad24dd8a3daf3a56ca69343849f` | MIT + per-directory terms | NOT_ACQUIRED | permissive | apps/orcel-agent | P1 |
| E | droidrun (verify org) | droidrun/mobilerun | `e34004270a9d7b68824b94a3a5ba6698cefea69d` | MIT | NOT_ACQUIRED | permissive | crates/orcel-provider-mobile (new) | P1 |
| E | mobile-dev-inc/Maestro | mobile-dev-inc/Maestro | `0ccf5a9c5b1c48d4cb6211d9060d537e04745107` | Apache-2.0 | NOT_ACQUIRED | permissive | tests/mobile-flows (new) | P1 |
| F | Ylianst/MeshCentral | Ylianst/MeshCentral | `03fe8529dc8ef0607ea6af78152dba8c70969464` | Apache-2.0 + per-directory terms | NOT_ACQUIRED | mixed per directory | apps/orcel-relay | P2 |
| F | rustdesk/rustdesk | rustdesk/rustdesk | `3e953e886a874956d8351d6c25e340ea82dd2343` | AGPL-3.0 + per-directory terms | NOT_ACQUIRED | copyleft, separate component | third_party/rustdesk (new) | P2 |
| F | OpenSandbox (verify org) | opensandbox-group/OpenSandbox | `44e79a2dc3c99e26d82aa87fe13a73537d7e7812` | Apache-2.0 | NOT_ACQUIRED | permissive | apps/orcel-sandbox (new) | P0 |
| F | CopilotKit/OpenBot | CopilotKit/OpenBot | `d88ff75ed691ab7a415c5c2d099371865c8ff61b` | MIT | NOT_ACQUIRED | permissive | apps/orcel-control-room | P2 |
| G | NousResearch/hermes-agent | NousResearch/hermes-agent | `081e8d9b75b2bedae297a89232b04ef9be7b26a0` | MIT + per-directory terms | NOT_ACQUIRED | permissive | apps/orcel-agent | P1 |
| G | screenpipe | screenpipe/screenpipe | `b8f09c879fddc807e9fd3aae7aae4f1a0accb1f6` | Screenpipe Commercial License | NOT_ACQUIRED | **needs grant evidence** | apps/orcel-native-host (reference only) | P3 |
| H | xlang-ai/OSWorld | xlang-ai/OSWorld | `5123bfdbbc34b947bcffcff564abc62d0ab7072d` | Apache-2.0 | NOT_ACQUIRED | permissive | tests/benchmarks | P1 |
| H | ServiceNow/BrowserGym | ServiceNow/BrowserGym | `27a90ce815098f43414e93491e06907af468e45b` | Apache-2.0 | NOT_ACQUIRED | permissive | tests/benchmarks | P2 |

Donors already tracked by Orcel (outside the 50):

| Donor | Pin | Licence | Status | Public redistribution | Orcel |
| --- | --- | --- | --- | --- | --- |
| vercel-labs/agent-browser | `b06e2533ba9b3823b8a96c859d455cb55f4d7893` | Apache-2.0; cli/src/native/a11y/axe.min.js MPL-2.0 | NOT_ACQUIRED | permissive | crates/orcel-browser-host/src/transfers.rs, crates/orcel-policy |
| vercel-labs/remote-agent-browser | `8770ea28f3ab0e8822e104e12e0efb65339d235b` | No LICENSE file; package.json declares MIT; GitHub reports no licence | NOT_ACQUIRED | **needs grant evidence** | none |
| wangzan101/Mika | `e956f5529ad4cfd7881aafaa630318097949f56a` | Apache-2.0 + NOTICE; bundled PRoot GPL-2.0-or-later, talloc LGPL-3.0-or-later, Alpine rootfs mixed | NOT_ACQUIRED | mixed per directory | none |
| phone-harness/phone-harness | `4bebff105af853215fb74c958c2c5e78bc275be2` | MIT | NOT_ACQUIRED | permissive | none |
| netease-uuyc/uuremote-integration-guide | `181dee4540a8e4161a65e1053fbcf6ad223d24f8` | MIT (org not GitHub-verified) | NOT_ACQUIRED | permissive | none |
| UU Remote (NetEase) | none | Proprietary; no official source repository found | NOT_ACQUIRED | **needs grant evidence** | none |
| Vercel agent-use | none | Unknown; repository not identified | NOT_ACQUIRED | **needs grant evidence** | none |
| bytedance/deer-flow | `81e1ab8dcc86574cfac0ecdfe3636b775a08c567` | MIT | TESTED | permissive | apps/orcel-agent/orcel_agent (tests: apps/orcel-agent/tests) |
| BuilderIO/agent-native | `9c277b79cb87eb27da538e572dd710986e2fa06d` | MIT | TESTED | permissive | apps/orcel-control-room/src/agentkit; crates/orcel-journal/src/resume.rs (unit tests in the file) |
| unclecode/crawl4ai | `94b67888ca8b335ff2121423a50e06dd27661922` | Apache-2.0 with an attribution requirement | TESTED | permissive | apps/orcel-browser-worker/src/extract/relevance.ts (relevance.test.ts) |
| Panniantong/Agent-Reach | `a19a171fa980a0785849596492e0af4db800c82f` | MIT | TESTED | permissive | crates/orceld/src/search.rs (crates/orceld/tests/wi06_search.rs) |
| WebMCP-org/npm-packages | `7db816b5a280c2d1d4b86559696e993c497c021a` | MIT | TESTED | permissive | apps/orcel-browser-worker/src/webmcp (declarative.test.ts) |
| J-F-Liu/lopdf | `version 0.45.0` | MIT | TESTED | permissive | apps/orcel-doc-parser/third_party/lopdf (apps/orcel-doc-parser tests) |

### 8.2 Resolution notes

- **Vercel browser-use/agent-desktop** (NEEDS_FOUNDER_CONFIRMATION): The name mixes two organisations. Candidates: vercel-labs/agent-desktop (Apache-2.0, Rust computer-use CLI; admitted as a candidate by FD-UP-3) and browser-use/desktop (MIT, TypeScript desktop app, pinned f073b7574f7927185ebbebd87556391d5cb0cfd1). Neither is substituted for the other; vercel-labs/agent-desktop is the recorded candidate until the founder confirms.
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
- **Vercel agent-use** (tracked, NEEDS_FOUNDER_CONFIRMATION): still unidentified; `vercel-labs/agent-use` returns 404.

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

### 8.4 PUBLIC_REDISTRIBUTION_NEEDS_GRANT_EVIDENCE

Publishing copied code from these sources in this public repository needs the stated evidence. Each needs a written
grant from the copyright holder covering redistribution under Orcel's terms, naming the files and the pinned commit,
stored under `docs/orcel/grants/` with the signer's identity. The founder's owner-asserted authorization is recorded but
is not that evidence.

- **fleetdm/fleet** (MIT + per-directory terms). Restricted part: ee/ (Fleet Enterprise Edition licence). Evidence: grant from Fleet Device Management Inc. for any file under ee/.
- **exa-labs/openapi-spec** (NONE). Evidence: grant from Exa Labs, Inc. for the openapi-spec files.
- **exa-labs/exa-deepseek-chat** (NONE). Evidence: grant from Exa Labs, Inc. for any file of exa-deepseek-chat.
- **adisinghstudent/exa-browser** (NONE). Evidence: grant from the GitHub user adisinghstudent for any file of exa-browser.
- **trycua/cua** (MIT + per-directory terms). Restricted part: apps/cua-spaces*, examples/{cua-bots-ios,cua-bots-macos,infinite-canvas-swift,openkoalabot-example-swift,openkoalabot-example-tauri}, libs/{cua-driver-bench,cua-spacesd,spaces-app-swift,spaces-notch-swift}, libs/cua/bench/streaming, libs/cua/crates/* (20 crates listed) (FSL-1.1-MIT). Evidence: grant from Cua AI, Inc. for the FSL-1.1-MIT directories listed above (FSL forbids competing use until each version converts to MIT two years after release).
- **screenpipe/screenpipe** (Screenpipe Commercial License). Evidence: grant from Negentropy Labs, Inc. (dba Screenpipe) for any screenpipe file, and commercial and competing use.
- **vercel-labs/remote-agent-browser** (No LICENSE file; package.json declares MIT; GitHub reports no licence). Evidence: grant from Vercel Inc. for the remote-agent-browser files (or a committed LICENSE file at a pinned commit).
- **UU Remote (NetEase)** (Proprietary; no official source repository found). Evidence: grant from NetEase for any UU Remote source or binary.
- **Vercel agent-use** (Unknown; repository not identified). Evidence: grant from the unidentified copyright holder for any file.

### 8.5 Copyleft: separate components only

AGPL/GPL code may be published only under its own licence as a separate component (own process and package, notices and
source offer, no linking into the Apache-2.0 core):

- firecrawl/firecrawl: whole repository.
- tinyfish-io/bigset-oss: whole repository.
- trycua/cua: libs/python/som (AGPL-3.0).
- microsoft/OmniParser: Ultralytics-based icon_detect weights (v1, v1.5, v2) and the ultralytics==8.3.70 dependency (AGPL-3.0).
- lightpanda-io/browser: whole repository.
- browseros-ai/BrowserOS: whole repository.
- Skyvern-AI/skyvern: whole repository.
- Ylianst/MeshCentral: rdp/, public/mstsc/ (GPL-3.0).
- rustdesk/rustdesk: whole repository.
- wangzan101/Mika: PRoot, talloc, Alpine rootfs (GPL-2.0+, LGPL-3.0+, mixed).

### 8.6 Priority 0: highest-value immediately transplantable modules

Ordered by value against Orcel's current gaps. The listed paths carry MIT, Apache-2.0 or CC-BY-4.0 terms (see the
cautions below); each still needs its own activated grain, provenance file and tests before any copy lands on main.

1. **Stale-reference rejection and reference minting for desktop elements** (hcu, `microsoft/Hybrid-Computer-Use` at `00eaeebe8ac0d275e46f875bdb5347e5f326faa1`, SOURCE_ACQUIRED) to apps/orcel-computer-host (Go to Go, same language; denied by default, test UI only first):
   `computer-use/internal/core/ax_ref_registry.go`, `computer-use/internal/core/ax_ref_minting.go`, `computer-use/internal/core/ax_ref_provider_continuity.go`, `computer-use/internal/core/ax_window_ref_registry.go`, `computer-use/internal/core/ax_app_ref_registry.go`, `computer-use/internal/core/ax_ref_snapshot_assignment.go`.
2. **Compact AX diff after each action, batched actions with readback** (hcu, `microsoft/Hybrid-Computer-Use` at `00eaeebe8ac0d275e46f875bdb5347e5f326faa1`, SOURCE_ACQUIRED) to apps/orcel-computer-host:
   `computer-use/internal/core/ax_semantic_diff.go`, `computer-use/internal/core/ax_semantic_diff_render.go`, `computer-use/internal/core/ax_batch.go`, `computer-use/internal/core/ax_batch_plan.go`, `computer-use/internal/core/ax_batch_observation.go`, `computer-use/internal/core/ax_action_readback.go`, `computer-use/internal/core/ax_action_stabilization.go`.
3. **Local screen parsing for vision fallback (icon detection, OCR, set-of-marks)** (omniparser, `microsoft/OmniParser` at `354021201345a96178360b28733573e27269f2de`, NOT_ACQUIRED) to apps/orcel-vision (new, contained sidecar; only icon_detect_v3 + MIT caption weights; ultralytics and AGPL detectors excluded or isolated):
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

Licence cautions for this list: OmniParser's repository is CC-BY-4.0 (attribution), its `requirements.txt` pins
`ultralytics==8.3.70` (AGPL-3.0) and older icon detectors are AGPL-3.0, so Orcel takes the code paths above with the
MIT `icon_detect_v3` and MIT caption weights only, or isolates the AGPL parts. HCU files under `osworld-overlay/` and
`ax_records.py` carry Apache-2.0 and a Playwright NOTICE. OpenAdapt Flow is taken from `OpenAdaptAI/OpenAdapt`
`packages/flow` because `openadapt-flow` is archived; its AGPL benchmark configuration is fetched at run time and stays out.

### 8.7 Pin drift since 2026-11-16

- `firecrawl/firecrawl`: `42f4d669954649ce33466a2a50e8215c7f1f4d1c` to `98a5630a0b7ad3d58653dfe4ceb21d444dd8e2d2`.
- `fleetdm/fleet`: `99e64e6bbee9e7a9b5334fea2527303992f747f7` to `6070ad340095cd9dbfdef75fb6d18c9ba14c4b82`.
- `vercel-labs/agent-browser`: `53384771fbafc261ba67608ac806dd5aa70b84f0` to `b06e2533ba9b3823b8a96c859d455cb55f4d7893`.
- Sections 1 to 7 keep the 2026-11-16 pins; the ledger records the new HEADs. Every other pre-existing pin is unchanged.
