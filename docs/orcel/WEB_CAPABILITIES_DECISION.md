# Web capabilities decision: WebMCP and native web extraction

Status: **ADOPTED founder decisions (2026-10-11)**, recorded here for review. This document grants no authority: every capability below still needs its own exact-head qualified implementation PR inside SG-000108, and every new tool needs its own approval policy and tests.

## Founder decisions

1. **Firecrawl: Orcel-native rebuild, revised 2026-10-12.**
   - Firecrawl's engine (`apps/api`, `apps/playwright-service-ts`, `apps/go-html-to-md-service`) is AGPL-3.0. Orcel is Apache-2.0.
   - **Revised by the founder decision of 2026-10-12** (`SOURCE_PERMISSIONS.md`): the founder attests official permission to copy and use Firecrawl's source. Firecrawl modules may now be copied and adapted module by module under source admission; the permission gate is satisfied by the founder authorization of 2026-10-13 (`docs/orcel/grants/2026-10-13-founder-source-authorization.md`).
   - Scrape, map, crawl and Markdown stay Orcel's own pipeline behind SG-000075 (no second HTTP client, no hosted service). Firecrawl code is taken where a module fits that pipeline: first, its Rust link and URL filtering, robots.txt handling and sitemap parsing (`apps/api/native/src/crawler.rs`) for the slice 7 host queue (`BROWSER_AGENT_DONORS_DECISION.md`).
2. **WebMCP: amend SG-000108.**
   - WebMCP becomes later SG-000108 slices on the isolated browser worker: read-only discovery first, then approval-gated execution.
   - No new active grain is opened. The founder-approved parallel pair {SG-000096, SG-000108} and its tests are unchanged.

## Donor pins

All donors are cloned read-only at exact commits; no donor script is run.

| Donor | Commit | License | Disposition |
|---|---|---|---|
| [webmachinelearning/webmcp](https://github.com/webmachinelearning/webmcp/tree/d0e4e0e0f039358cc9d93f90074116622bfebd53) | `d0e4e0e0f039358cc9d93f90074116622bfebd53` | W3C Software and Document License | **Specification reference.** It defines `document.modelContext` (`registerTool`, `getTools`, `executeTool`), the declarative form tools and the security and privacy questionnaire. It contains no implementation code. |
| [WebMCP-org/npm-packages](https://github.com/WebMCP-org/npm-packages/tree/7db816b5a280c2d1d4b86559696e993c497c021a) (MCP-B 6.0.0) | `7db816b5a280c2d1d4b86559696e993c497c021a` | MIT, © 2025 mcp-b contributors | **Adapt selected modules** (see the matrix below). |
| [ripulio/web-mcp](https://github.com/ripulio/web-mcp/tree/4921a1834446440c4d1c6867d98d0ff662ea6231) | `4921a1834446440c4d1c6867d98d0ff662ea6231` | MIT, © 2025 Ripul | **Reference.** Its polyfill (0.0.2), extension and WebSocket server duplicate MCP-B in a less mature form. |
| [firecrawl/firecrawl](https://github.com/firecrawl/firecrawl/tree/f84845c864b6e2af22791c18fcf89ac2a21f1434) | `f84845c864b6e2af22791c18fcf89ac2a21f1434` | AGPL-3.0 at the root; the JS, Python, Ruby and Elixir SDK directories carry MIT LICENSE files (python-sdk `setup.py` says GPLv3; the Go, Java and .NET SDKs have no LICENSE file) | **Adapt under the founder's permission** (decision 1, revised 2026-10-12): engine modules such as `apps/api/native/src/crawler.rs`. No SDK is used: they are clients of the hosted or self-hosted API. |

## What Orcel already has (and must not rebuild)

- **The isolated browser stack.**
  - The Rust host is the policy authority (SG-000074..SG-000079, SG-000108 slice 1).
  - A private Playwright-core worker sits behind a closed, versioned protocol (slice 2a).
  - The launcher confines the worker in a Job Object, restricts handle inheritance and verifies the argv (slice 2b-ii-a, PR #297).
- **Network policy.** SG-000075 admitted destinations, the no-route proxy, host-resolver pinning, and refusal of QUIC and WebRTC.
- **Observation and actuation.** Generation-bound observation (SG-000077) and typed actuation through the approval broker.
- **WebMCP in the engine.** `@playwright/mcp` already lists and calls WebMCP tools (`REA_DEEP_INVESTIGATION.md`, R9). Edge 155 accepted the CDP `WebMCP` domain, but a page that registered a tool only through the native API exposed no `document.modelContext` without the experimental flag.

## Approach per subsystem

The three approaches considered:
- **(A)** copy large portions of a donor;
- **(B)** transplant selected modules;
- **(C)** use donor packages behind an Orcel adapter.

| Subsystem | Choice | Why |
|---|---|---|
| WebMCP discovery | **B** | MCP-B's declarative-form recognition (`webmcp-polyfill/src/declarative-forms.ts`) and its schema normalisation (`webmcp-ts-sdk/src/json-schema.ts`, `normalize.ts`) are mature and MIT. They are adapted into one fixed, host-constructed, read-only evaluation that returns data and leaves nothing in the page. Installing the polyfill (A or C) would instead persistently mutate every page: it defines `document.modelContext`, registers listeners and observers, and changes form behaviour. It would also add `@modelcontextprotocol/*` runtime dependencies beyond the single admitted dependency (playwright-core). Neither approach evaluates caller-, model- or page-supplied script; the difference is persistence and page mutation, and the fixed read-only evaluation is the one that keeps pages unchanged. |
| WebMCP execution | **Native, in the worker and host protocol** | The call is one fixed worker function: `document.modelContext.executeTool` for a discovered, generation-bound tool. Authorisation, argument validation, approval and result bounding are done by the Rust host. No donor code decides authority. |
| WebMCP bridge and relay | **Rejected** | `@mcp-b/webmcp-local-relay` (`ws`), the browser extensions and ripulio's WebSocket server would add a second channel to the browser. Orcel's only channel is the host-owned worker pipe. |
| Page reading fallback | **Existing** | SG-000077 observation over Playwright accessibility snapshots. `@mcp-b/smart-dom-reader` overlaps with it and is a reference only. |
| Scrape and Markdown | **Native rebuild (decision 1)** | Built in the worker from the observed DOM, through a permissively licensed HTML-to-Markdown and readability path. That dependency is admitted separately, with integrity, licence and SBOM records. |
| Map and crawl | **Native rebuild (decision 1)** | A queue owned by the Rust host. It deduplicates on normalised URLs and enforces depth and origin scope, page, byte and time budgets, cancellation and bounded retries. Every fetch is a navigation of the isolated browser under SG-000075, so there is no second HTTP client. |

## Authority and security boundaries

1. **A page advertising a tool grants nothing.**
   - Tool names, descriptions, schemas, arguments and results are untrusted page data, labelled as page-provided, with every size bounded.
   - Descriptions are never placed where a model reads them as instructions.
2. **The host keeps the authority.**
   - Discovery returns a generation-bound tool identity (page, document and tool generation).
   - Execution requires a fresh identity, host-side validation of the arguments against a bounded subset of the advertised schema, and approval through the existing broker, policy and approval paths as an actuation.
   - The call carries a deadline and can be cancelled.
3. **There is one network boundary.**
   - Scrape, map and crawl reach the web only as browser navigations under SG-000075. That covers admitted public HTTPS, pinned resolution, no loopback, private, link-local or metadata addresses, a re-check on every redirect, and refusal of other schemes.
   - No Node or Rust HTTP client is added for web content.
   - If enforcement cannot be shown for a request, it fails closed.
4. **There is one browser session model.**
   - Every capability uses the supervised worker and its Orcel-owned profile.
   - There is no second engine, extension or debugging port.

## Traceability matrix

| Donor module (pinned) | Orcel destination | Approach | Required modifications | Verification |
|---|---|---|---|---|
| MCP-B `packages/webmcp-polyfill/src/declarative-forms.ts` | `apps/orcel-browser-worker/src/webmcp/declarative.ts` | Adapt (MIT notice kept) | Read only: no `registerTool`, no listeners, no mutation. Extracts the declared tool name, description and input fields into a bounded, typed record. Product names changed to Orcel. | The donor's tests are ported where applicable. Fixture pages cover valid, oversized, duplicate and hostile declarations. |
| MCP-B `packages/webmcp-ts-sdk/src/json-schema.ts`, `normalize.ts` | `apps/orcel-browser-worker/src/webmcp/schema.ts` | Adapt (MIT notice kept) | Restricted to a bounded subset (types, `properties`, `required`, `enum`, string and number bounds). Anything outside the subset is refused. Plain TypeScript, without `zod` or standard-schema. | Unit tests, including the donor's cases. A Rust host validator for the same subset, checked against shared vectors. |
| W3C WebMCP spec `index.bs`, `declarative-api-explainer.md`, `security-privacy-questionnaire.md` | `docs/security/SG-000108_WEBMCP.md` | Specification reference | Not applicable | Conformance cases for `getTools` and `executeTool` behaviour on fixture pages, with native support and without. |
| ripulio `packages/polyfill` (npm `webmcp-polyfill` 0.0.2) | none | Reference | Not applicable | Not applicable |
| Firecrawl `apps/api` scrape, map and crawl behaviour; `apps/api/native/src/crawler.rs` | Worker extraction and the host crawl queue | Adapt under founder permission (decision 1, revised 2026-10-12) | Copied code keeps attribution, the AGPL notice and the permission reference; its crates are admitted separately | Firecrawl's documented features and limits are mapped to Orcel tests. Fixture site at loopback through the test-only pin. |

The donor integration record (copied paths, commits, modifications, notices) is kept in `THIRD_PARTY_NOTICES` and the per-file headers whenever donor code is adapted.

## Slice plan (inside SG-000108)

1. **2b-ii-b** (already planned): HTTPS-fixture probes (QUIC, WebTransport, service-worker block), a real pinned public name, the job process limit under a heavy page, and worker packaging.
2. **3: governed journey.** Navigation, observation, typed actuation and a create-only PDF download, through the host policies and the approval broker. This is SG-000108's `done_when`.
3. **4: WebMCP discovery (read only).**
   - Detect native `document.modelContext` and the declarative form tools.
   - Return bounded, generation-bound, untrusted tool records.
   - Report typed unavailable when a page has no WebMCP, and fall back to observation.
4. **5: WebMCP execution.**
   - Host-side schema validation, approval, deadline and cancellation.
   - Results are bounded and untrusted.
   - Negative controls: a stale generation, an undeclared tool, a schema violation, a denied approval and a hostile description.
5. **6: native extraction.** Scrape to Markdown, HTML and structured output of the observed page. The extraction dependency is admitted separately. *As built:* Markdown only, through Orcel's own port of the browser-use pipeline, so no dependency was admitted. HTML is not handed out, and structured data crosses on execution results. See `docs/security/SG-000108_EXTRACTION.md`.
6. **7: map and crawl.** The host queue described above. *As built:* an Orcel-native queue (Firecrawl as behavioural reference only, no code copied) over one admitted destination; see `docs/security/SG-000108_CRAWL.md`. Negative controls cover localhost, private, link-local and metadata addresses, redirect chains, DNS rebinding through the pin, URL parser confusion, other schemes, credentials in URLs, cross-origin scope, cancellation and timeouts.

Each slice runs the full review gates (CI, native Windows, independent code review, OCR delegation, a PStack-role judge, Graft; before 2026-11-23 also Jev) and merges with a normal merge commit. No slice may add an MCP-facing tool before its approval policy is qualified.

## Open risks

- Native `document.modelContext` needs an experimental flag in Edge 155, and SG-000074's argv allowlist does not include it. Discovery must therefore work without the flag (declarative forms, and pages that ship their own polyfill), or the flag must be admitted as a reviewed argv amendment.
- **Page code runs in response to Orcel's calls.** `executeTool` runs the page-registered handler, and on pages that ship their own polyfill, discovery (`getTools`) also calls a page-defined function. That code is page-supplied, even though Orcel's own evaluation is fixed. Before slices 4 and 5 qualify, they must amend the SG-000108 invariant's wording explicitly to cover this, for discovery calls as well as `executeTool`. Orcel never evaluates page-, model- or caller-supplied script; it may invoke a page's own declared handler only through the approval-gated actuation path, and treats its result as untrusted. Slice 5 must also cite the SG-000079 exposure policy, because page tools are exposed to a model.
- The extraction dependency (HTML to Markdown, readability) is not chosen yet. Its admission needs the same integrity, licence and SBOM discipline as playwright-core.
