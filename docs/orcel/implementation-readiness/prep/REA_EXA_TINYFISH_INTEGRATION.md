# REA Exa/TinyFish results: integration into Orcel

Status: design note for packet P-1 (landed as `crates/orcel-search`) and the plan for P-0, P-2, P-3 and P-4.
Base: `plan/unified-activation` (PR #789, `UNIFIED_INTEGRATION_SPEC.md`). Date: 2026-11-17.

## 1. What the REA delivered, and what it did not

The founder's REA run (workspace `D:\Orcel-REA`, reports `00` to `08`, `CURRENT_STATE.md`) cost $0 and produced:

- Pinned, read-only clones of the public Exa repositories (7 public, 1 third-party) and TinyFish repositories (8),
  inventoried in `01_exa_source_inventory.json`, `04_tinyfish_source_inventory.json` and
  `source_clone_manifest_machine.json`.
- A TypeScript proof of concept, `orcel-poc`, whose engine, text, ingest and server code is Orcel-authored against the
  public Exa contract (module map: INDEPENDENT). 48 of 48 tests passed, including the unmodified `exa-js@2.28.0` client
  against its loopback server.
- A transplant plan with packets P-0 to P-4 (`07_orcel_transplant_plan.md`).

Recorded honestly, not available and not claimed:

- **Semantic search.** No embedding model or neural retriever exists locally. The engine is lexical (BM25 + phrase +
  proximity) and reports `semantic: false` in its capabilities and a notice on every `auto`/`neural` search.
- **Exa's ranker, live crawl, subpages, Websets, monitors scheduler and hosted agent.** Not public. Hosted-only routes
  answer a typed `501 not_implemented`.
- **TinyFish's hosted backend** (agent runtime, browser fleet, anti-bot service, hosted rendering, monitors). Not
  public; only clients, integrations, a proxy, a stealth library and one AGPL dataset app are.
- **Private source.** None was accessed: the configured identity has no membership in `exa-labs` or `tinyfish-io`
  (`00_access_and_identity.md`). Nothing in Orcel depends on private source.

Licences: this packet copies no donor code. `exa-browser` (third-party, no licence), `exa-deepseek-chat` and
`openapi-spec` (no licence) were used as reference only, and nothing from `bigset-oss` (AGPL-3.0) is linked or copied.
The founder's decision of 2026-11-17 is that licences no longer block copying; provenance records stay mandatory, so
any later copy carries its repository, commit, paths, licence and notice through the WP1-01 provenance gate. No
telemetry is carried over (Exa `trackMCP`, TinyFish `connect-event`). Nothing calls Exa's or TinyFish's hosted APIs by
default.

## 2. Reconciling the REA plan with Orcel's architecture

The REA plan assumed `orcel-poc` would grow its own HTTP server, MCP server and fetcher. The reviewed spec does not
allow that: `orceld` is the sole authority (C-06), fronts are stateless, and network fetch is authority that goes
through the governed transport (SG-000040) and the WP1-08 fetch engine (C-13). So the REA code is split by authority:

| REA piece | In Orcel |
| --- | --- |
| Pure engine: BM25, highlights, extractive answers, findSimilar, extraction, categories, hashes | `crates/orcel-search` (this packet), inert library |
| PoC `fetch` in `ingest.ts` | Not ported. The governed fetch in `orceld` fills `FetchedResponse`/`TransportFailure`; `orcel-search::ingest` turns it into a document or a typed error |
| PoC HTTP server (`exa-compat.ts`, `cli.ts`) | Not ported as a server. Its route table and error policy are data in `orcel-search::surface`; an `orceld` loopback route mounts them later |
| PoC `ExaJsPort` (BYOK cloud) | Not ported. A bring-your-own-key cloud path belongs to `crates/orceld/src/search.rs` providers, explicit opt-in only |
| PoC auth (`x-api-key`, Bearer, 401) | Moves to `orceld`'s per-client REST tokens (WP1-07) |

### P-0: provenance and licence gate

P-0 folds into **WP1-01** (licence and provenance gates). When WP1-01 lands, add donor registry entries for the Exa and
TinyFish repositories with the pins in `source_clone_manifest_machine.json` and their licence classes (MIT; no-licence
reference-only; AGPL never linked), and add `crates/orcel-search` to the per-crate licence check. P-1 copies no donor
code, so it needs no `PROVENANCE.json` beyond its test fixtures (`crates/orcel-search/tests/fixtures/PROVENANCE.json`,
Orcel-authored pages with SHA-256 pins). Interface facts used: Exa's response field names as the MIT `exa-js` client
reads them (`exa-labs/exa-js@ec25f401`), and TinyFish's per-URL fetch error names (REA T20).

### P-1: the local search engine (this packet)

`crates/orcel-search`, Apache-2.0, depends only on `serde`, `serde_json` and `sha2` from the root lockfile. It has no
network, listener, process or file access and no `orceld` wiring yet. It holds:

- the ported engine (search with domain, category, date and text filters; contents; extractive answers with citations
  and abstention; term-vector findSimilar; sentence highlights with budgets);
- HTML to text, markdown and typed blocks, with metadata, JSON-LD and category inference (a small tree builder replaces
  `linkedom`);
- provenance (`docId`, URL, SHA-256 content hash, origin, retrieval time, `extractive: true`) and the capability flags;
- the Exa-shaped envelopes, including `statuses[]` with typed per-URL errors, and the route table with typed `501`;
- the remaining P-1 items: `page`/`offset` pagination, batch contents of 1 to 10 URLs or ids with per-URL typed errors,
  `format: markdown | html | json`, the ingest error taxonomy (`bot_blocked`, `timeout`, `target_unreachable`,
  `page_not_found`, `target_http_error`, plus the refusals `unsupported_scheme`, `unsupported_content_type`,
  `empty_content`), and an ingest record with `ETag`, `Last-Modified`, `If-None-Match`/`If-Modified-Since`
  conditional-request headers, `304` revalidation and TTL freshness.

Dependency direction: `orcel-search` is a leaf below `orceld` (like `orcel-web`, it depends on no Orcel crate and no
`apps/*`, `tests/*`, `packages/*` or `third_party/*` unit). Add it to `crates/orceld/tests/dependency_direction.rs`
when WP1-01 creates that test: "`orcel-search` depends only on serde, serde_json and sha2".

### P-2: MCP tools

`orcel_search`, `orcel_fetch`, `orcel_answer` and `orcel_similar` go into the existing `apps/orcel-mcp` catalog and
dispatch through `orceld` (after WP1-06 dispatch and WP1-07 MCP/REST). `orcel_fetch` for a URL that is not in the corpus
runs the governed fetch with the same SOFT approval as `web_scrape`, then `orcel-search::ingest`; the others read the
corpus and need no network. No separate MCP server is started. From the donors, only patterns are reused: the TinyFish
proxy's error taxonomy and SSE relay shape and Exa's tool registry layout (MIT, with notices if any line is copied).

### Exa-compatible REST

The Exa shape (`POST /search`, `/contents`, `/answer`, `/findSimilar`, `GET /v1/capabilities`) becomes an `orceld`
loopback route beside the Firecrawl REST routes of WP1-07, with the same per-client REST tokens, so the unmodified
`exa-js` client works by setting `baseURL` to the loopback address. The PoC's live `exa-js` contract test moves there,
next to `tests/firecrawl-compat`.

### P-3: monitors

Monitors run on `orcel-jobs` (WP1-04) for scheduling, budgets and the store, and reuse the existing
`crates/orcel-browser-host/src/change_tracking.rs` for diffs. A run is a governed fetch revalidated with the ingest
record's conditional-request headers (a `304` is an unchanged run) or a local search, compared by content hash.
Webhooks stay local by default.

### P-4: browser and agent

Browser sessions use the existing browser host with Obscura and the Chromium fallback (track B). The MIT
`tf-playwright-stealth` patches may be adopted only as an opt-in sensitive feature behind the 4.16 gate (off by
default, per-client permission, audited), never as CAPTCHA solving or access-control bypass, which SG-000133 excludes.
The run surface (`/agent/runs`) answers `501` until Orcel's own planner exists.

## 3. Grain scope

This work extends **SG-000133** (web intelligence) beyond Firecrawl parity. The P-1 crate is inert (no tool, route,
listener, network or authority), so this PR does not amend the grain. The amendment belongs with the dispatch packet
that first wires the crate into `orceld` (MCP tools or the loopback route). Recommended line for the grain's scope:

> Include: Exa-compatible local search (REA P-1 to P-4): the pure `crates/orcel-search` engine (lexical, $0, no
> network), its MCP tools `orcel_search`/`orcel_fetch`/`orcel_answer`/`orcel_similar` and an Exa-shaped `orceld`
> loopback REST route dispatched through `orceld`, with fetches only through the governed transport and no default
> call to Exa or TinyFish hosted APIs.

## 4. Port map and parity

| PoC file | Rust module |
| --- | --- |
| `src/text/tokenize.ts` | `crates/orcel-search/src/tokenize.rs` |
| `src/engine/bm25.ts` | `src/bm25.rs` |
| `src/text/highlights.ts` | `src/highlights.rs` |
| `src/text/extract.ts` | `src/extract.rs` and `src/html.rs` (replaces `linkedom`) |
| `src/engine/engine.ts` | `src/engine.rs` |
| `src/types.ts` | `src/types.rs` |
| `src/ingest.ts` | `src/ingest.rs` (no fetch; typed errors and validators added) |
| `src/orcel/search-port.ts` | `src/provenance.rs` (local port and capability classification; no `exa-js`) |
| `src/server/exa-compat.ts` | `src/surface.rs` (route table and error policy; no server) |
| `src/server/cli.ts` | not ported (no listener) |
| new | `src/formats.rs` (`html`, `json`), `src/url.rs` |

Tests: 79 Rust tests. 46 of the 48 PoC behaviours are ported one to one (`tests/engine.rs` 15, `tests/ranking.rs`
11, `tests/extract.rs` 6, `tests/provenance_cost.rs` 8, `tests/exa_surface.rs` 6). The three `exa-js` round trips run
at the JSON-body level (the bodies `exa-js` sends and the fields it reads); the live HTTP round trip moves to the
packet that mounts the route on `orceld`. Of the remaining two, the loopback-only assertion is covered by the
no-network-surface test (the crate's dependency set and source), and the 401 for a wrong key moves to `orceld` (auth is
its job). New tests: 3 extraction checks for the tree builder, hidden content and dates, 2 for the route table and Exa
bodies with unknown fields, 13 for the P-1 items (`tests/p1_items.rs`), and 15 for hostile input and
cost bounds (`tests/adversarial.rs`).

Hostile-input bounds (security review of the first P-1 commit): input over 5 MiB (`MAX_HTML_BYTES`) or a tree over
200 000 nodes (`MAX_NODES`) is refused with `content_too_large`; the open-element stack stops growing at 512, and
implied-end and end-tag rules find their tag and boundary through per-tag depth lists, never a stack scan; at most 256
attributes per tag are kept, names are deduplicated through a set and values are cut to 8 KiB; dropped elements are
removed in one pass; trimmed text lengths and leaf-block flags come from one post-order pass; sentence splitting reads
each word once; queries are limited to 2 KiB and 64 terms; `contents` enforces the 10-target limit; `/answer`
`numResults` is clamped. `ETag` and `Last-Modified` values with anything but visible ASCII and spaces, or over 256
bytes, are dropped at ingest and again when conditional-request headers are built, so a stored value cannot inject a
header line. Corpus eviction at the 5000-document cap is O(1) amortized (an insertion-order queue with generation
tags), `findSimilar` reuses cached term vectors until the corpus changes, and `Dom` traversals return empty results for
ids outside the tree. The adversarial tests assert deterministic work counters (node count, rule lookups, analysis
visits), not wall-clock time.

Known differences from the PoC: diacritic folding covers combining marks, Latin-1, Latin Extended-A, Latin ligatures
and fullwidth ASCII rather than full NFKD; lengths count Unicode scalar values rather than UTF-16 units; request ids are
derived from a seed and counter rather than random; non-ISO dates keep the written calendar date instead of shifting by
the host time zone; the tree builder is not a full HTML5 parser.

Not done in P-1: CSS selector scoping (T17), the truncation marker (T21), geo and language filters (T24), the
`purpose` hint (T27), `?exaApiKey=` auth, rendered extraction for script-heavy pages (reported as `empty_content`).
