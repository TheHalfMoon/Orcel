# Firecrawl → Orcel web intelligence blueprint (scrape + crawl + map + extract + research)

Status: PROPOSED (Fable, 2026-10-18). Extends `WEB_CAPABILITIES_DECISION.md` (adopted, authoritative for slices 4-7 already merged). Donors: Firecrawl `f84845c8` (AGPL engine, founder authorization `docs/orcel/grants/2026-10-13-founder-source-authorization.md`), crawl4ai `94b67888` (Apache-2.0 + attribution clause), Agent-Reach `a19a171f` (MIT), TinyFish AgentQL `9257f7aa` (MIT examples). Rows: `transplant_matrix.json` `T-FC-*`, `T-C4-*`, `T-AR-*`.

## 1. What already exists in Orcel (VERIFIED SOURCE FACT)

| Capability | Where | Notes |
|---|---|---|
| Scrape (navigate + extract Markdown) | slice 6, `crates/orcel-browser-host/src/extraction.rs`, worker `src/extract/*` | browser-use extraction port; untrusted text labelling |
| Crawl and map | slice 7, `crates/orcel-browser-host/src/crawl.rs` (1,391 lines) | One admitted destination per lifetime, ≤50 pages, depth ≤5, 600 s, 1,000 URLs, ≤4 sitemaps, path-prefix include/exclude (≤16 × 256 B). Header: "no Firecrawl code is copied" |
| robots.txt and sitemaps | `crates/orcel-browser-host/src/robots.rs` (391 lines) | RFC 9309, read through governed navigation (#317) |
| Download journey | slice 3d + SG-000078 | inert files only |

So the earlier plan to adapt Firecrawl's crawler was not executed; a native rebuild shipped. That rebuild is qualified and stays. The job now is to add what is missing with the smallest donor units.

## 2. What Firecrawl has that Orcel lacks

Inspected (VERIFIED SOURCE FACT): native Rust crate `apps/api/native/src` (3,494 lines: `crawler.rs` 1,505, `html.rs` 1,041, `document.rs` 291, `pdf.rs` 143, `engpicker.rs` 222), TypeScript `apps/api/src/lib/*` and `scraper/*`.

| Firecrawl unit | Gap it fills | Verdict | Task |
|---|---|---|---|
| `native/src/crawler.rs` `filter_links`, `filter_url`, `validate_regexes` | regex include/exclude, subdomain/backward options, denial reasons | COPY_ADAPT with regex size/DFA limits | WI-01 |
| `native/src/crawler.rs` `parse_sitemap_xml`, `exceeds_element_depth` | nested-sitemap depth guard | COPY_ADAPT only if the corpus comparison shows an Orcel parser gap | WI-01 |
| `lib/crawl-regex.ts`, `lib/canonical-url.ts` | pattern normalization; canonical URL for dedup | PORT | WI-01 |
| `lib/map-cosine.ts` (95 lines) | rank mapped URLs by a search term | PORT | WI-02 |
| `lib/change-tracking-diff.ts` (96 lines) | page change tracking | PORT | WI-04 |
| `native/src/pdf.rs`, `native/src/document.rs` | PDF and Office to Markdown | COPY_ADAPT inside a confined parser process | WI-05 |
| `native/src/html.rs` (lol_html, kuchikiki) | raw-HTML parsing | REFERENCE: Orcel reads the rendered DOM through DOMSnapshot; metadata fields (title, description, Open Graph) are worth adding to slice 6 output | WI-01 (metadata only) |
| `lib/map-utils.ts` hosted index (`fireEngineMap`, `queryIndex*`) | Firecrawl's cloud URL index | REJECT: proprietary hosted service, not inspectable, paid |
| `scrapeURL/engines/*` (fire-engine, playwright service, fetch) | engine waterfall | REJECT: Orcel has one confined engine; a second fetch engine would bypass browser confinement |
| LLM extract, `promptInjectionGuard.ts`, deep-research, generate-llmstxt | model calls | REJECT in the kernel: the model is outside Orcel; structured extraction is offered as a schema-validated tool result for the client model |
| queues, Redis, BigTable, ClickHouse, billing, team accounting | service infrastructure | REJECT |

## 3. crawl4ai

`crawl4ai/content_filter_strategy.py`: `BM25ContentFilter` and `PruningContentFilter` → **PORT** to `src/extract/relevance.ts` (WI-03). They reduce what the client model reads for a focused question. `LLMContentFilter` REJECT. `adaptive_crawler.py` (stop when coverage is sufficient) and `async_url_seeder.py` (sitemap/Common Crawl seeding) → REFERENCE. License note: Apache-2.0 plus an added clause requiring the sentence "This product includes software developed by UncleCode (https://x.com/unclecode) as part of the Crawl4AI project (https://github.com/unclecode/crawl4ai)." in NOTICE/README/About. WI-03 adds it.

## 4. Research workflows

Orcel does not run a research agent in the kernel. Research is composed by the client (or founder AI) from these tools: `web_search` (WI-06, optional provider), browser navigate/extract (scrape), map/crawl, document parse (WI-05), change tracking (WI-04), and verifiers. Each result carries source URL, retrieval time and extraction bounds so citations are checkable.

Search providers: self-hosted SearXNG (AGPL upstream, used only over HTTP, no code copied), or user-supplied keys for Brave, Tavily, Exa, Serper, ScrapingBee. None is mandatory and Orcel never pays for one. Agent-Reach's channel/probe/doctor semantics are the router model (SG-000103); its `cookie_extract.py` and OpenCLI browser-session channels are rejected because they rely on personal browser sessions and exported cookies.

## 5. One pipeline

```text
web_search (optional) ─┐
                       ├─► map (sitemap + links + rank)  ─► crawl queue (scope rules) ─┐
user URL ──────────────┘                                                                ├─► governed navigation (one engine)
                                                                                        │      └─► extract (Markdown, relevance, metadata)
approved download ─────────────────────────────────────► document parser process ──────┘           └─► change tracking (optional)
                                                                                                         └─► verified result + citations
```

Every arrow passes the host's admitted-destination and SG-000075 checks. No second engine and no unconfined HTTP fetch for page content (the existing `web_fetch` tool stays a bounded single-response HTTPS GET with public-address pinning).

## 6. Resource bounds to keep or add

Keep the slice 7 bounds. Add: regex size limit 1 MiB and DFA limit; map ranking over ≤1,000 URLs; document parser input ≤50 MiB, output ≤1,000,000 characters, 30 s; change-tracking store per workspace ≤50 MiB with oldest-first eviction. ESTIMATE values; confirm in each task.

## 7. Cost

Zero required spend: no hosted API, no proxy service, no paid index. Optional paid search only with the user's own key.
