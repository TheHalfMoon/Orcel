# SG-000108 slice 7: map and crawl

Slice 7 of `docs/orcel/WEB_CAPABILITIES_DECISION.md` adds a host-side crawl queue: `crate::crawl::crawl` (pure) and `BrowserWorker::crawl_site(spec, scope, cancelled)`.

## Decision

- **Orcel-native, no Firecrawl code.** The founder chose a native rebuild on 2026-10-11. Firecrawl's crawl behaviour (`apps/api/native/src/crawler.rs` at `f84845c`) is the behavioural reference: a path-prefix scope, a depth bound, internal links only, fragments dropped, files and non-web schemes skipped, and include and exclude filters. No line is copied, so this slice needs no grant in `docs/orcel/grants/`, and `SOURCE_PERMISSIONS.md`'s AGPL condition does not apply. Include and exclude filters are path prefixes, not Firecrawl's regular expressions, so they are linear and cannot be used for ReDoS.
- **One destination, the existing gates.** A crawl runs inside one browser lifetime, which admits exactly one destination. Each page is opened by the governed navigation (SG-000075): public HTTPS on the admitted name only, the DNS pin and rebinding denial, redirect revalidation and limits, and downgrade, loopback, private, link-local and metadata denial.

  The crawl adds its own scope on top and never widens anything. Links come from the host's observation (the link URL as written), and page content from the slice 6 extraction, as untrusted `PageText`. No new worker frame, no new route and no new request path are added.
- **No MCP-facing tool.** `crawl_site` is a host API, and exposing it goes through SG-000079.

## Scope rules

- **The start URL** must parse as a navigation URL (`https`, port 443, no userinfo, no backslash, no control characters) and contain no dot segments. Its scope follows Firecrawl's rule:
  - a path ending in `/` is its own prefix;
  - a document (a last segment ending in a dot and two or more letters or digits, such as `/docs/intro.html`) scopes to its directory, `/docs/`;
  - anything else (`/docs`) is in scope itself and scopes to `/docs/`.
- **A discovered link is opened only if all of these hold:**
  - It resolves on the crawl's origin. Only absolute `https://host/…` and root-relative `/…` links count. Other schemes, protocol-relative `//…`, document-relative paths, credentials, backslashes, other ports, other hosts and IP literals are skipped as `OtherOrigin`.
  - It has no dot segment, no encoded dot (`%2e`), no whitespace or control character anywhere, and is shorter than 2,045 bytes (`Unnormalized`). The engine trims or rewrites the first group (`/site/.. ` would open `/`). A link that long may have been cut by the observation's 2,048-byte bound.
  - Its path is under the scope (`OutOfScope`).
  - It is not a file by its path ending, such as `.pdf`, archives, images, media, executables, office files, `.json`/`.xml`, fonts or scripts (`NotAPage`). Downloads stay with the approval-gated SG-000078 path.
  - It passes the include and exclude prefixes (`Filtered`; at most 16 of each, 256 bytes each). They compare the URL text as written: `/docs/%70rivate` or `/DOCS/private` passes `exclude /docs/private` on a server that decodes escapes or ignores case. The filters narrow a crawl; they are not an access control. The origin is the boundary.
  - It is within `max_depth` link hops (`TooDeep`, at most 5; each such URL is reported once).
  - The crawl remembers fewer than 1,000 URLs (`TooMany`).
- **Fragments are dropped, and each URL is opened at most once.** A page is read once, keyed by its normalized final URL, so a redirect to `…#x` is the same page.
- **A page is read** (extracted, and its links followed) only if its navigation succeeded with a 2xx status and its final URL, after redirects, is in scope and not already read. Otherwise the report says why:
  - a refused or failed navigation;
  - `status N`;
  - "redirected out of the crawl scope";
  - "redirected onto a page already read".

  A same-origin server redirect out of the path scope is still followed by the engine, because the navigation policy decides redirects and the origin is the boundary. Its page is not read.

## robots.txt and sitemaps (#317)

- **How they are read.** With `robots: true`, the crawl first opens `https://host/robots.txt`, and with `sitemaps: true` it reads sitemaps. Both use `BrowserWorker::fetch_text`, worker protocol generation 9:
  - It is a governed navigation like `navigate`: the same routes, host decisions, redirect checks, commit and generation advance.
  - It returns the document's text only for `text/plain`, `application/xml`, `text/xml`, `text/html` and a missing content type. HTML is included because a robots.txt served as a page is still read as one, as major crawlers do.
  - It is a full page load. The engine runs the document as it would any page: an XML document with an `<?xml-stylesheet?>` is transformed before its text is read, and the stylesheet and anything the result loads (images, scripts) are requested through the same routes. So the "text" of a styled sitemap is the transformed HTML, not the XML.
  - The worker removes control and invisible characters and cuts the text to fit one frame (`truncated`). The host refuses anything else in the reply.
  - No new request path is added. Playwright's API request context is not used, because it would bypass the page routes.
- **robots.txt (RFC 9309).**
  - **Groups:** the groups naming Orcel's product token `orcel` (case-insensitive, exact) apply; otherwise the `*` groups.
  - **Matching:** the longest matching rule wins, an allow wins a tie, and no match allows. `*` and a final `$` are supported, matched without backtracking. `/robots.txt` itself is always allowed.
  - **Bounds:** 512 rules of at most 512 bytes each, and 8 `Sitemap:` lines (https only).
  - **Answers:** a 2xx is parsed, and a 4xx means no rules. A 5xx, or no answer (including a navigation the policy refuses), means the site is unreachable. RFC 9309 then treats everything as disallowed, so the crawl stops as `RobotsUnreachable` before opening any page.
  - **Size:** a robots.txt larger than one frame (about 56 Ki characters, so `truncated`), or one where the groups that apply have more than 512 rules or a rule longer than 512 bytes, cannot be honoured in full. RFC 9309 asks a crawler to parse at least 500 KiB, so such a crawl stops as `RobotsUnreachable` rather than dropping late rules. The exception is an HTML page answering `/robots.txt` (a catch-all route) whose text read so far holds no robots records. It is taken as no robots.txt, as an HTML answer of any size always was.
  - **What it applies to:** every link, the start URL, every sitemap document (including the `/sitemap.xml` fallback and an index's children), and every sitemap entry. A page reached by a redirect onto a disallowed path is not read ("redirected onto a page robots.txt disallows"), although the engine already requested it.
- **Sitemaps.**
  - **Sources:** the robots.txt `Sitemap:` URLs on the crawl's origin, or `/sitemap.xml` if there are none.
  - **Index files:** a sitemap index's children on the origin are read in turn, up to 4 sitemaps in all.
  - **Entries:** each `<loc>` (XML's five entities decoded, CDATA taken literally, at most 1,000 per sitemap) goes through the same scope, robots and bound checks as a link, at depth 1.
  - **Failures:** a sitemap that fails or answers non-2xx is skipped. One that yields no `<loc>` (not a sitemap, or styled and transformed as above) is counted in `sitemaps_empty`, not `sitemaps_read`.
  - **Stops:** cancellation and the deadline are checked before each sitemap as well as before each page.
- `report.robots_status`, `report.sitemaps_read` and `report.sitemaps_empty` record what was read.

## Bounds and stops

- At most 50 pages, depth 5, and 10 minutes; a spec past any of these is refused.
- The caller's `cancelled` flag is checked first, before anything is fetched: a crawl cancelled before it starts reads not even robots.txt. The page count, the deadline and the flag are then checked before each page. A page that has started keeps its own timeouts: navigation 45 s, observation 10 s, extraction 20 s plus 10 s per further piece. A crawl can therefore overrun its deadline by one page's timeouts.
- **Worker failure:** the crawl stops as `WorkerFailed` only when the browser lifetime has failed closed: the host's own deadline passed, malformed worker output, the worker exited, or the caller cancelled. An out-of-order worker reply during a navigation is reported as a protocol violation without ending the lifetime (as before this slice); the crawl then records each remaining page's failure, within its page bound. A page that fails as the worker reports it does not stop the crawl. Examples: a download link, a load timeout, a network error, an observation too large to take. That failure is recorded and the crawl goes on, because the next navigation gets a fresh page.
- The report keeps at most 200 skipped links and counts the rest. `discovered` (the map) lists every URL the crawl admitted and queued, in discovery order. Links skipped as `TooDeep` or `TooMany` appear only in `skipped`.
- **A map** is a crawl with `extract: None`: pages are opened only to find their links.

## Limits

- **robots.txt details.**
  - Paths are matched as written, without percent-encoding normalisation in either direction: a link to `/café` does not match `Disallow: /caf%C3%A9`, although the engine requests the encoded path.
  - A `User-agent` value is compared by its product token (`orcel/1.0` names `orcel`). A `Sitemap:` or other non-group line between two `User-agent` lines does not end the group.
  - The `crawl-delay` extension is not honoured. The crawl is sequential: one page at a time, each a full navigation.
- **Sitemaps:** gzip-compressed sitemaps, text sitemaps (one URL per line) and styled sitemaps (see above) yield no entries. Numeric character references (`&#38;`) are not decoded, prefixed or attributed `<loc>` elements (`<sm:loc>`, `<loc attr>`) are not found, and a file is taken for an index whenever it mentions `<sitemapindex`.
- Links are what the observation reports. A link the bounded observation does not include (past its node bound) is not found, and the observation's `truncated` flag is not surfaced per page.
- Document-relative links (`page2`, `../x`) are skipped, not resolved, because the observation reports the `href` as written.
- A start host with Unicode (IDN) characters fails closed: the engine commits its punycode form, which is not the crawl's origin, so every page reads "redirected out of the crawl scope". Start from the punycode name.
- The engine's own requests (subresources, redirects) are governed by the navigation policy, not by the crawl's path scope.

## Evidence

**Native test** `a_crawl_reads_only_its_scope_through_the_governed_navigation` (Windows, Edge, HTTPS fixture):
- A crawl cancelled before it starts fetches nothing, robots.txt included (no robots status).
- **What the crawl of `/site/` opened, in order:** home, A, B, `moved`, `away`, `missing`, C and `deep/1`, with:
  - `moved` redirecting onto C and read once under `moved`, after which C is "already read";
  - `away` redirecting out of scope and not read;
  - `missing` returning 404, not read;
  - `deep/2` past depth 2 and skipped;
  - `dl`, a download link with no file ending, failing that page only, after which the crawl went on.
- **Extraction:** A reads "Alpha text.", and `moved` reads "Gamma text.".
- **Skips:** `other.test` and `mailto:` as `OtherOrigin`, `/elsewhere` as `OutOfScope`, `report.pdf` as `NotAPage`, and `/site/private/…` as `Filtered`.
- **Map:** two pages, stopped at `PageLimit`, nothing extracted, and the unopened `missing` page listed in `discovered`.
- **Foreign start:** a start on `other.test` is refused by the navigation and reported, and the lifetime goes on.
- **Fixture log:**
  - no `other.test`, `report.pdf`, `/site/private`, `/site/deep/2` or `mailto`;
  - `/elsewhere` exactly once, by `away`'s redirect, never as a link.

Since #317, the native test also covers robots.txt and the sitemap:
- the fixture's robots.txt disallows `/site/blocked` and names a sitemap on the origin and one on `other.test`;
- the page found only in the sitemap is crawled at depth 1 and extracted;
- `/site/blocked/...` is skipped as `Robots`, both from a link and from the sitemap, and never requested;
- `other.test` is never contacted;
- a crawl starting on `other.test` stops as `RobotsUnreachable` with no page. With `robots: false` the start page itself is refused and reported.

**Unit tests** in `robots.rs`:
- group selection (exact product token, the `*` fallback, rules outside any group);
- longest match and ties; `*` and `$`, including a 200-star pattern on a 2,000-byte path;
- the bounds;
- sitemap and index parsing, entities and CDATA.

**Unit tests** in `crawl.rs`, through a fake driver:
- the scope and every skip reason, including backslash, port, look-alike host, IP literal, protocol-relative, credentials, `%2e` and dot segments;
- read-once across redirects (a fragment on the final URL included); 404s;
- whitespace, possibly cut and repeated too-deep links;
- the reference scope rule;
- a per-page worker failure that does not stop the crawl;
- depth, page-limit, cancellation, deadline and worker-failure stops;
- maps; failed extraction (its links are still followed);
- spec bounds; the URL-memory and skip-report bounds;
- robots.txt read first and honoured for links, the start URL and redirects; a 404 allows everything; a 5xx or no answer stops the crawl;
- sitemaps seeding at depth 1 within scope and robots, with an index, foreign sitemaps ignored, and the `/sitemap.xml` default.
