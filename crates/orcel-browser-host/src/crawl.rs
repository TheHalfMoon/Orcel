//! SG-000108 slice 7: map and crawl. A bounded, host-side queue over the one
//! admitted destination of a browser lifetime: every page is opened by the
//! governed navigation (SG-000075, the redirect and rebinding checks
//! included), its links come from the host's observation, and its content,
//! if asked, from the slice 6 extraction.
//!
//! Orcel-native: Firecrawl's documented crawl behaviour (a path-prefix
//! scope, a depth bound, internal links only, fragments dropped, non-page
//! files and non-web schemes skipped, include and exclude paths) is the
//! reference. Include and exclude are path prefixes by default, or
//! regular expressions with Firecrawl's semantics (WI-01, `crawl_scope`,
//! the only adapted Firecrawl code here). robots.txt (RFC 9309) and sitemaps
//! are read through governed navigations too (#317).

use crate::error::HostError;
use crate::extraction::{ExtractOptions, PageExtraction};
use crate::robots::{sitemap_locations, Robots};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Pages one crawl may open.
pub const MAX_CRAWL_PAGES: u32 = 50;
/// Link hops from the start page.
pub const MAX_CRAWL_DEPTH: u32 = 5;
/// Wall-clock bound of one crawl (checked between pages).
pub const MAX_CRAWL_DURATION: Duration = Duration::from_secs(600);
/// Distinct in-scope URLs one crawl remembers (visited and queued).
pub const MAX_CRAWL_URLS: usize = 1000;
/// Skipped links reported (later ones are only counted).
pub const MAX_SKIPPED_REPORTED: usize = 200;
/// Sitemaps one crawl reads (an index's children included).
pub const MAX_SITEMAPS: usize = 4;
/// Include and exclude path prefixes, each.
pub const MAX_PATH_PATTERNS: usize = 16;
pub const MAX_PATH_PATTERN_BYTES: usize = 256;

/// Links at least this long may have been cut by the worker's 2048-byte
/// bound (a multi-byte character can stop the cut short): never opened.
const MAX_LINK_BYTES: usize = 2048 - 3;

/// Path endings that are files, not pages: never opened by a crawl.
const NOT_PAGES: &[&str] = &[
    ".pdf", ".zip", ".gz", ".tgz", ".rar", ".7z", ".tar", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".bmp", ".avif", ".mp3", ".mp4", ".m4a", ".wav", ".ogg", ".webm", ".mov",
    ".avi", ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".apk", ".iso", ".bin", ".doc",
    ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".json", ".xml", ".woff", ".woff2", ".ttf",
    ".otf", ".css", ".js", ".mjs", ".wasm",
];

/// What to crawl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlSpec {
    /// An `https` URL on the browser lifetime's admitted destination. Its
    /// directory is the crawl's scope: only paths under it are opened.
    pub start_url: String,
    pub max_pages: u32,
    pub max_depth: u32,
    /// Patterns a page must match (none: every in-scope path).
    pub include_paths: Vec<String>,
    /// Patterns a page must not match.
    pub exclude_paths: Vec<String>,
    /// WI-01: whether the patterns are path prefixes (the default) or
    /// regular expressions over the path.
    pub pattern_kind: crate::crawl_scope::PatternKind,
    /// Extract every opened page (slice 6); `None` maps links only.
    pub extract: Option<ExtractOptions>,
    /// Read `/robots.txt` first and honour it for Orcel's product token
    /// (RFC 9309): an unreachable one (5xx, or no answer) stops the crawl.
    pub robots: bool,
    /// Seed the queue from the sitemaps robots.txt names (else
    /// `/sitemap.xml`), at depth 1.
    pub sitemaps: bool,
    pub deadline: Duration,
}

/// Why a discovered link was not opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Not an `https` URL on the crawl's origin, or not resolvable
    /// (another scheme, a relative path, credentials, a backslash).
    OtherOrigin,
    /// Outside the start URL's directory.
    OutOfScope,
    /// An include path did not match, or an exclude path did.
    Filtered,
    /// A file, not a page (by its path ending).
    NotAPage,
    /// Dot segments, an encoded dot, whitespace or a control character
    /// anywhere (the engine trims or rewrites them), or a link possibly cut
    /// by the observation's bound: not in the form the engine requests.
    Unnormalized,
    /// Past the depth bound.
    TooDeep,
    /// The crawl already remembers MAX_CRAWL_URLS URLs.
    TooMany,
    /// robots.txt disallows it for Orcel.
    Robots,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedLink {
    pub url: String,
    pub reason: SkipReason,
}

/// Why the crawl stopped before its queue was empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlStop {
    PageLimit,
    Deadline,
    Cancelled,
    /// The worker failed in a way the lifetime does not survive.
    WorkerFailed,
    /// robots.txt could not be read (a 5xx answer or none): RFC 9309 treats
    /// the whole site as disallowed, so nothing was opened.
    RobotsUnreachable,
}

/// One opened page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawledPage {
    pub url: String,
    /// Where the governed navigation committed (after redirects).
    pub final_url: String,
    pub depth: u32,
    pub status: u16,
    pub extraction: Option<PageExtraction>,
    /// Why the page was not read: a refused or failed navigation, a non-2xx
    /// status, a redirect out of scope or onto a page already read, or a
    /// failed observation or extraction.
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrawlReport {
    pub pages: Vec<CrawledPage>,
    /// Every in-scope URL the crawl found, opened or not, in discovery
    /// order (the map).
    pub discovered: Vec<String>,
    pub skipped: Vec<SkippedLink>,
    /// Skipped links past MAX_SKIPPED_REPORTED.
    pub skipped_unreported: usize,
    pub stopped: Option<CrawlStop>,
    /// The robots.txt answer's status, when it was read.
    pub robots_status: Option<u16>,
    /// Sitemaps read that yielded at least one location.
    pub sitemaps_read: usize,
    /// Sitemaps opened (2xx) that yielded none: not a sitemap, or one the
    /// engine transformed with its XSLT stylesheet before the text was read.
    pub sitemaps_empty: usize,
}

/// One page as the driver saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visit {
    pub final_url: String,
    pub status: u16,
}

/// A text document (robots.txt, a sitemap) as the driver read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextDocument {
    pub final_url: String,
    pub status: u16,
    /// Empty unless the document was text, XML or HTML.
    pub text: String,
    /// The text was cut to fit one frame.
    pub truncated: bool,
    /// The document's media type, as the worker reported it.
    pub media: String,
}

/// The browser side of a crawl.
pub trait CrawlDriver {
    /// Open a text document through the governed navigation.
    fn fetch_text(&mut self, url: &str) -> Result<TextDocument, HostError>;
    /// Open `url` through the governed navigation.
    fn open(&mut self, url: &str) -> Result<Visit, HostError>;
    /// The links of the committed page, as observed (absolute or
    /// root-relative URLs as written).
    fn links(&mut self) -> Result<Vec<String>, HostError>;
    fn extract(&mut self, options: ExtractOptions) -> Result<PageExtraction, HostError>;
    /// The browser lifetime has failed closed: nothing more can be opened.
    /// A failed page (a download link, a load timeout, a network error, an
    /// observation too large) is not this; the next page gets a fresh one.
    fn lost(&self) -> bool;
}

/// The crawl's origin and scope, from its start URL.
#[derive(Debug, Clone)]
struct Scope {
    /// `https://host` (port 443 implied).
    base: String,
    /// Paths under this prefix are in scope.
    prefix: String,
    /// A start path without a trailing slash that is not a document is in
    /// scope itself, besides everything below it.
    exact: Option<String>,
    patterns: crate::crawl_scope::Patterns,
}

fn invalid(message: &str) -> HostError {
    HostError::Invalid(message.into())
}

/// Path and query of an `https` URL on `base`, without its fragment; `None`
/// if it is on another origin or not resolvable.
fn split_on(base: &str, url: &str) -> Option<String> {
    let resolved = if url.starts_with('/') && !url.starts_with("//") {
        format!("{base}{url}")
    } else {
        url.to_owned()
    };
    let target = crate::navigation::parse_navigation_url(&resolved).ok()?;
    let rest = resolved.get("https://".len()..)?;
    let path = rest.find('/').map_or("/", |at| &rest[at..]);
    if format!("https://{}", target.host) != base {
        return None;
    }
    let path = path.split('#').next().unwrap_or("/");
    Some(if path.is_empty() {
        "/".into()
    } else {
        path.to_owned()
    })
}

fn unnormalized(path: &str) -> bool {
    let only_path = path.split('?').next().unwrap_or(path);
    let lower = only_path.to_ascii_lowercase();
    lower.contains("%2e")
        || only_path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn not_a_page(path: &str) -> bool {
    let only_path = path.split('?').next().unwrap_or(path).to_ascii_lowercase();
    NOT_PAGES.iter().any(|ending| only_path.ends_with(ending))
}

/// The scope of a start path, as Firecrawl defines it: a path ending in `/`
/// is its own prefix; a document (`/docs/intro.html`, a last segment ending
/// in a dot and two or more letters or digits) scopes to its directory;
/// anything else (`/docs`) is in scope itself and scopes to `/docs/`.
fn scope_of(path: &str) -> (String, Option<String>) {
    if path.ends_with('/') {
        return (path.to_owned(), None);
    }
    let last = path.rfind('/').map_or(0, |at| at + 1);
    let segment = &path[last..];
    let document = segment.rfind('.').is_some_and(|dot| {
        let ext = &segment[dot + 1..];
        ext.len() >= 2 && ext.bytes().all(|b| b.is_ascii_alphanumeric())
    });
    if document {
        (path[..last].to_owned(), None)
    } else {
        (format!("{path}/"), Some(path.to_owned()))
    }
}

impl Scope {
    fn of(spec: &CrawlSpec) -> Result<(Self, String), HostError> {
        let target = crate::navigation::parse_navigation_url(&spec.start_url)?;
        let base = format!("https://{}", target.host);
        let path = split_on(&base, &spec.start_url)
            .ok_or_else(|| invalid("the crawl start URL cannot be resolved"))?;
        if unnormalized(&path) {
            return Err(invalid("the crawl start URL is not normalized"));
        }
        let only_path = path.split('?').next().unwrap_or("/");
        let (prefix, exact) = scope_of(only_path);
        let scope = Self {
            base: base.clone(),
            prefix,
            exact,
            patterns: crate::crawl_scope::Patterns::compile(
                spec.pattern_kind,
                &spec.include_paths,
                &spec.exclude_paths,
            )?,
        };
        Ok((scope, format!("{base}{path}")))
    }

    /// The normalized URL to open, or why not.
    fn admit(&self, link: &str) -> Result<String, SkipReason> {
        if link.len() >= MAX_LINK_BYTES
            || link.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(SkipReason::Unnormalized);
        }
        let path = split_on(&self.base, link).ok_or(SkipReason::OtherOrigin)?;
        if unnormalized(&path) {
            return Err(SkipReason::Unnormalized);
        }
        let only_path = path.split('?').next().unwrap_or(&path);
        if !path.starts_with(&self.prefix) && self.exact.as_deref() != Some(only_path) {
            return Err(SkipReason::OutOfScope);
        }
        if not_a_page(&path) {
            return Err(SkipReason::NotAPage);
        }
        if !self.patterns.admits(&path) {
            return Err(SkipReason::Filtered);
        }
        Ok(format!("{}{path}", self.base))
    }
}

fn check_spec(spec: &CrawlSpec) -> Result<(), HostError> {
    if spec.max_pages == 0 || spec.max_pages > MAX_CRAWL_PAGES {
        return Err(invalid("max_pages must be 1 to MAX_CRAWL_PAGES"));
    }
    if spec.max_depth > MAX_CRAWL_DEPTH {
        return Err(invalid("max_depth is above MAX_CRAWL_DEPTH"));
    }
    if spec.deadline.is_zero() || spec.deadline > MAX_CRAWL_DURATION {
        return Err(invalid(
            "the crawl deadline must be within MAX_CRAWL_DURATION",
        ));
    }
    Ok(())
}

/// Seed the frontier from the sitemaps robots.txt names on the crawl's
/// origin (else `/sitemap.xml`): their page URLs at depth 1, an index's
/// child sitemaps read in turn, at most MAX_SITEMAPS in all.
fn read_sitemaps(
    driver: &mut dyn CrawlDriver,
    spec: &CrawlSpec,
    scope: &Scope,
    robots: &Robots,
    frontier: &mut Frontier,
    report: &mut CrawlReport,
    (started, cancelled): (Instant, &AtomicBool),
) {
    let mut sources: VecDeque<String> = robots
        .sitemaps
        .iter()
        .filter(|url| split_on(&scope.base, url).is_some())
        .cloned()
        .collect();
    if sources.is_empty() {
        sources.push_back(format!("{}/sitemap.xml", scope.base));
    }
    let mut opened = 0;
    while let Some(source) = sources.pop_front() {
        if opened >= MAX_SITEMAPS {
            break;
        }
        if cancelled.load(Ordering::SeqCst) {
            report.stopped = Some(CrawlStop::Cancelled);
            return;
        }
        if started.elapsed() >= spec.deadline {
            report.stopped = Some(CrawlStop::Deadline);
            return;
        }
        // The sitemap document itself must be one robots.txt allows.
        let Some(path) = split_on(&scope.base, &source) else {
            continue;
        };
        if !robots.allowed(&path) {
            skip(report, source, SkipReason::Robots);
            continue;
        }
        opened += 1;
        let document = match driver.fetch_text(&source) {
            Ok(document) if (200..300).contains(&document.status) => document,
            Ok(_) => continue,
            Err(_) if driver.lost() => {
                report.stopped = Some(CrawlStop::WorkerFailed);
                return;
            }
            Err(_) => continue,
        };
        let (locations, index) = sitemap_locations(&document.text);
        if locations.is_empty() {
            report.sitemaps_empty += 1;
            continue;
        }
        report.sitemaps_read += 1;
        for location in locations {
            if index {
                if split_on(&scope.base, &location).is_some() && sources.len() < MAX_SITEMAPS {
                    sources.push_back(location);
                }
            } else {
                frontier.offer(report, scope, robots, location, 1, spec.max_depth);
            }
        }
    }
}

/// What the crawl remembers and what it will open next.
struct Frontier {
    seen: HashSet<String>,
    /// Links past the depth bound, reported once each (bounded like `seen`).
    too_deep: HashSet<String>,
    queue: VecDeque<(String, u32)>,
}

fn skip(report: &mut CrawlReport, url: String, reason: SkipReason) {
    if report.skipped.len() < MAX_SKIPPED_REPORTED {
        report.skipped.push(SkippedLink { url, reason });
    } else {
        report.skipped_unreported += 1;
    }
}

impl Frontier {
    /// Queue `link` at `depth` if the scope, robots.txt and the bounds let
    /// it in; report why not otherwise. A URL already seen is ignored.
    fn offer(
        &mut self,
        report: &mut CrawlReport,
        scope: &Scope,
        robots: &Robots,
        link: String,
        depth: u32,
        max_depth: u32,
    ) {
        let admitted = match scope.admit(&link) {
            Ok(admitted) => admitted,
            Err(reason) => return skip(report, link, reason),
        };
        // `/docs` and `/docs/` are one page (WI-01).
        let key = crate::crawl_scope::canonical(&admitted);
        if self.seen.contains(&key) {
            return;
        }
        if !robots.allowed(&admitted[scope.base.len()..]) {
            if self.too_deep.len() < MAX_CRAWL_URLS && self.too_deep.insert(admitted.clone()) {
                skip(report, admitted, SkipReason::Robots);
            }
            return;
        }
        if depth > max_depth {
            if self.too_deep.len() < MAX_CRAWL_URLS && self.too_deep.insert(admitted.clone()) {
                skip(report, admitted, SkipReason::TooDeep);
            }
            return;
        }
        if self.seen.len() >= MAX_CRAWL_URLS {
            return skip(report, admitted, SkipReason::TooMany);
        }
        self.seen.insert(key);
        report.discovered.push(admitted.clone());
        self.queue.push_back((admitted, depth));
    }
}

/// robots.txt for the crawl's origin, or the stop it causes.
fn read_robots(
    driver: &mut dyn CrawlDriver,
    scope: &Scope,
    report: &mut CrawlReport,
) -> Result<Robots, CrawlStop> {
    match driver.fetch_text(&format!("{}/robots.txt", scope.base)) {
        Ok(document) => {
            report.robots_status = Some(document.status);
            match document.status {
                200..=299 => {
                    // A file larger than one frame, or with more rules than
                    // kept, cannot be honoured in full: RFC 9309 asks a
                    // crawler to parse at least 500 KiB, so the crawl fails
                    // closed instead of dropping late rules.
                    let robots = Robots::parse(&document.text);
                    // An HTML page answering /robots.txt (a catch-all route)
                    // with no records in what was read is no robots.txt.
                    let page_not_robots = document.media == "text/html" && !robots.has_records();
                    if !robots.complete() || (document.truncated && !page_not_robots) {
                        return Err(CrawlStop::RobotsUnreachable);
                    }
                    Ok(robots)
                }
                // "Unavailable": no rules (RFC 9309 2.3.1.3).
                400..=499 => Ok(Robots::allow_all()),
                _ => Err(CrawlStop::RobotsUnreachable),
            }
        }
        Err(_) if driver.lost() => Err(CrawlStop::WorkerFailed),
        // No answer, or a redirect the navigation refused: "unreachable".
        Err(_) => Err(CrawlStop::RobotsUnreachable),
    }
}

/// Run a crawl. A refused spec is an error; everything after the start is
/// in the report. `cancelled` is checked before anything is fetched (robots
/// included) and, with the deadline, between pages.
pub fn crawl(
    driver: &mut dyn CrawlDriver,
    spec: &CrawlSpec,
    cancelled: &AtomicBool,
) -> Result<CrawlReport, HostError> {
    check_spec(spec)?;
    let (scope, start) = Scope::of(spec)?;
    let scope_start = scope
        .admit(&start)
        .map_err(|_| invalid("the crawl start URL is outside its own filters"))?;
    let started = Instant::now();
    let mut report = CrawlReport {
        pages: Vec::new(),
        discovered: Vec::new(),
        skipped: Vec::new(),
        skipped_unreported: 0,
        stopped: None,
        robots_status: None,
        sitemaps_read: 0,
        sitemaps_empty: 0,
    };
    // A crawl cancelled before it starts fetches nothing, robots.txt
    // included: its outcome does not depend on whether a fetch it never
    // needed would have succeeded.
    if cancelled.load(Ordering::SeqCst) {
        report.stopped = Some(CrawlStop::Cancelled);
        return Ok(report);
    }
    let robots = if spec.robots {
        match read_robots(driver, &scope, &mut report) {
            Ok(robots) => robots,
            Err(stop) => {
                report.stopped = Some(stop);
                return Ok(report);
            }
        }
    } else {
        Robots::allow_all()
    };
    let mut frontier = Frontier {
        seen: HashSet::new(),
        too_deep: HashSet::new(),
        queue: VecDeque::new(),
    };
    frontier.offer(&mut report, &scope, &robots, scope_start, 0, spec.max_depth);
    if spec.sitemaps {
        read_sitemaps(
            driver,
            spec,
            &scope,
            &robots,
            &mut frontier,
            &mut report,
            (started, cancelled),
        );
        if report.stopped.is_some() {
            return Ok(report);
        }
    }
    // Final URLs already read, so a redirect onto one is not read twice.
    let mut read: HashSet<String> = HashSet::new();
    while let Some((url, depth)) = frontier.queue.pop_front() {
        if cancelled.load(Ordering::SeqCst) {
            report.stopped = Some(CrawlStop::Cancelled);
            break;
        }
        if started.elapsed() >= spec.deadline {
            report.stopped = Some(CrawlStop::Deadline);
            break;
        }
        if report.pages.len() as u32 >= spec.max_pages {
            report.stopped = Some(CrawlStop::PageLimit);
            break;
        }
        let mut page = CrawledPage {
            url: url.clone(),
            final_url: String::new(),
            depth,
            status: 0,
            extraction: None,
            failure: None,
        };
        let visit = match driver.open(&url) {
            Ok(visit) => visit,
            Err(error) => {
                let stop = driver.lost();
                page.failure = Some(error.to_string());
                report.pages.push(page);
                if stop {
                    report.stopped = Some(CrawlStop::WorkerFailed);
                    break;
                }
                continue;
            }
        };
        page.final_url = visit.final_url.clone();
        page.status = visit.status;
        let failure = if !(200..300).contains(&visit.status) {
            Some(format!("status {}", visit.status))
        } else {
            match scope.admit(&visit.final_url) {
                Err(_) => Some("redirected out of the crawl scope".to_owned()),
                Ok(normalized) if !robots.allowed(&normalized[scope.base.len()..]) => {
                    Some("redirected onto a page robots.txt disallows".to_owned())
                }
                // Keyed by the normalized URL (no fragment), as the queue is.
                Ok(normalized) if !read.insert(crate::crawl_scope::canonical(&normalized)) => {
                    Some("redirected onto a page already read".to_owned())
                }
                Ok(_) => None,
            }
        };
        if failure.is_some() {
            page.failure = failure;
            report.pages.push(page);
            continue;
        }
        if let Some(options) = spec.extract {
            match driver.extract(options) {
                Ok(extraction) => page.extraction = Some(extraction),
                Err(error) if driver.lost() => {
                    page.failure = Some(error.to_string());
                    report.pages.push(page);
                    report.stopped = Some(CrawlStop::WorkerFailed);
                    break;
                }
                Err(error) => page.failure = Some(error.to_string()),
            }
        }
        let links = match driver.links() {
            Ok(links) => links,
            Err(error) => {
                let stop = driver.lost();
                page.failure.get_or_insert(error.to_string());
                report.pages.push(page);
                if stop {
                    report.stopped = Some(CrawlStop::WorkerFailed);
                    break;
                }
                continue;
            }
        };
        report.pages.push(page);
        for link in links {
            frontier.offer(
                &mut report,
                &scope,
                &robots,
                link,
                depth + 1,
                spec.max_depth,
            );
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::UnavailableReason;
    use std::collections::HashMap;

    /// A site as a map from URL to (final URL, status, links).
    struct Site {
        pages: HashMap<String, (String, u16, Vec<String>)>,
        opened: Vec<String>,
        current: Option<String>,
        fail_extract: bool,
        lost: bool,
        /// Text documents by URL: (status, text).
        texts: HashMap<String, (u16, String)>,
    }

    impl Site {
        fn new(pages: &[(&str, &str, u16, &[&str])]) -> Self {
            Self {
                pages: pages
                    .iter()
                    .map(|(url, end, status, links)| {
                        (
                            (*url).to_owned(),
                            (
                                (*end).to_owned(),
                                *status,
                                links.iter().map(|l| (*l).to_owned()).collect(),
                            ),
                        )
                    })
                    .collect(),
                opened: Vec::new(),
                current: None,
                fail_extract: false,
                lost: false,
                texts: HashMap::new(),
            }
        }
    }

    impl CrawlDriver for Site {
        fn open(&mut self, url: &str) -> Result<Visit, HostError> {
            self.opened.push(url.to_owned());
            let (end, status, _) = self
                .pages
                .get(url)
                .cloned()
                .ok_or_else(|| HostError::Invalid("navigation denied".into()))?;
            // 0: the lifetime fails closed; 1: one page fails, typed as the
            // worker reports it, and the lifetime goes on.
            if status == 0 {
                self.lost = true;
                return Err(HostError::Unavailable(UnavailableReason::ProtocolViolation));
            }
            if status == 1 {
                return Err(HostError::Unavailable(UnavailableReason::ActionFailed));
            }
            // The committed page is the final one, after redirects.
            self.current = Some(end.clone());
            Ok(Visit {
                final_url: end,
                status,
            })
        }
        fn links(&mut self) -> Result<Vec<String>, HostError> {
            let current = self.current.clone().unwrap_or_default();
            Ok(self
                .pages
                .get(&current)
                .map(|(_, _, links)| links.clone())
                .unwrap_or_default())
        }
        fn lost(&self) -> bool {
            self.lost
        }
        fn fetch_text(&mut self, url: &str) -> Result<TextDocument, HostError> {
            self.opened.push(url.to_owned());
            match self.texts.get(url) {
                Some((0, _)) => Err(HostError::Invalid("navigation denied".into())),
                Some((status, text)) => Ok(TextDocument {
                    final_url: url.to_owned(),
                    status: *status % 1000,
                    text: text.clone(),
                    // A status above 1000 marks the text as cut; HTML text is
                    // served as text/html.
                    truncated: *status > 1000,
                    media: if text.starts_with("<html") {
                        "text/html".into()
                    } else {
                        "text/plain".into()
                    },
                }),
                None => Ok(TextDocument {
                    final_url: url.to_owned(),
                    status: 404,
                    text: String::new(),
                    truncated: false,
                    media: "text/plain".into(),
                }),
            }
        }
        fn extract(&mut self, _options: ExtractOptions) -> Result<PageExtraction, HostError> {
            if self.fail_extract {
                return Err(HostError::Invalid("stale page".into()));
            }
            Ok(PageExtraction {
                url: self.current.clone().unwrap_or_default(),
                document_generation: self.opened.len() as u64,
                truncated: false,
                chunks: Vec::new(),
            })
        }
    }

    const S: &str = "https://site.test";

    fn spec(start: &str) -> CrawlSpec {
        CrawlSpec {
            start_url: start.into(),
            max_pages: 20,
            max_depth: 3,
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
            pattern_kind: Default::default(),
            extract: Some(ExtractOptions::default()),
            robots: false,
            sitemaps: false,
            deadline: Duration::from_secs(60),
        }
    }

    fn site() -> Site {
        Site::new(&[
            (
                "https://site.test/docs/",
                "https://site.test/docs/",
                200,
                &[
                    "/docs/a",
                    "https://site.test/docs/b#part",
                    "https://other.test/docs/x",
                    "/elsewhere",
                    "/docs/manual.pdf",
                    "/docs/../admin",
                    "/docs/%2e%2e/admin",
                    "javascript:alert(1)",
                    "mailto:a@site.test",
                    "relative/page",
                    "//site.test/docs/protocol-relative",
                    "https://user:pw@site.test/docs/creds",
                    "/docs\\..\\admin",
                    "https://site.test:8443/docs/port",
                    "https://site.test.evil.test/docs/x",
                    "https://127.0.0.1/docs/x",
                    "/docs/a",
                    "/docs/private/x",
                ],
            ),
            (
                "https://site.test/docs/a",
                "https://site.test/docs/a",
                200,
                &["/docs/c", "/docs/"],
            ),
            (
                "https://site.test/docs/b",
                "https://site.test/docs/c",
                200,
                &[],
            ),
            (
                "https://site.test/docs/c",
                "https://site.test/docs/c",
                200,
                &["/docs/d"],
            ),
            (
                "https://site.test/docs/d",
                "https://site.test/docs/d",
                404,
                &["/docs/e"],
            ),
            (
                "https://site.test/docs/private/x",
                "https://site.test/docs/private/x",
                200,
                &[],
            ),
        ])
    }

    fn reasons(report: &CrawlReport) -> Vec<(&str, SkipReason)> {
        report
            .skipped
            .iter()
            .map(|s| (s.url.as_str(), s.reason))
            .collect()
    }

    /// WI-01: regex include and exclude through a whole crawl; a link on
    /// another origin that matches stays refused; `/docs/x` and `/docs/x/`
    /// are one page.
    #[test]
    fn wi01_regex_patterns_and_canonical_urls_through_a_crawl() {
        let mut driver = Site::new(&[
            (
                "https://site.test/docs/",
                "https://site.test/docs/",
                200,
                &[
                    "/docs/guide/intro",
                    "/docs/guide/intro/",
                    "/docs/api/v1",
                    "/docs/guide/old/setup",
                    "https://other.test/docs/guide/x",
                ],
            ),
            (
                "https://site.test/docs/guide/intro",
                "https://site.test/docs/guide/intro",
                200,
                &[],
            ),
            (
                "https://site.test/docs/guide/intro/",
                "https://site.test/docs/guide/intro/",
                200,
                &[],
            ),
            (
                "https://site.test/docs/api/v1",
                "https://site.test/docs/api/v1",
                200,
                &[],
            ),
            (
                "https://site.test/docs/guide/old/setup",
                "https://site.test/docs/guide/old/setup",
                200,
                &[],
            ),
        ]);
        let mut wanted = spec("https://site.test/docs/");
        wanted.pattern_kind = crate::crawl_scope::PatternKind::Regex;
        wanted.include_paths = vec!["^/docs/(guide|$)".into()];
        wanted.exclude_paths = vec!["/old/".into()];
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            driver.opened,
            [
                "https://site.test/docs/",
                "https://site.test/docs/guide/intro"
            ],
            "regex include and exclude, and one visit for /intro and /intro/"
        );
        let reasons = reasons(&report);
        assert!(reasons.contains(&("/docs/api/v1", SkipReason::Filtered)));
        assert!(reasons.contains(&("/docs/guide/old/setup", SkipReason::Filtered)));
        assert!(reasons.contains(&("https://other.test/docs/guide/x", SkipReason::OtherOrigin)));
        // An oversized regex refuses the crawl before anything is opened.
        let mut refused = spec("https://site.test/docs/");
        refused.pattern_kind = crate::crawl_scope::PatternKind::Regex;
        refused.include_paths = vec!["a{5}{5}{5}{5}{5}{5}".into()];
        let mut untouched = site();
        assert!(crawl(&mut untouched, &refused, &AtomicBool::new(false)).is_err());
        assert!(untouched.opened.is_empty());
    }

    #[test]
    fn a_crawl_stays_on_its_origin_and_directory_and_reads_each_page_once() {
        let mut driver = site();
        let mut wanted = spec("https://site.test/docs/");
        wanted.exclude_paths = vec!["/docs/private".into()];
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            driver.opened,
            [
                "https://site.test/docs/",
                "https://site.test/docs/a",
                "https://site.test/docs/b",
                "https://site.test/docs/c",
                "https://site.test/docs/d",
            ]
        );
        let read: Vec<(&str, bool)> = report
            .pages
            .iter()
            .map(|p| (p.url.as_str(), p.extraction.is_some()))
            .collect();
        assert_eq!(
            read,
            [
                ("https://site.test/docs/", true),
                ("https://site.test/docs/a", true),
                // b redirects onto c before c is opened: read as b's final URL.
                ("https://site.test/docs/b", true),
                // c itself is then a page already read.
                ("https://site.test/docs/c", false),
                ("https://site.test/docs/d", false),
            ]
        );
        assert_eq!(
            report.pages[3].failure.as_deref(),
            Some("redirected onto a page already read")
        );
        assert_eq!(report.pages[4].failure.as_deref(), Some("status 404"));
        assert_eq!(
            reasons(&report),
            [
                ("https://other.test/docs/x", SkipReason::OtherOrigin),
                ("/elsewhere", SkipReason::OutOfScope),
                ("/docs/manual.pdf", SkipReason::NotAPage),
                ("/docs/../admin", SkipReason::Unnormalized),
                ("/docs/%2e%2e/admin", SkipReason::Unnormalized),
                ("javascript:alert(1)", SkipReason::OtherOrigin),
                ("mailto:a@site.test", SkipReason::OtherOrigin),
                ("relative/page", SkipReason::OtherOrigin),
                (
                    "//site.test/docs/protocol-relative",
                    SkipReason::OtherOrigin
                ),
                (
                    "https://user:pw@site.test/docs/creds",
                    SkipReason::OtherOrigin
                ),
                ("/docs\\..\\admin", SkipReason::OtherOrigin),
                ("https://site.test:8443/docs/port", SkipReason::OtherOrigin),
                (
                    "https://site.test.evil.test/docs/x",
                    SkipReason::OtherOrigin
                ),
                ("https://127.0.0.1/docs/x", SkipReason::OtherOrigin),
                ("/docs/private/x", SkipReason::Filtered),
            ]
        );
        assert_eq!(report.stopped, None);
        // The map: every in-scope URL found, fragments dropped, once.
        assert_eq!(
            report.discovered,
            [
                "https://site.test/docs/",
                "https://site.test/docs/a",
                "https://site.test/docs/b",
                "https://site.test/docs/c",
                "https://site.test/docs/d",
            ]
        );
    }

    #[test]
    fn depth_page_count_cancellation_and_a_lost_worker_stop_the_crawl() {
        let mut shallow = spec("https://site.test/docs/");
        shallow.max_depth = 1;
        let mut driver = site();
        let report = crawl(&mut driver, &shallow, &AtomicBool::new(false)).unwrap();
        assert!(!driver
            .opened
            .contains(&"https://site.test/docs/c".to_owned()));
        assert!(reasons(&report).contains(&("https://site.test/docs/c", SkipReason::TooDeep)));

        let mut few = spec("https://site.test/docs/");
        few.max_pages = 2;
        let mut driver = site();
        let report = crawl(&mut driver, &few, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.pages.len(), 2);
        assert_eq!(report.stopped, Some(CrawlStop::PageLimit));

        let mut driver = site();
        let report = crawl(
            &mut driver,
            &spec("https://site.test/docs/"),
            &AtomicBool::new(true),
        )
        .unwrap();
        assert!(driver.opened.is_empty());
        assert_eq!(report.stopped, Some(CrawlStop::Cancelled));

        let mut driver = site();
        driver.pages.insert(
            "https://site.test/docs/a".into(),
            (String::new(), 0, Vec::new()),
        );
        let report = crawl(
            &mut driver,
            &spec("https://site.test/docs/"),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.stopped, Some(CrawlStop::WorkerFailed));
        assert_eq!(driver.opened.len(), 2);

        // A page that fails as the worker reports it (a download link, a load
        // timeout) is recorded, and the crawl goes on.
        let mut driver = site();
        driver.pages.insert(
            "https://site.test/docs/a".into(),
            (String::new(), 1, Vec::new()),
        );
        let report = crawl(
            &mut driver,
            &spec("https://site.test/docs/"),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.stopped, None);
        assert!(report.pages[1].failure.is_some());
        assert!(driver
            .opened
            .contains(&"https://site.test/docs/b".to_owned()));
    }

    #[test]
    fn whitespace_long_links_fragments_and_repeated_deep_links() {
        let long = format!("/docs/{}", "x".repeat(MAX_LINK_BYTES));
        let refs = [
            "/docs/.. ",
            "/docs/a\t",
            " /docs/a",
            long.as_str(),
            "/docs/deep",
            "/docs/deep",
        ];
        let mut driver = Site::new(&[
            (
                "https://site.test/docs/",
                "https://site.test/docs/",
                200,
                &refs,
            ),
            // A redirect whose final URL carries a fragment.
            (
                "https://site.test/docs/deep",
                "https://site.test/docs/#top",
                200,
                &[],
            ),
        ]);
        let mut shallow = spec("https://site.test/docs/");
        shallow.max_depth = 0;
        let report = crawl(&mut driver, &shallow, &AtomicBool::new(false)).unwrap();
        let unnormalized = report
            .skipped
            .iter()
            .filter(|s| s.reason == SkipReason::Unnormalized)
            .count();
        assert_eq!(unnormalized, 4);
        // Reported once although linked twice.
        assert_eq!(
            report
                .skipped
                .iter()
                .filter(|s| s.reason == SkipReason::TooDeep)
                .count(),
            1
        );
        let mut deep = spec("https://site.test/docs/");
        deep.max_depth = 1;
        let mut driver = Site::new(&[
            (
                "https://site.test/docs/",
                "https://site.test/docs/",
                200,
                &["/docs/deep"],
            ),
            (
                "https://site.test/docs/deep",
                "https://site.test/docs/#top",
                200,
                &[],
            ),
        ]);
        let report = crawl(&mut driver, &deep, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            report.pages[1].failure.as_deref(),
            Some("redirected onto a page already read"),
            "a fragment made a second key"
        );
    }

    #[test]
    fn the_scope_follows_the_reference_rule() {
        assert_eq!(scope_of("/docs/"), ("/docs/".into(), None));
        assert_eq!(scope_of("/docs/intro.html"), ("/docs/".into(), None));
        assert_eq!(scope_of("/docs"), ("/docs/".into(), Some("/docs".into())));
        assert_eq!(
            scope_of("/docs/v1.x"),
            ("/docs/v1.x/".into(), Some("/docs/v1.x".into()))
        );
        assert_eq!(scope_of("/"), ("/".into(), None));
        let (scope, _) = Scope::of(&spec("https://site.test/docs")).unwrap();
        assert!(scope.admit("/docs").is_ok());
        assert!(scope.admit("/docs?page=2").is_ok());
        assert!(scope.admit("/docs/a").is_ok());
        assert_eq!(scope.admit("/docsx"), Err(SkipReason::OutOfScope));
        assert_eq!(scope.admit("/other"), Err(SkipReason::OutOfScope));
    }

    #[test]
    fn robots_txt_is_read_first_and_honoured_for_links_starts_and_redirects() {
        let mut driver = site();
        driver.texts.insert(
            "https://site.test/robots.txt".into(),
            (
                200,
                "User-agent: *\nDisallow: /docs/a\nDisallow: /docs/c\nAllow: /docs/\n".into(),
            ),
        );
        let mut wanted = spec("https://site.test/docs/");
        wanted.robots = true;
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(driver.opened[0], "https://site.test/robots.txt");
        assert_eq!(report.robots_status, Some(200));
        assert!(!driver
            .opened
            .contains(&"https://site.test/docs/a".to_owned()));
        assert!(reasons(&report).contains(&("https://site.test/docs/a", SkipReason::Robots)));
        // b redirects onto c, which robots.txt disallows: not read.
        let b = report
            .pages
            .iter()
            .find(|p| p.url.ends_with("/docs/b"))
            .unwrap();
        assert_eq!(
            b.failure.as_deref(),
            Some("redirected onto a page robots.txt disallows")
        );
        assert!(b.extraction.is_none());

        // A disallowed start opens nothing.
        let mut driver = site();
        driver.texts.insert(
            "https://site.test/robots.txt".into(),
            (200, "User-agent: orcel\nDisallow: /\n".into()),
        );
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert!(report.pages.is_empty());
        assert_eq!(
            reasons(&report),
            [("https://site.test/docs/", SkipReason::Robots)]
        );

        // No robots.txt (404) allows everything.
        let mut driver = site();
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.robots_status, Some(404));
        assert!(report.pages.len() > 1);

        // A cut robots.txt, or one with more rules than kept, is not
        // honoured in part: the crawl stops before any page.
        let mut many = String::from("User-agent: *\n");
        for i in 0..crate::robots::MAX_ROBOTS_RULES + 1 {
            many.push_str(&format!("Disallow: /x{i}\n"));
        }
        for answer in [
            (1200, "User-agent: *\nDisallow: /a\n".to_owned()),
            (200, many),
        ] {
            let mut driver = site();
            driver
                .texts
                .insert("https://site.test/robots.txt".into(), answer);
            let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
            assert_eq!(report.stopped, Some(CrawlStop::RobotsUnreachable));
            assert!(report.pages.is_empty());
        }

        // A cut HTML page with no robots records is no robots.txt.
        let mut driver = site();
        driver.texts.insert(
            "https://site.test/robots.txt".into(),
            (1200, "<html><body>An app shell</body></html>".into()),
        );
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.stopped, None);
        assert!(report.pages.len() > 1);

        // A 5xx answer, or none, stops the crawl before any page.
        for answer in [(503, String::new()), (0, String::new())] {
            let mut driver = site();
            driver
                .texts
                .insert("https://site.test/robots.txt".into(), answer);
            let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
            assert_eq!(report.stopped, Some(CrawlStop::RobotsUnreachable));
            assert!(report.pages.is_empty());
        }

        // Cancelled before it starts: not even robots.txt is fetched, so an
        // unreachable robots.txt cannot mask the cancellation.
        for answer in [None, Some((503, String::new())), Some((0, String::new()))] {
            let mut driver = site();
            if let Some(answer) = answer {
                driver
                    .texts
                    .insert("https://site.test/robots.txt".into(), answer);
            }
            let report = crawl(&mut driver, &wanted, &AtomicBool::new(true)).unwrap();
            assert_eq!(report.stopped, Some(CrawlStop::Cancelled));
            assert!(driver.opened.is_empty(), "{:?}", driver.opened);
            assert_eq!(report.robots_status, None);
        }
    }

    #[test]
    fn sitemaps_seed_the_queue_at_depth_one_within_scope_and_robots() {
        let mut driver = site();
        driver.pages.insert(
            "https://site.test/docs/only-in-sitemap".into(),
            (
                "https://site.test/docs/only-in-sitemap".into(),
                200,
                Vec::new(),
            ),
        );
        driver.texts.insert(
            "https://site.test/robots.txt".into(),
            (
                200,
                "User-agent: *\nDisallow: /docs/blocked\nSitemap: https://site.test/index.xml\nSitemap: https://other.test/s.xml\n".into(),
            ),
        );
        driver.texts.insert(
            "https://site.test/index.xml".into(),
            (
                200,
                "<sitemapindex><sitemap><loc>https://site.test/pages.xml</loc></sitemap><sitemap><loc>https://other.test/x.xml</loc></sitemap></sitemapindex>".into(),
            ),
        );
        driver.texts.insert(
            "https://site.test/pages.xml".into(),
            (
                200,
                "<urlset><url><loc>https://site.test/docs/only-in-sitemap</loc></url><url><loc>https://site.test/docs/blocked</loc></url><url><loc>https://site.test/elsewhere</loc></url></urlset>".into(),
            ),
        );
        let mut wanted = spec("https://site.test/docs/");
        wanted.robots = true;
        wanted.sitemaps = true;
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.sitemaps_read, 2);
        assert!(!driver.opened.iter().any(|u| u.contains("other.test")));
        let only = report
            .pages
            .iter()
            .find(|p| p.url.ends_with("/only-in-sitemap"))
            .expect("the sitemap page was crawled");
        assert_eq!(only.depth, 1);
        assert!(reasons(&report).contains(&("https://site.test/docs/blocked", SkipReason::Robots)));
        assert!(reasons(&report).contains(&("https://site.test/elsewhere", SkipReason::OutOfScope)));

        // A sitemap robots.txt disallows is not opened, and one that yields
        // no location (an XSLT-transformed page) is counted apart.
        let mut driver = site();
        driver.texts.insert(
            "https://site.test/robots.txt".into(),
            (200, "User-agent: *\nDisallow: /sitemap.xml\n".into()),
        );
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert!(!driver
            .opened
            .contains(&"https://site.test/sitemap.xml".to_owned()));
        assert!(reasons(&report).contains(&("https://site.test/sitemap.xml", SkipReason::Robots)));
        let mut driver = site();
        driver.texts.insert(
            "https://site.test/sitemap.xml".into(),
            (200, "<html><body>Styled sitemap</body></html>".into()),
        );
        let mut plain = spec("https://site.test/docs/");
        plain.sitemaps = true;
        let report = crawl(&mut driver, &plain, &AtomicBool::new(false)).unwrap();
        assert_eq!((report.sitemaps_read, report.sitemaps_empty), (0, 1));
        // Cancellation is checked before each sitemap too.
        let mut driver = site();
        let report = crawl(&mut driver, &plain, &AtomicBool::new(true)).unwrap();
        assert_eq!(report.stopped, Some(CrawlStop::Cancelled));
        assert!(driver.opened.is_empty());

        // Without robots.txt sitemaps, /sitemap.xml is tried.
        let mut driver = site();
        let mut plain = spec("https://site.test/docs/");
        plain.sitemaps = true;
        crawl(&mut driver, &plain, &AtomicBool::new(false)).unwrap();
        assert!(driver
            .opened
            .contains(&"https://site.test/sitemap.xml".to_owned()));
    }

    #[test]
    fn the_deadline_is_checked_between_pages() {
        struct Slow(Site);
        impl CrawlDriver for Slow {
            fn open(&mut self, url: &str) -> Result<Visit, HostError> {
                std::thread::sleep(Duration::from_millis(30));
                self.0.open(url)
            }
            fn links(&mut self) -> Result<Vec<String>, HostError> {
                self.0.links()
            }
            fn extract(&mut self, options: ExtractOptions) -> Result<PageExtraction, HostError> {
                self.0.extract(options)
            }
            fn lost(&self) -> bool {
                self.0.lost()
            }
            fn fetch_text(&mut self, url: &str) -> Result<TextDocument, HostError> {
                self.0.fetch_text(url)
            }
        }
        let mut quick = spec("https://site.test/docs/");
        quick.deadline = Duration::from_millis(10);
        let mut driver = Slow(site());
        let report = crawl(&mut driver, &quick, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.pages.len(), 1);
        assert_eq!(report.stopped, Some(CrawlStop::Deadline));
    }

    #[test]
    fn a_map_opens_pages_without_extracting_and_a_failed_extraction_is_recorded() {
        let mut map = spec("https://site.test/docs/");
        map.extract = None;
        let mut driver = site();
        let report = crawl(&mut driver, &map, &AtomicBool::new(false)).unwrap();
        assert!(report.pages.iter().all(|p| p.extraction.is_none()));
        // No exclude here: /docs/private/x is in scope too.
        assert_eq!(report.discovered.len(), 6);

        let mut driver = site();
        driver.fail_extract = true;
        let report = crawl(
            &mut driver,
            &spec("https://site.test/docs/"),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(report.pages[0].failure.is_some());
        // Its links are still followed.
        assert!(report.pages.len() > 1);
    }

    #[test]
    fn includes_scope_and_bad_specs() {
        let mut only_a = spec("https://site.test/docs/");
        only_a.include_paths = vec!["/docs/a".into()];
        // The start page must pass its own filters.
        assert!(crawl(&mut site(), &only_a, &AtomicBool::new(false)).is_err());
        only_a.include_paths = vec!["/docs/a".into(), "/docs/".into()];
        assert!(crawl(&mut site(), &only_a, &AtomicBool::new(false)).is_ok());
        // A start page names its directory as the scope.
        let (scope, start) = Scope::of(&spec("https://site.test/docs/intro.html?x=1#top")).unwrap();
        assert_eq!(scope.prefix, "/docs/");
        assert_eq!(start, "https://site.test/docs/intro.html?x=1");
        for bad in [
            "http://site.test/",
            "https://site.test:8443/",
            "https://user@site.test/",
            "https://site.test/a/../b",
            "javascript:alert(1)",
        ] {
            assert!(
                crawl(&mut site(), &spec(bad), &AtomicBool::new(false)).is_err(),
                "{bad}"
            );
        }
        let mut wide = spec(S);
        wide.max_pages = MAX_CRAWL_PAGES + 1;
        assert!(crawl(&mut site(), &wide, &AtomicBool::new(false)).is_err());
        let mut deep = spec(S);
        deep.max_depth = MAX_CRAWL_DEPTH + 1;
        assert!(crawl(&mut site(), &deep, &AtomicBool::new(false)).is_err());
        let mut long = spec(S);
        long.deadline = MAX_CRAWL_DURATION + Duration::from_secs(1);
        assert!(crawl(&mut site(), &long, &AtomicBool::new(false)).is_err());
        let mut patterns = spec(S);
        patterns.exclude_paths = vec!["no-slash".into()];
        assert!(crawl(&mut site(), &patterns, &AtomicBool::new(false)).is_err());
        patterns.exclude_paths = vec!["/x".into(); MAX_PATH_PATTERNS + 1];
        assert!(crawl(&mut site(), &patterns, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn the_url_memory_and_the_skip_report_are_bounded() {
        let many: Vec<String> = (0..MAX_CRAWL_URLS + 50)
            .map(|i| format!("/docs/p{i}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let mut driver = Site::new(&[(
            "https://site.test/docs/",
            "https://site.test/docs/",
            200,
            &refs,
        )]);
        let mut wanted = spec("https://site.test/docs/");
        wanted.max_pages = 1;
        let report = crawl(&mut driver, &wanted, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.discovered.len(), MAX_CRAWL_URLS);
        // The start URL is one of the remembered ones.
        assert_eq!(report.skipped.len(), 51);
        assert!(report
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::TooMany));
        let junk: Vec<String> = (0..MAX_SKIPPED_REPORTED + 7)
            .map(|i| format!("https://other.test/{i}"))
            .collect();
        let refs: Vec<&str> = junk.iter().map(String::as_str).collect();
        let mut driver = Site::new(&[(
            "https://site.test/docs/",
            "https://site.test/docs/",
            200,
            &refs,
        )]);
        let report = crawl(
            &mut driver,
            &spec("https://site.test/docs/"),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(report.skipped.len(), MAX_SKIPPED_REPORTED);
        assert_eq!(report.skipped_unreported, 7);
    }
}
