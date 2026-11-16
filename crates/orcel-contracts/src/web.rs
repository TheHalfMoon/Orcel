//! Orcel-owned web request contracts (spec sections 4.11, 5.3 and 5.4).
//!
//! These are the requests that cross from the pure Firecrawl-compatible
//! mapping layer (`orcel-web`) into `orceld`. They hold no browser-host
//! type. Everything here is shape and bounds: no request is sent, no
//! credential is resolved and no capability is enabled by this module.
//!
//! The shapes can represent pending founder decisions without deciding
//! them:
//! - crawl budgets are data (`CrawlBudget`), so raised limits (FD-UP-11)
//!   are a configuration value checked by `CrawlBudget::admits`, not a code
//!   change;
//! - custom request headers (FD-UP-8) are carried as `RequestHeader`s whose
//!   credential-bearing names must reference a protected credential by id,
//!   so a secret never travels in a request, an approval digest or an
//!   audit event;
//! - stealth (FD-UP-2) is an explicit opt-in field that defaults to `off`;
//!   honouring it is a policy and capability decision (`blocked` until
//!   then).

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::Contract;

/// At most this many include and this many exclude path filters.
pub const MAX_PATH_FILTERS: usize = 16;
/// Each path filter, tag selector or header name is at most this long.
pub const MAX_FILTER_BYTES: usize = 256;
/// At most this many request headers per request.
pub const MAX_REQUEST_HEADERS: usize = 32;
/// A literal header value is at most this long.
pub const MAX_HEADER_VALUE_BYTES: usize = 4 * 1024;
/// URLs and credential references are at most this long.
pub const MAX_URL_BYTES: usize = 2 * 1024;
/// Credential references are opaque ids of at most this many bytes.
pub const MAX_CREDENTIAL_REF_BYTES: usize = 256;

/// Header names (lowercase) that may carry credentials. A request may name
/// them only with a `HeaderValue::Credential` reference, never a literal.
pub const PROTECTED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
];

/// Header names (lowercase) that the transport owns and a request may never
/// set, literal or not.
pub const FORBIDDEN_HEADER_NAMES: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "proxy-connection",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SitemapMode {
    Include,
    Skip,
    Only,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Fetch,
    Chromium,
    /// Wave 2.
    Obscura,
}

/// Whether a crawl-shaped request is a crawl or a map run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlMode {
    Crawl,
    Map,
}

/// Fingerprinting and bot-detection evasion (FD-UP-2). `off` unless the
/// caller opts in explicitly; an opt-in is honoured only where the
/// capability report says the stealth capability is `available`, and fails
/// `POLICY_BLOCKED` otherwise. Never a silent upgrade or downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StealthMode {
    #[default]
    Off,
    OptIn,
}

impl StealthMode {
    fn is_off(&self) -> bool {
        *self == Self::Off
    }
}

/// Output formats of the section 5.3 subset Orcel can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractFormat {
    Markdown,
    Html,
    RawHtml,
    Links,
    ChangeTracking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractRequest {
    pub formats: Vec<ExtractFormat>,
    #[serde(default)]
    pub only_main_content: bool,
    /// CSS selectors, at most `MAX_PATH_FILTERS`.
    #[serde(default)]
    pub include_tags: Vec<String>,
    #[serde(default)]
    pub exclude_tags: Vec<String>,
}

/// A header value: a literal, or a reference to a credential held by
/// `orceld` under the private state root. A reference is resolved only at
/// send time inside the transport; the secret never appears in a contract,
/// an approval digest, a job spec or an audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderValue {
    Literal { value: String },
    Credential { credential_ref: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeader {
    pub name: String,
    pub value: HeaderValue,
}

/// Why a web request falls outside its contract bounds. It names the field
/// and never echoes a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebContractError {
    /// A field is empty, too long, or holds a forbidden character.
    InvalidField(&'static str),
    /// A count or limit is outside the configured budget.
    OverBudget(&'static str),
    /// A header name the transport owns.
    ForbiddenHeader,
    /// A credential-bearing header given as a literal.
    ProtectedHeaderLiteral,
    /// Robots obedience cannot be switched off.
    RobotsRequired,
}

impl fmt::Display for WebContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid field: {field}"),
            Self::OverBudget(field) => write!(f, "over budget: {field}"),
            Self::ForbiddenHeader => f.write_str("header name is reserved for the transport"),
            Self::ProtectedHeaderLiteral => {
                f.write_str("credential-bearing header must reference a protected credential")
            }
            Self::RobotsRequired => f.write_str("robots.txt obedience is required"),
        }
    }
}

impl std::error::Error for WebContractError {}

fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILTER_BYTES
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

impl RequestHeader {
    /// Whether `name` (any case) may only carry a credential reference.
    pub fn is_protected_name(name: &str) -> bool {
        PROTECTED_HEADER_NAMES
            .iter()
            .any(|protected| protected.eq_ignore_ascii_case(name))
    }

    /// Whether `name` (any case) is owned by the transport.
    pub fn is_forbidden_name(name: &str) -> bool {
        FORBIDDEN_HEADER_NAMES
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(name))
            || (name
                .get(..6)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("proxy-"))
                && !name.eq_ignore_ascii_case("proxy-authorization"))
    }

    /// Shape check: a token name, not transport-owned, and a credential
    /// reference for every credential-bearing name. Whether headers are
    /// honoured at all is a policy decision (FD-UP-8), not made here.
    pub fn check(&self) -> Result<(), WebContractError> {
        if !is_header_token(&self.name) {
            return Err(WebContractError::InvalidField("headers.name"));
        }
        if Self::is_forbidden_name(&self.name) {
            return Err(WebContractError::ForbiddenHeader);
        }
        match &self.value {
            HeaderValue::Literal { value } => {
                if Self::is_protected_name(&self.name) {
                    return Err(WebContractError::ProtectedHeaderLiteral);
                }
                if value.len() > MAX_HEADER_VALUE_BYTES
                    || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                {
                    return Err(WebContractError::InvalidField("headers.value"));
                }
            }
            HeaderValue::Credential { credential_ref } => {
                if credential_ref.is_empty()
                    || credential_ref.len() > MAX_CREDENTIAL_REF_BYTES
                    || credential_ref.bytes().any(|b| b.is_ascii_control())
                {
                    return Err(WebContractError::InvalidField("headers.credential_ref"));
                }
            }
        }
        Ok(())
    }
}

fn check_headers(headers: &[RequestHeader]) -> Result<(), WebContractError> {
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(WebContractError::OverBudget("headers"));
    }
    for (index, header) in headers.iter().enumerate() {
        header.check()?;
        if headers[..index]
            .iter()
            .any(|earlier| earlier.name.eq_ignore_ascii_case(&header.name))
        {
            return Err(WebContractError::InvalidField("headers.name"));
        }
    }
    Ok(())
}

fn check_url(url: &str, field: &'static str) -> Result<(), WebContractError> {
    if url.is_empty() || url.len() > MAX_URL_BYTES || url.bytes().any(|b| b.is_ascii_control()) {
        return Err(WebContractError::InvalidField(field));
    }
    Ok(())
}

fn check_filters(filters: &[String], field: &'static str) -> Result<(), WebContractError> {
    if filters.len() > MAX_PATH_FILTERS {
        return Err(WebContractError::OverBudget(field));
    }
    if filters
        .iter()
        .any(|filter| filter.is_empty() || filter.len() > MAX_FILTER_BYTES)
    {
        return Err(WebContractError::InvalidField(field));
    }
    Ok(())
}

impl ExtractRequest {
    pub fn check(&self) -> Result<(), WebContractError> {
        if self.formats.is_empty() {
            return Err(WebContractError::InvalidField("extract.formats"));
        }
        check_filters(&self.include_tags, "extract.include_tags")?;
        check_filters(&self.exclude_tags, "extract.exclude_tags")
    }
}

/// Configurable crawl and batch budget (FD-UP-11). Requests are checked
/// against a budget value rather than fixed constants, so a decided change
/// of limits is configuration. `WAVE1` holds SG-000108 slice 7's bounds;
/// raising any field needs its own security review. It is configuration
/// read by `orceld`, not a request: callers never supply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrawlBudget {
    pub max_pages: u32,
    pub max_depth: u32,
    pub max_duration_s: u32,
    pub max_remembered_urls: u32,
    /// Politeness floor between requests to one origin.
    pub min_delay_ms: u32,
    pub max_batch_urls: u32,
    /// Result store bound per job.
    pub max_job_result_bytes: u64,
}

impl CrawlBudget {
    /// SG-000108 slice 7 bounds, kept for Wave 1 unless FD-UP-11 changes
    /// them: 50 pages, depth 5, 600 s, 1,000 remembered URLs, 250 ms delay
    /// floor, 50 batch URLs, 20 MiB per job.
    pub const WAVE1: Self = Self {
        max_pages: 50,
        max_depth: 5,
        max_duration_s: 600,
        max_remembered_urls: 1_000,
        min_delay_ms: 250,
        max_batch_urls: 50,
        max_job_result_bytes: 20 * 1024 * 1024,
    };

    /// Whether a crawl or map request fits this budget and its shape bounds.
    pub fn admits(&self, request: &WebCrawlRequest) -> Result<(), WebContractError> {
        check_url(&request.start_url, "start_url")?;
        check_filters(&request.include_paths, "include_paths")?;
        check_filters(&request.exclude_paths, "exclude_paths")?;
        if request.max_pages == 0 || request.max_pages > self.max_pages {
            return Err(WebContractError::OverBudget("max_pages"));
        }
        if request.max_depth > self.max_depth {
            return Err(WebContractError::OverBudget("max_depth"));
        }
        if request.deadline_s == 0 || request.deadline_s > self.max_duration_s {
            return Err(WebContractError::OverBudget("deadline_s"));
        }
        if request.delay_ms < self.min_delay_ms {
            return Err(WebContractError::OverBudget("delay_ms"));
        }
        if !request.robots {
            return Err(WebContractError::RobotsRequired);
        }
        if let Some(search) = &request.search {
            if search.is_empty() || search.len() > MAX_FILTER_BYTES {
                return Err(WebContractError::InvalidField("search"));
            }
        }
        if let Some(extract) = &request.extract {
            extract.check()?;
        }
        check_headers(&request.headers)
    }

    /// Whether a batch scrape request fits this budget and its shape bounds.
    pub fn admits_batch(&self, request: &WebBatchScrapeRequest) -> Result<(), WebContractError> {
        if request.urls.is_empty() || request.urls.len() > self.max_batch_urls as usize {
            return Err(WebContractError::OverBudget("urls"));
        }
        for url in &request.urls {
            check_url(url, "urls")?;
        }
        request.extract.check()?;
        check_headers(&request.headers)
    }
}

/// A crawl or map run (one `orcel-jobs` unit), produced by `orcel-web` and
/// translated by `orceld` into the browser host's crawl spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebCrawlRequest {
    /// `"orcel.web-crawl/1"`.
    pub contract: String,
    pub mode: CrawlMode,
    pub start_url: String,
    #[serde(default)]
    pub include_paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    pub max_pages: u32,
    pub max_depth: u32,
    pub deadline_s: u32,
    pub sitemap: SitemapMode,
    /// Always `true` in Wave 1.
    pub robots: bool,
    /// Map ranking (WI-02).
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub extract: Option<ExtractRequest>,
    pub engine: Engine,
    /// Politeness delay, at least the budget's `min_delay_ms`.
    pub delay_ms: u32,
    /// Custom headers (FD-UP-8). Empty unless that decision allows them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<RequestHeader>,
    #[serde(default, skip_serializing_if = "StealthMode::is_off")]
    pub stealth: StealthMode,
}

impl Contract for WebCrawlRequest {
    const CONTRACT: &'static str = "orcel.web-crawl/1";
}

/// The `arguments` of a `web/scrape` request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebScrapeRequest {
    /// `"orcel.web-scrape/1"`.
    pub contract: String,
    pub url: String,
    pub extract: ExtractRequest,
    pub engine: Engine,
    /// Capped by the engine's own timeouts.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub wait_for_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<RequestHeader>,
    #[serde(default, skip_serializing_if = "StealthMode::is_off")]
    pub stealth: StealthMode,
}

impl Contract for WebScrapeRequest {
    const CONTRACT: &'static str = "orcel.web-scrape/1";
}

impl WebScrapeRequest {
    pub fn check(&self) -> Result<(), WebContractError> {
        check_url(&self.url, "url")?;
        self.extract.check()?;
        check_headers(&self.headers)
    }
}

/// A batch scrape job: each URL is an independent unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebBatchScrapeRequest {
    /// `"orcel.web-batch-scrape/1"`.
    pub contract: String,
    pub urls: Vec<String>,
    pub extract: ExtractRequest,
    pub engine: Engine,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<RequestHeader>,
    #[serde(default, skip_serializing_if = "StealthMode::is_off")]
    pub stealth: StealthMode,
}

impl Contract for WebBatchScrapeRequest {
    const CONTRACT: &'static str = "orcel.web-batch-scrape/1";
}
