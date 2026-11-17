//! Orcel-owned web request contracts (spec sections 4.11, 4.12, 4.16, 5.3
//! and 5.4; FD-UP-2, FD-UP-5, FD-UP-8 and FD-UP-11 decided).
//!
//! These are the requests that cross from the pure Firecrawl-compatible
//! mapping layer (`orcel-web`) into `orceld`. They hold no browser-host
//! type. Everything here is shape and bounds: no request is sent, no secret
//! is resolved, no permission is granted and no capability is enabled by
//! this module.
//!
//! - Crawl budgets are user configuration (`CrawlBudget`); the only fixed
//!   limits are resource-protection ceilings.
//! - Custom headers are `HeaderSpec`s. Credential-like names must name a
//!   secret held in the OS secret store (`secret:<name>`); a secret value
//!   never travels in a request, an approval digest, a job spec or an audit
//!   event.
//! - Sensitive web features are explicit, per-request opt-ins in the
//!   privacy profile; each needs a per-client permission (C-31), checked by
//!   policy, not here.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::lease::MAX_TASK_BYTES;
use crate::{Contract, MAX_ID_BYTES};

/// At most this many include and this many exclude path filters.
pub const MAX_PATH_FILTERS: usize = 16;
/// Each path filter, tag selector, search text or header name is at most
/// this long.
pub const MAX_FILTER_BYTES: usize = 256;
/// At most this many request headers per request.
pub const MAX_REQUEST_HEADERS: usize = 32;
/// A literal header value is at most this long.
pub const MAX_HEADER_VALUE_BYTES: usize = 4 * 1024;
/// URLs and origins are at most this long.
pub const MAX_URL_BYTES: usize = 2 * 1024;
/// A secret name is at most this long.
pub const MAX_SECRET_NAME_BYTES: usize = 128;
/// A destination scope names at most this many origins.
pub const MAX_SCOPE_ORIGINS: usize = 64;
/// A batch names at most this many URLs regardless of budget (resource
/// protection for one approval prompt).
pub const MAX_BATCH_URLS_CEILING: u32 = 10_000;
/// The Firecrawl-facing spelling of a secret reference: `secret:<name>`.
pub const SECRET_REF_PREFIX: &str = "secret:";

/// Credential-like header names (lowercase) that must always reference a
/// secret. `HeaderSpec::check` takes a configurable list on top of these.
pub const BASE_PROTECTED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
];

/// Hop-by-hop and framing header names (lowercase) that the transport owns
/// and a request may never set.
pub const FORBIDDEN_HEADER_NAMES: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
    "expect",
    "keep-alive",
    "trailer",
    "proxy-connection",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SitemapMode {
    Include,
    Skip,
    Only,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    Fetch,
    Chromium,
    /// Track B.
    Obscura,
}

/// Whether a crawl-shaped request is a crawl or a map run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CrawlMode {
    Crawl,
    Map,
}

/// Output formats Orcel produces in Wave 1 (section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ExtractFormat {
    Markdown,
    Html,
    RawHtml,
    Links,
    ChangeTracking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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

/// Sensitive, opt-in web features (section 4.16). Each is off unless the
/// request names it, and each needs the client permission
/// `web.privacy.sensitive:<feature>`. CAPTCHA solving, login, paywall or
/// access-control bypass and ignoring robots rules are never offered and
/// have no variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SensitiveFeature {
    UserAgentOverride,
    DeviceEmulation,
    LocaleOverride,
    TimezoneOverride,
    GeolocationOverride,
    UserProxy,
    FingerprintRandomisation,
    TlsImpersonation,
}

impl SensitiveFeature {
    pub const ALL: [Self; 8] = [
        Self::UserAgentOverride,
        Self::DeviceEmulation,
        Self::LocaleOverride,
        Self::TimezoneOverride,
        Self::GeolocationOverride,
        Self::UserProxy,
        Self::FingerprintRandomisation,
        Self::TlsImpersonation,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UserAgentOverride => "user_agent_override",
            Self::DeviceEmulation => "device_emulation",
            Self::LocaleOverride => "locale_override",
            Self::TimezoneOverride => "timezone_override",
            Self::GeolocationOverride => "geolocation_override",
            Self::UserProxy => "user_proxy",
            Self::FingerprintRandomisation => "fingerprint_randomisation",
            Self::TlsImpersonation => "tls_impersonation",
        }
    }

    /// The per-client permission that must be granted before policy
    /// honours this feature (`web.privacy.sensitive:<feature>`).
    pub fn permission(self) -> String {
        format!("web.privacy.sensitive:{}", self.wire_name())
    }
}

/// The privacy profile a request runs under. `profile` names the
/// privacy-and-compatibility defaults (on by default, section 4.16);
/// `sensitive` lists the opt-in features requested, empty by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PrivacyProfileRef {
    /// `"default"` in Wave 1.
    pub profile: String,
    #[serde(default)]
    pub sensitive: Vec<SensitiveFeature>,
}

impl Default for PrivacyProfileRef {
    fn default() -> Self {
        Self {
            profile: "default".to_owned(),
            sensitive: Vec::new(),
        }
    }
}

impl PrivacyProfileRef {
    /// The client permissions this profile needs, sorted and deduplicated.
    pub fn required_permissions(&self) -> Vec<String> {
        let mut features = self.sensitive.clone();
        features.sort();
        features.dedup();
        features
            .into_iter()
            .map(SensitiveFeature::permission)
            .collect()
    }

    fn check(&self) -> Result<(), WebContractError> {
        if !is_bounded_token(&self.profile, MAX_FILTER_BYTES) {
            return Err(WebContractError::InvalidField("privacy.profile"));
        }
        if self.sensitive.len() > SensitiveFeature::ALL.len() {
            return Err(WebContractError::InvalidField("privacy.sensitive"));
        }
        Ok(())
    }
}

/// A header value: a literal, or the name of a secret held in the OS secret
/// store and bound to its destination origins (section 4.12). On the wire:
/// `{"literal": "en"}` or `{"secret": "docs-token"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HeaderValue {
    Literal(String),
    Secret(String),
}

impl HeaderValue {
    /// Maps a Firecrawl header value: `secret:<name>` names a secret, any
    /// other value is a literal.
    pub fn from_firecrawl(value: &str) -> Self {
        match value.strip_prefix(SECRET_REF_PREFIX) {
            Some(name) => Self::Secret(name.to_owned()),
            None => Self::Literal(value.to_owned()),
        }
    }
}

/// A custom request header (FD-UP-8 decided).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct HeaderSpec {
    pub name: String,
    pub value: HeaderValue,
}

/// Why a web request falls outside its contract bounds. It names the field
/// and never echoes a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebContractError {
    /// A field is empty, too long, or holds a forbidden character.
    InvalidField(&'static str),
    /// A count or limit is outside the budget or its ceilings.
    OverBudget(&'static str),
    /// A header name the transport owns.
    ForbiddenHeader,
    /// A credential-like header given as a literal.
    ProtectedHeaderLiteral,
    /// A URL outside the declared destination scope.
    OutOfScope(&'static str),
}

impl fmt::Display for WebContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid field: {field}"),
            Self::OverBudget(field) => write!(f, "over budget: {field}"),
            Self::ForbiddenHeader => f.write_str("header name is reserved for the transport"),
            Self::ProtectedHeaderLiteral => {
                f.write_str("credential-like header must reference a stored secret")
            }
            Self::OutOfScope(field) => write!(f, "outside the destination scope: {field}"),
        }
    }
}

impl std::error::Error for WebContractError {}

fn is_bounded_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

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

impl HeaderSpec {
    /// Whether `name` (any case) is credential-like: in the base list or
    /// in the configured `extra_protected` list.
    pub fn is_protected_name(name: &str, extra_protected: &[String]) -> bool {
        BASE_PROTECTED_HEADER_NAMES
            .iter()
            .any(|protected| protected.eq_ignore_ascii_case(name))
            || extra_protected
                .iter()
                .any(|protected| protected.eq_ignore_ascii_case(name))
    }

    /// Whether `name` (any case) is owned by the transport.
    pub fn is_forbidden_name(name: &str) -> bool {
        FORBIDDEN_HEADER_NAMES
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(name))
    }

    /// Shape check: a token name, not transport-owned, a secret reference
    /// for every credential-like name, and literal values of visible ASCII
    /// plus space and horizontal tab only (every other control byte, DEL
    /// and non-ASCII refused). Whether this client may send custom headers
    /// or use a given secret is a per-client permission checked by policy.
    pub fn check(&self, extra_protected: &[String]) -> Result<(), WebContractError> {
        if !is_header_token(&self.name) {
            return Err(WebContractError::InvalidField("headers.name"));
        }
        if Self::is_forbidden_name(&self.name) {
            return Err(WebContractError::ForbiddenHeader);
        }
        match &self.value {
            HeaderValue::Literal(value) => {
                if Self::is_protected_name(&self.name, extra_protected) {
                    return Err(WebContractError::ProtectedHeaderLiteral);
                }
                if value.len() > MAX_HEADER_VALUE_BYTES
                    || !value
                        .bytes()
                        .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
                {
                    return Err(WebContractError::InvalidField("headers.value"));
                }
            }
            HeaderValue::Secret(name) => {
                if !is_bounded_token(name, MAX_SECRET_NAME_BYTES) {
                    return Err(WebContractError::InvalidField("headers.secret"));
                }
            }
        }
        Ok(())
    }
}

fn check_headers(
    headers: &[HeaderSpec],
    extra_protected: &[String],
) -> Result<(), WebContractError> {
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(WebContractError::OverBudget("headers"));
    }
    for (index, header) in headers.iter().enumerate() {
        header.check(extra_protected)?;
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
    if url.is_empty() || url.len() > MAX_URL_BYTES || !url.bytes().all(|b| b.is_ascii_graphic()) {
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

fn check_task(task: &str) -> Result<(), WebContractError> {
    if task.is_empty() || task.len() > MAX_TASK_BYTES || task.chars().any(char::is_control) {
        return Err(WebContractError::InvalidField("task"));
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

/// The destination scope a job's approval binds (section 4.11). Wave 1:
/// exactly one origin (policy); Wave 2: a declared origin set. Origins are
/// written `https://host[:port]`, lowercase, without a default port, path,
/// query, fragment or user info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WebScope {
    pub origins: Vec<String>,
}

fn is_origin(origin: &str) -> bool {
    let Some(authority) = origin.strip_prefix("https://") else {
        return false;
    };
    origin.len() <= MAX_URL_BYTES
        && !authority.is_empty()
        && !authority.ends_with(":443")
        && authority.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
        })
}

impl WebScope {
    pub fn check(&self) -> Result<(), WebContractError> {
        if self.origins.is_empty() || self.origins.len() > MAX_SCOPE_ORIGINS {
            return Err(WebContractError::InvalidField("scope.origins"));
        }
        if !self.origins.iter().all(|origin| is_origin(origin)) {
            return Err(WebContractError::InvalidField("scope.origins"));
        }
        Ok(())
    }

    /// Whether `url` lies inside one of the scope's origins: the origin
    /// itself, or the origin followed by `/`, `?` or `#`. A prefix check
    /// only: `orceld` still parses and revalidates every page URL and its
    /// resolved addresses.
    pub fn contains_url(&self, url: &str) -> bool {
        self.origins.iter().any(|origin| {
            url.strip_prefix(origin.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
        })
    }
}

/// Request ids supplied by the front, never by the body (section 4.11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Ids {
    /// UUIDv4 generated by the front per HTTP request or MCP call.
    pub request_id: String,
    /// MCP session id, or the REST token id.
    pub client_session_id: String,
    /// The transport's configured default workspace.
    pub workspace_id: String,
    /// The client principal.
    pub principal_id: String,
}

impl Ids {
    pub fn check(&self) -> Result<(), WebContractError> {
        let bounded = |value: &str| !value.is_empty() && value.len() <= MAX_ID_BYTES;
        if bounded(&self.request_id)
            && bounded(&self.client_session_id)
            && bounded(&self.workspace_id)
            && bounded(&self.principal_id)
        {
            Ok(())
        } else {
            Err(WebContractError::InvalidField("ids"))
        }
    }
}

/// User-configurable crawl and batch budget (FD-UP-11 decided). The user
/// changes it from the local control path only; `DEFAULT` holds the
/// shipped defaults. The only fixed limits are the resource-protection
/// ceilings checked by `check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CrawlBudget {
    pub max_pages: u32,
    pub max_depth: u32,
    pub max_duration_s: u32,
    pub max_remembered_urls: u32,
    /// Politeness delay between requests to one origin.
    pub min_delay_ms: u32,
    pub max_batch_urls: u32,
    /// Result store bound per job.
    pub max_job_result_bytes: u64,
}

impl CrawlBudget {
    /// Shipped defaults: 50 pages, depth 5, 10 minutes, 1,000 remembered
    /// URLs, 250 ms delay, 50 batch URLs, 20 MiB per job.
    pub const DEFAULT: Self = Self {
        max_pages: 50,
        max_depth: 5,
        max_duration_s: 600,
        max_remembered_urls: 1_000,
        min_delay_ms: 250,
        max_batch_urls: 50,
        max_job_result_bytes: 20 * 1024 * 1024,
    };

    /// Resource-protection ceiling: the delay is never below this per
    /// origin, whatever the user configures.
    pub const MIN_DELAY_FLOOR_MS: u32 = 100;
    /// Resource-protection ceiling on the result store per job.
    pub const MAX_JOB_RESULT_BYTES_CEILING: u64 = 20 * 1024 * 1024;

    /// Whether a configured budget respects the resource-protection
    /// ceilings and is usable (every count positive).
    pub fn check(&self) -> Result<(), WebContractError> {
        if self.min_delay_ms < Self::MIN_DELAY_FLOOR_MS {
            return Err(WebContractError::OverBudget("budget.min_delay_ms"));
        }
        if self.max_job_result_bytes == 0
            || self.max_job_result_bytes > Self::MAX_JOB_RESULT_BYTES_CEILING
        {
            return Err(WebContractError::OverBudget("budget.max_job_result_bytes"));
        }
        if self.max_batch_urls == 0 || self.max_batch_urls > MAX_BATCH_URLS_CEILING {
            return Err(WebContractError::OverBudget("budget.max_batch_urls"));
        }
        if self.max_pages == 0 || self.max_duration_s == 0 || self.max_remembered_urls == 0 {
            return Err(WebContractError::OverBudget("budget"));
        }
        Ok(())
    }
}

impl Default for CrawlBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A crawl or map run (one `orcel-jobs` unit), produced by `orcel-web` and
/// translated by `orceld` into the browser host's crawl spec. Robots rules
/// are always obeyed, so there is no field to turn them off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WebCrawlRequest {
    /// `"orcel.web-crawl/1"`.
    pub contract: String,
    pub mode: CrawlMode,
    pub start_url: String,
    pub scope: WebScope,
    #[serde(default)]
    pub include_paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    pub max_pages: u32,
    pub max_depth: u32,
    pub deadline_s: u32,
    pub sitemap: SitemapMode,
    /// Map ranking (WI-02).
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub extract: Option<ExtractRequest>,
    pub engine: Engine,
    /// Politeness delay, at least the budget's `min_delay_ms`.
    pub delay_ms: u32,
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,
    #[serde(default)]
    pub privacy: PrivacyProfileRef,
    /// Declared task, at most `MAX_TASK_BYTES`, escaped for prompts.
    pub task: String,
}

impl Contract for WebCrawlRequest {
    const CONTRACT: &'static str = "orcel.web-crawl/1";
}

impl WebCrawlRequest {
    /// Shape and budget check against the user's `budget` and the
    /// configured credential-like header names.
    pub fn check(
        &self,
        budget: &CrawlBudget,
        extra_protected: &[String],
    ) -> Result<(), WebContractError> {
        check_url(&self.start_url, "start_url")?;
        self.scope.check()?;
        if !self.scope.contains_url(&self.start_url) {
            return Err(WebContractError::OutOfScope("start_url"));
        }
        check_filters(&self.include_paths, "include_paths")?;
        check_filters(&self.exclude_paths, "exclude_paths")?;
        if self.max_pages == 0 || self.max_pages > budget.max_pages {
            return Err(WebContractError::OverBudget("max_pages"));
        }
        if self.max_depth > budget.max_depth {
            return Err(WebContractError::OverBudget("max_depth"));
        }
        if self.deadline_s == 0 || self.deadline_s > budget.max_duration_s {
            return Err(WebContractError::OverBudget("deadline_s"));
        }
        if self.delay_ms < budget.min_delay_ms.max(CrawlBudget::MIN_DELAY_FLOOR_MS) {
            return Err(WebContractError::OverBudget("delay_ms"));
        }
        if let Some(search) = &self.search {
            if search.is_empty() || search.len() > MAX_FILTER_BYTES {
                return Err(WebContractError::InvalidField("search"));
            }
        }
        if let Some(extract) = &self.extract {
            extract.check()?;
        }
        self.privacy.check()?;
        check_task(&self.task)?;
        check_headers(&self.headers, extra_protected)
    }
}

/// The `arguments` of a `web/scrape` request envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,
    #[serde(default)]
    pub privacy: PrivacyProfileRef,
}

impl Contract for WebScrapeRequest {
    const CONTRACT: &'static str = "orcel.web-scrape/1";
}

impl WebScrapeRequest {
    pub fn check(&self, extra_protected: &[String]) -> Result<(), WebContractError> {
        check_url(&self.url, "url")?;
        self.extract.check()?;
        self.privacy.check()?;
        check_headers(&self.headers, extra_protected)
    }
}

/// A batch scrape job: each URL is an independent unit, all under one
/// approval bound to the task and the destination scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct WebBatchScrapeRequest {
    /// `"orcel.web-batch-scrape/1"`.
    pub contract: String,
    pub urls: Vec<String>,
    pub scope: WebScope,
    pub extract: ExtractRequest,
    pub engine: Engine,
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,
    #[serde(default)]
    pub privacy: PrivacyProfileRef,
    /// Declared task, at most `MAX_TASK_BYTES`, escaped for prompts.
    pub task: String,
}

impl Contract for WebBatchScrapeRequest {
    const CONTRACT: &'static str = "orcel.web-batch-scrape/1";
}

impl WebBatchScrapeRequest {
    pub fn check(
        &self,
        budget: &CrawlBudget,
        extra_protected: &[String],
    ) -> Result<(), WebContractError> {
        if self.urls.is_empty() || self.urls.len() > budget.max_batch_urls as usize {
            return Err(WebContractError::OverBudget("urls"));
        }
        self.scope.check()?;
        for url in &self.urls {
            check_url(url, "urls")?;
            if !self.scope.contains_url(url) {
                return Err(WebContractError::OutOfScope("urls"));
            }
        }
        self.extract.check()?;
        self.privacy.check()?;
        check_task(&self.task)?;
        check_headers(&self.headers, extra_protected)
    }
}
