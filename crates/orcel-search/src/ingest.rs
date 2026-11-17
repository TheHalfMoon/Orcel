//! Ingestion: a fetched response (or local HTML) becomes a [`CorpusDoc`].
//!
//! Adapted from `orcel-poc/src/ingest.ts` (Orcel-authored) with one change
//! of authority: this module never fetches. The proof of concept called
//! `fetch` itself; in Orcel the network belongs to `orceld`'s governed fetch
//! (SG-000040 transport, the WP1-08 fetch engine). That adapter fills a
//! [`FetchedResponse`] or a [`TransportFailure`] and this module turns it
//! into a document, a [`IngestOutcome::NotModified`] revalidation, or a typed
//! [`IngestError`].
//!
//! The five fetch error names (`bot_blocked`, `timeout`,
//! `target_unreachable`, `page_not_found`, `target_http_error`) follow
//! TinyFish's public per-URL error contract as recorded by the REA
//! (`06_tinyfish_feature_parity.md` T20; the MIT
//! `tinyfish-io/tinyfish-web-agent-integrations@73402549` Convex schema
//! stores these per-URL codes, for example `bot_blocked`). Only the names are
//! used: no TinyFish code, and nothing from the AGPL `bigset-oss`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::extract::{content_hash, extract_page, infer_category};
use crate::html::{HtmlLimit, MAX_HTML_BYTES};
use crate::types::CorpusDoc;
use crate::url;

/// Where the bytes of a document came from, with the HTTP validators needed
/// to revalidate it later.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestRecord {
    /// `governed-fetch`, `local-corpus`, or a fixture label.
    pub origin: String,
    /// The URL after redirects, when the fetch reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// The `ETag` response header, verbatim (weak validators keep `W/`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// The `Last-Modified` response header, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// When the bytes were fetched, in Unix milliseconds (caller's clock).
    pub fetched_at_ms: u64,
    /// When a `304 Not Modified` last confirmed the bytes, if ever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidated_at_ms: Option<u64>,
}

/// The conditional-request headers a revalidating fetch should send.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionalRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_none_match: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_modified_since: Option<String>,
}

impl ConditionalRequest {
    /// True when at least one validator is present.
    pub fn is_conditional(&self) -> bool {
        self.if_none_match.is_some() || self.if_modified_since.is_some()
    }

    /// Header pairs for the governed fetch, in a stable order. A value that
    /// is not a safe validator (see [`sanitize_validator`]) is left out, so a
    /// stored or hand-built value can never inject a header line.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(etag) = self.if_none_match.as_deref().and_then(sanitize_validator) {
            out.push(("If-None-Match", etag));
        }
        if let Some(date) = self
            .if_modified_since
            .as_deref()
            .and_then(sanitize_validator)
        {
            out.push(("If-Modified-Since", date));
        }
        out
    }
}

/// Longest `ETag` or `Last-Modified` value kept, in bytes.
pub const MAX_VALIDATOR_BYTES: usize = 256;

/// Returns the trimmed validator when it is non-empty, at most
/// [`MAX_VALIDATOR_BYTES`] long and made only of visible ASCII and spaces
/// (0x20 to 0x7E). Anything else, including CR, LF, NUL, tabs, other control
/// characters and non-ASCII, drops the validator entirely.
pub fn sanitize_validator(value: &str) -> Option<String> {
    let trimmed = value.trim_matches(' ');
    let safe = !trimmed.is_empty()
        && trimmed.len() <= MAX_VALIDATOR_BYTES
        && trimmed.bytes().all(|b| (0x20..=0x7e).contains(&b));
    safe.then(|| trimmed.to_string())
}

impl IngestRecord {
    /// The validators to replay when revalidating this document.
    pub fn conditional_request(&self) -> ConditionalRequest {
        ConditionalRequest {
            if_none_match: self.etag.clone(),
            if_modified_since: self.last_modified.clone(),
        }
    }

    /// True when the record is younger than `ttl_ms` at `now_ms`, counting
    /// from the later of the fetch and the last revalidation. A zero TTL is
    /// never fresh (TinyFish's `ttl: 0` means "live").
    pub fn is_fresh(&self, now_ms: u64, ttl_ms: u64) -> bool {
        let since = self.revalidated_at_ms.unwrap_or(0).max(self.fetched_at_ms);
        ttl_ms > 0 && now_ms.saturating_sub(since) < ttl_ms
    }
}

/// The machine-readable reason a fetch failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchErrorKind {
    /// An anti-bot interstitial or challenge answered instead of the page.
    BotBlocked,
    /// The transport gave up waiting.
    Timeout,
    /// DNS, connect, TLS or reset: no HTTP answer at all.
    TargetUnreachable,
    /// 404 or 410.
    PageNotFound,
    /// Any other non-success HTTP status.
    TargetHttpError,
}

impl FetchErrorKind {
    /// The wire code.
    pub fn code(self) -> &'static str {
        match self {
            Self::BotBlocked => "bot_blocked",
            Self::Timeout => "timeout",
            Self::TargetUnreachable => "target_unreachable",
            Self::PageNotFound => "page_not_found",
            Self::TargetHttpError => "target_http_error",
        }
    }
}

/// Why ingestion refused before or after a fetch, without a fetch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// Not an `http` or `https` URL; refused before any socket.
    UnsupportedScheme,
    /// The response is not HTML.
    UnsupportedContentType,
    /// The page extracted to no text (a script-rendered shell, for example).
    /// Returned as an error, never as an empty success.
    EmptyContent,
    /// The body exceeds the HTML size or node limits.
    ContentTooLarge,
}

impl RefusalReason {
    /// The wire code.
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::UnsupportedContentType => "unsupported_content_type",
            Self::EmptyContent => "empty_content",
            Self::ContentTooLarge => "content_too_large",
        }
    }
}

/// A transport-level failure the fetch adapter observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    Timeout,
    Dns,
    Connect,
    Tls,
    Reset,
    /// The governed fetch refused the destination (policy or address check).
    Refused,
}

/// A typed ingestion error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    Fetch {
        kind: FetchErrorKind,
        url: String,
        http_status: Option<u16>,
        message: String,
    },
    Refused {
        reason: RefusalReason,
        url: String,
        message: String,
    },
}

impl IngestError {
    /// The wire code (`bot_blocked`, `unsupported_scheme`, ...).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Fetch { kind, .. } => kind.code(),
            Self::Refused { reason, .. } => reason.code(),
        }
    }

    /// The URL the error is about.
    pub fn url(&self) -> &str {
        match self {
            Self::Fetch { url, .. } | Self::Refused { url, .. } => url,
        }
    }

    /// The upstream HTTP status, when the error carries one.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Fetch { http_status, .. } => *http_status,
            Self::Refused { .. } => None,
        }
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        match self {
            Self::Fetch { message, .. } | Self::Refused { message, .. } => message,
        }
    }
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.code(), self.url(), self.message())
    }
}

impl std::error::Error for IngestError {}

/// Refuses anything but `http(s)` before a fetch is attempted.
pub fn check_target(target: &str) -> Result<(), IngestError> {
    if url::is_http(target) {
        Ok(())
    } else {
        Err(IngestError::Refused {
            reason: RefusalReason::UnsupportedScheme,
            url: target.to_string(),
            message: format!("refusing to ingest non-http(s) target: {target}"),
        })
    }
}

/// Maps a transport failure to the fetch error taxonomy.
pub fn transport_error(target: &str, failure: TransportFailure, detail: &str) -> IngestError {
    let kind = match failure {
        TransportFailure::Timeout => FetchErrorKind::Timeout,
        TransportFailure::Dns
        | TransportFailure::Connect
        | TransportFailure::Tls
        | TransportFailure::Reset
        | TransportFailure::Refused => FetchErrorKind::TargetUnreachable,
    };
    IngestError::Fetch {
        kind,
        url: target.to_string(),
        http_status: None,
        message: format!("{} fetching {target}: {detail}", kind.code()),
    }
}

/// What the governed fetch returned for one URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchedResponse {
    pub url: String,
    pub final_url: Option<String>,
    pub status: u16,
    /// Response headers; names are matched case-insensitively.
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub fetched_at_ms: u64,
}

impl FetchedResponse {
    /// First header value by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

const CHALLENGE_MARKERS: [&str; 8] = [
    "cf-chl",
    "challenge-platform",
    "cf-turnstile",
    "captcha",
    "attention required!",
    "just a moment...",
    "px-captcha",
    "verify you are human",
];

fn looks_like_challenge(response: &FetchedResponse) -> bool {
    if response
        .header("cf-mitigated")
        .is_some_and(|v| v.eq_ignore_ascii_case("challenge"))
    {
        return true;
    }
    let lower = response.body.to_lowercase();
    CHALLENGE_MARKERS.iter().any(|m| lower.contains(m))
}

/// Classifies a non-`304` response; `None` means the response is usable.
pub fn classify_response(response: &FetchedResponse) -> Option<FetchErrorKind> {
    match response.status {
        200..=299 => {
            // A small 200 page that is only a challenge is a block, not content.
            (response.body.len() < 32 * 1024 && looks_like_challenge(response))
                .then_some(FetchErrorKind::BotBlocked)
        }
        404 | 410 => Some(FetchErrorKind::PageNotFound),
        401 | 403 | 429 | 503 if looks_like_challenge(response) => Some(FetchErrorKind::BotBlocked),
        _ => Some(FetchErrorKind::TargetHttpError),
    }
}

/// The result of ingesting one response.
#[derive(Debug, Clone, PartialEq)]
pub enum IngestOutcome {
    /// New or changed bytes, extracted into a document.
    Fresh(CorpusDoc),
    /// `304 Not Modified`: the prior document, with `revalidated_at_ms` set
    /// and any refreshed validators recorded.
    NotModified(CorpusDoc),
}

fn too_large(page_url: &str, limit: HtmlLimit) -> IngestError {
    IngestError::Refused {
        reason: RefusalReason::ContentTooLarge,
        url: page_url.to_string(),
        message: format!("{page_url}: {limit}"),
    }
}

/// Builds a corpus document from HTML (the proof of concept's `makeDoc`).
/// The document id is the first 12 hex characters of the URL's SHA-256.
/// Refuses with `content_too_large` past the HTML size or node limits.
pub fn document_from_html(
    page_url: &str,
    html: &str,
    record: IngestRecord,
) -> Result<CorpusDoc, IngestError> {
    let page = extract_page(html, page_url).map_err(|limit| too_large(page_url, limit))?;
    let category = infer_category(page_url, page.open_graph_type.as_deref());
    Ok(CorpusDoc {
        id: content_hash(page_url)[..12].to_string(),
        url: page_url.to_string(),
        title: page.title,
        content_hash: content_hash(&page.text),
        text: page.text,
        markdown: page.markdown,
        blocks: page.blocks,
        published_date: page.published_date,
        author: page.author,
        site_name: page.site_name,
        language: page.language,
        category,
        ingest: record,
    })
}

/// Ingests a local HTML file's contents under a synthetic URL (the proof of
/// concept's `ingestFile`). Reading the file is the caller's job.
pub fn ingest_html(
    page_url: &str,
    html: &str,
    origin: &str,
    fetched_at_ms: u64,
) -> Result<CorpusDoc, IngestError> {
    document_from_html(
        page_url,
        html,
        IngestRecord {
            origin: origin.to_string(),
            fetched_at_ms,
            ..IngestRecord::default()
        },
    )
}

/// Turns one governed-fetch response into a document, a revalidation or a
/// typed error. `prior` is the stored document for the URL, if any; a `304`
/// without one is a `target_http_error` (nothing to revalidate).
pub fn ingest_response(
    response: &FetchedResponse,
    prior: Option<&CorpusDoc>,
) -> Result<IngestOutcome, IngestError> {
    check_target(&response.url)?;
    // Validators are replayed as request headers later, so only safe values
    // are kept (no CR/LF or other control characters).
    let etag = response.header("etag").and_then(sanitize_validator);
    let last_modified = response
        .header("last-modified")
        .and_then(sanitize_validator);

    if response.status == 304 {
        if let Some(prior) = prior {
            let mut doc = prior.clone();
            doc.ingest.revalidated_at_ms = Some(response.fetched_at_ms);
            doc.ingest.http_status = Some(304);
            if etag.is_some() {
                doc.ingest.etag = etag;
            }
            if last_modified.is_some() {
                doc.ingest.last_modified = last_modified;
            }
            return Ok(IngestOutcome::NotModified(doc));
        }
        return Err(IngestError::Fetch {
            kind: FetchErrorKind::TargetHttpError,
            url: response.url.clone(),
            http_status: Some(304),
            message: "304 Not Modified without a stored document to revalidate".to_string(),
        });
    }

    if response.body.len() > MAX_HTML_BYTES {
        return Err(too_large(
            &response.url,
            HtmlLimit::InputTooLarge {
                bytes: response.body.len(),
            },
        ));
    }

    if let Some(kind) = classify_response(response) {
        return Err(IngestError::Fetch {
            kind,
            url: response.url.clone(),
            http_status: Some(response.status),
            message: format!(
                "GET {} -> {} ({})",
                response.url,
                response.status,
                kind.code()
            ),
        });
    }

    let content_type = response.header("content-type").unwrap_or("").to_string();
    let lower = content_type.to_ascii_lowercase();
    if !(lower.contains("text/html") || lower.contains("application/xhtml")) {
        let shown = if content_type.is_empty() {
            "unknown"
        } else {
            content_type.as_str()
        };
        return Err(IngestError::Refused {
            reason: RefusalReason::UnsupportedContentType,
            url: response.url.clone(),
            message: format!("unsupported content-type '{shown}' for {}", response.url),
        });
    }

    let record = IngestRecord {
        origin: "governed-fetch".to_string(),
        final_url: response.final_url.clone(),
        http_status: Some(response.status),
        content_type: Some(content_type),
        etag,
        last_modified,
        fetched_at_ms: response.fetched_at_ms,
        revalidated_at_ms: None,
    };
    let doc = document_from_html(&response.url, &response.body, record)?;
    if doc.text.trim().is_empty() {
        return Err(IngestError::Refused {
            reason: RefusalReason::EmptyContent,
            url: response.url.clone(),
            message: format!(
                "{} extracted to no text; script-rendered pages need the browser engine",
                response.url
            ),
        });
    }
    Ok(IngestOutcome::Fresh(doc))
}
