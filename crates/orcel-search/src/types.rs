//! Exa-shaped request and response envelopes, the corpus document and the
//! content-block tree.
//!
//! Ported from `orcel-poc/src/types.ts` (Orcel-authored). Wire field names
//! follow the public Exa API contract as the MIT `exa-js` client reads it
//! (`exa-labs/exa-js@ec25f401`, `src/index.ts`: `requestId`, `results`,
//! `costDollars`, `statuses[] { id, status, error { tag, httpStatusCode } }`),
//! so an unmodified client can read them. No code from `exa-labs/openapi-spec`
//! (no licence) is used; only interface facts.
//!
//! Additive fields beyond Exa (`pagination`, `markdown`, `html`, `json`,
//! `etag`, `lastModified`, per-URL error tags) are optional and skipped when
//! absent, so Exa clients ignore them.

use serde::{Deserialize, Serialize};

use crate::ingest::IngestRecord;

/// Exa's result categories, inferred locally from host and `og:type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DocCategory {
    #[serde(rename = "general")]
    General,
    #[serde(rename = "news")]
    News,
    #[serde(rename = "research paper")]
    ResearchPaper,
    #[serde(rename = "company")]
    Company,
    #[serde(rename = "github")]
    Github,
    #[serde(rename = "pdf")]
    Pdf,
    #[serde(rename = "personal site")]
    PersonalSite,
    #[serde(rename = "linkedin profile")]
    LinkedinProfile,
}

/// One structural block of the extracted main content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Heading { level: u8, text: String },
    Paragraph { text: String },
    ListItem { ordered: bool, text: String },
    Quote { text: String },
    Code { text: String },
}

/// A document in the local corpus.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusDoc {
    pub id: String,
    pub url: String,
    pub title: String,
    pub text: String,
    pub markdown: String,
    #[serde(default)]
    pub blocks: Vec<ContentBlock>,
    pub published_date: Option<String>,
    pub author: Option<String>,
    pub site_name: Option<String>,
    pub language: Option<String>,
    pub category: DocCategory,
    /// Lowercase hex SHA-256 of `text`: the citation fingerprint.
    pub content_hash: String,
    /// Where and how the bytes arrived (validators, status, timing).
    pub ingest: IngestRecord,
}

/// `contents.text`: a flag or options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TextOption {
    Flag(bool),
    Options(TextOptions),
}

/// Options for `contents.text`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TextOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_characters: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_html_tags: Option<bool>,
}

/// `contents.highlights`: a flag or options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HighlightsOption {
    Flag(bool),
    Options(HighlightsOptions),
}

/// Options for `contents.highlights`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HighlightsOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_sentences: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_characters: Option<usize>,
}

/// `contents.summary`: a flag or options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SummaryOption {
    Flag(bool),
    Options(SummaryOptions),
}

/// Options for `contents.summary`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

/// Exa's `livecrawl`. Locally only `never` has an effect; the rest are
/// reported as ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Livecrawl {
    Never,
    Fallback,
    Preferred,
    Always,
}

/// Output format for page content (`text` is Exa's default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentFormat {
    Text,
    Markdown,
    Html,
    Json,
}

/// What content to return with each result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentsOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<TextOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlights: Option<HighlightsOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<SummaryOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpages: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub livecrawl: Option<Livecrawl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ContentFormat>,
    /// Adds `etag` and `lastModified` from the ingest record to each result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_etag_and_last_modified: Option<bool>,
}

/// Exa search types. Unknown values are accepted and treated as `auto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchType {
    Auto,
    Neural,
    Keyword,
    Fast,
    Lite,
    Instant,
    #[serde(other)]
    Other,
}

/// `POST /search` body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    #[serde(default)]
    pub query: String,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub search_type: Option<SearchType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<DocCategory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_results: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_domains: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_published_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_published_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_text: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_text: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents: Option<ContentsOptions>,
    /// Zero-based page of `numResults` results (0 to [`crate::engine::MAX_PAGE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    /// Zero-based result offset; mutually exclusive with `page`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

/// `POST /contents` body. Content options may sit at the top level (Exa's
/// `/contents` shape) or under `contents` (the `/search` shape).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentsRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contents: Option<ContentsOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<TextOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlights: Option<HighlightsOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<SummaryOption>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub livecrawl: Option<Livecrawl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<ContentFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_etag_and_last_modified: Option<bool>,
}

impl ContentsRequest {
    /// The effective content options: `contents` when present, otherwise the
    /// top-level fields.
    pub fn options(&self) -> ContentsOptions {
        if let Some(nested) = &self.contents {
            return nested.clone();
        }
        ContentsOptions {
            text: self.text.clone(),
            highlights: self.highlights.clone(),
            summary: self.summary.clone(),
            subpages: None,
            livecrawl: self.livecrawl,
            format: self.format,
            include_etag_and_last_modified: self.include_etag_and_last_modified,
        }
    }

    /// `urls` when non-empty, otherwise `ids`.
    pub fn targets(&self) -> Vec<String> {
        match (&self.urls, &self.ids) {
            (Some(urls), _) if !urls.is_empty() => urls.clone(),
            (_, Some(ids)) => ids.clone(),
            _ => Vec::new(),
        }
    }
}

/// `POST /answer` body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnswerRequest {
    #[serde(default)]
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_results: Option<i64>,
}

/// `POST /findSimilar` body.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindSimilarRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_results: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_source_domain: Option<bool>,
}

/// The `json` format: the page as a typed block tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentTree {
    pub url: String,
    pub title: String,
    pub published_date: Option<String>,
    pub author: Option<String>,
    pub language: Option<String>,
    pub blocks: Vec<ContentBlock>,
}

/// One search or contents result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultItem {
    pub id: String,
    pub url: String,
    pub title: String,
    pub published_date: Option<String>,
    pub author: Option<String>,
    pub score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlights: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight_scores: Option<Vec<f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<DocumentTree>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// A note shown to the caller (and the model) about how a result was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    #[serde(rename = "type")]
    pub kind: String,
    pub message: String,
}

impl Notice {
    /// Builds a notice.
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

/// Per-call cost split.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CostBreakdown {
    pub search: f64,
    pub contents: f64,
}

/// Exa's `costDollars`. Always zero locally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostDollars {
    pub total: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub break_down: Option<Vec<CostBreakdown>>,
}

impl CostDollars {
    /// `{ total: 0 }`.
    pub fn zero() -> Self {
        Self {
            total: 0.0,
            break_down: None,
        }
    }
}

/// Where a page of results sits in the full ranked list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pagination {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    pub offset: usize,
    pub num_results: usize,
    pub total_results: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// `POST /search` and `POST /findSimilar` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    pub request_id: String,
    pub resolved_search_type: String,
    pub results: Vec<ResultItem>,
    pub cost_dollars: CostDollars,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notices: Option<Vec<Notice>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pagination: Option<Pagination>,
}

/// Exa's per-URL `statuses[].error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentStatusError {
    /// A typed code: one of the ingest error codes or `not_in_corpus`.
    pub tag: String,
    pub http_status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Exa's per-URL `statuses[]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentStatus {
    pub id: String,
    /// `success` or `error`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ContentStatusError>,
}

/// `POST /contents` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentsResponse {
    pub request_id: String,
    pub results: Vec<ResultItem>,
    pub statuses: Vec<ContentStatus>,
    pub cost_dollars: CostDollars,
    pub notices: Vec<Notice>,
}

/// One answer citation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnswerCitation {
    pub id: String,
    pub url: String,
    pub title: String,
    pub published_date: Option<String>,
    pub author: Option<String>,
    pub text: String,
}

/// Whether the corpus supported an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerStatus {
    Supported,
    NoSupport,
}

/// `POST /answer` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnswerResponse {
    pub request_id: String,
    pub answer: Option<String>,
    pub citations: Vec<AnswerCitation>,
    pub status: AnswerStatus,
    pub cost_dollars: CostDollars,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notices: Option<Vec<Notice>>,
}
