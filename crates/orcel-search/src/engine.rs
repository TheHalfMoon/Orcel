//! The local retrieval engine: search, contents, answer and findSimilar.
//!
//! Ported from `orcel-poc/src/engine/engine.ts` (Orcel-authored), plus the
//! P-1 items: pagination, batch contents with per-URL typed errors, the
//! `markdown`/`html`/`json` formats and the ETag/Last-Modified fields.
//! Everything is mechanical: BM25 ranking, sentence extraction, span
//! selection. No embedding model, no LLM, no network. The lexical limit is
//! reported in `notices` rather than hidden.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::bm25::{cosine_similarity, Bm25Index, Hit};
use crate::extract::content_hash;
use crate::formats::{render_html, render_json};
use crate::highlights::{extract_highlights, lead_sentences, round_to, HighlightOptions};
use crate::ingest::IngestError;
use crate::tokenize::{index_terms, MAX_QUERY_BYTES, MAX_QUERY_TERMS};
use crate::types::{
    AnswerCitation, AnswerRequest, AnswerResponse, AnswerStatus, ContentFormat, ContentStatus,
    ContentStatusError, ContentsOptions, ContentsRequest, ContentsResponse, CorpusDoc,
    CostBreakdown, CostDollars, FindSimilarRequest, HighlightsOption, Notice, Pagination,
    ResultItem, SearchRequest, SearchResponse, SearchType, SummaryOption, TextOption,
};
use crate::url::{self, domain_matches, normalise_domain};

/// Exa client default for `text.maxCharacters`.
pub const DEFAULT_TEXT_MAX_CHARACTERS: usize = 10_000;
/// Upper bound for `numResults`.
pub const MAX_RESULTS: usize = 100;
/// Highest zero-based `page` accepted (TinyFish pages 0 to 10).
pub const MAX_PAGE: u32 = 10;
/// Highest `offset` accepted.
pub const MAX_OFFSET: u32 = 1_000;
/// Most targets one `/contents` batch accepts (TinyFish fetch: 1 to 10).
pub const MAX_BATCH_URLS: usize = 10;
const LOW_SUPPORT_THRESHOLD: f64 = 0.45;

/// A caller error: the HTTP surface maps it to `400 bad_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineInputError {
    pub message: String,
}

impl EngineInputError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Always 400.
    pub fn status(&self) -> u16 {
        400
    }
}

impl fmt::Display for EngineInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EngineInputError {}

/// Engine limits.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Documents kept in memory; the oldest insertion is evicted first.
    pub max_documents: usize,
    /// Domain suffixes always excluded.
    pub blocked_domains: Vec<String>,
    /// Seed for request ids (ids are derived, not random, so runs replay).
    pub request_id_seed: String,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            max_documents: 5000,
            blocked_domains: Vec::new(),
            request_id_seed: "orcel-search".to_string(),
        }
    }
}

/// The in-memory corpus and its index.
#[derive(Debug)]
pub struct LocalSearchEngine {
    docs: HashMap<String, CorpusDoc>,
    order: Vec<String>,
    by_url: HashMap<String, String>,
    index: Bm25Index,
    options: EngineOptions,
    requests: AtomicU64,
}

impl Default for LocalSearchEngine {
    fn default() -> Self {
        Self::new(EngineOptions::default())
    }
}

fn clamp_count(value: Option<i64>, default: usize) -> usize {
    let value = value.unwrap_or(default as i64);
    value.clamp(1, MAX_RESULTS as i64) as usize
}

fn check_batch(count: usize) -> Result<(), EngineInputError> {
    if count == 0 {
        return Err(EngineInputError::new(
            "contents requires a non-empty urls or ids array",
        ));
    }
    if count > MAX_BATCH_URLS {
        return Err(EngineInputError::new(format!(
            "contents accepts at most {MAX_BATCH_URLS} urls or ids per request (got {count})"
        )));
    }
    Ok(())
}

/// Trims the query and refuses an empty one, one over [`MAX_QUERY_BYTES`]
/// or one with more than [`MAX_QUERY_TERMS`] index terms.
fn validate_query(raw: &str) -> Result<&str, EngineInputError> {
    let query = raw.trim();
    if query.is_empty() {
        return Err(EngineInputError::new("query must be a non-empty string"));
    }
    if query.len() > MAX_QUERY_BYTES {
        return Err(EngineInputError::new(format!(
            "query must be at most {MAX_QUERY_BYTES} bytes"
        )));
    }
    if index_terms(query).len() > MAX_QUERY_TERMS {
        return Err(EngineInputError::new(format!(
            "query must have at most {MAX_QUERY_TERMS} terms"
        )));
    }
    Ok(query)
}

fn truncate_at_word(text: &str, max_characters: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_characters {
        return text.to_string();
    }
    let slice = &chars[..max_characters];
    match slice.iter().rposition(|c| *c == ' ') {
        Some(last_space) if last_space as f64 > max_characters as f64 * 0.8 => {
            slice[..last_space].iter().collect()
        }
        _ => slice.iter().collect(),
    }
}

fn host_of(target: &str) -> String {
    url::parse(target).map(|p| p.host).unwrap_or_default()
}

impl LocalSearchEngine {
    /// An empty engine.
    pub fn new(options: EngineOptions) -> Self {
        Self {
            docs: HashMap::new(),
            order: Vec::new(),
            by_url: HashMap::new(),
            index: Bm25Index::default(),
            options,
            requests: AtomicU64::new(0),
        }
    }

    /// Documents in the corpus.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// True when the corpus is empty.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// A UUID-shaped id derived from the seed and a per-engine counter.
    pub fn next_request_id(&self) -> String {
        let n = self.requests.fetch_add(1, Ordering::Relaxed);
        let hex = content_hash(&format!("{}:{n}", self.options.request_id_seed));
        format!(
            "{}-{}-8{}-{}-{}",
            &hex[0..8],
            &hex[8..12],
            &hex[13..16],
            &hex[16..20],
            &hex[20..32]
        )
    }

    /// Adds or replaces a document. A document with the same URL but a new
    /// id replaces the old one; the index stays consistent on eviction.
    pub fn add(&mut self, doc: CorpusDoc) {
        if let Some(existing) = self.by_url.get(&doc.url).cloned() {
            if existing != doc.id {
                self.evict(&existing);
            }
        }
        if !self.docs.contains_key(&doc.id) {
            self.order.push(doc.id.clone());
        }
        let index_text = if doc.markdown.is_empty() {
            doc.text.clone()
        } else {
            doc.markdown.clone()
        };
        self.index.add(&doc.id, &doc.title, &index_text);
        self.by_url.insert(doc.url.clone(), doc.id.clone());
        self.docs.insert(doc.id.clone(), doc);
        while self.docs.len() > self.options.max_documents {
            let Some(oldest) = self.order.first().cloned() else {
                break;
            };
            self.evict(&oldest);
        }
    }

    /// Adds every document; returns the corpus size.
    pub fn add_many(&mut self, docs: impl IntoIterator<Item = CorpusDoc>) -> usize {
        for doc in docs {
            self.add(doc);
        }
        self.docs.len()
    }

    /// Document by id.
    pub fn get(&self, id: &str) -> Option<&CorpusDoc> {
        self.docs.get(id)
    }

    /// Document by URL.
    pub fn get_by_url(&self, target: &str) -> Option<&CorpusDoc> {
        self.by_url.get(target).and_then(|id| self.docs.get(id))
    }

    /// Documents in insertion order.
    pub fn all(&self) -> Vec<&CorpusDoc> {
        self.order
            .iter()
            .filter_map(|id| self.docs.get(id))
            .collect()
    }

    /// The BM25 index (read-only).
    pub fn index(&self) -> &Bm25Index {
        &self.index
    }

    fn evict(&mut self, id: &str) {
        let Some(doc) = self.docs.remove(id) else {
            return;
        };
        self.order.retain(|other| other != id);
        if self.by_url.get(&doc.url).map(String::as_str) == Some(id) {
            self.by_url.remove(&doc.url);
        }
        self.index.remove(id);
    }

    /// Ranked search with Exa filters and optional pagination.
    pub fn search(&self, request: &SearchRequest) -> Result<SearchResponse, EngineInputError> {
        let query = validate_query(&request.query)?;
        let mut notices = Vec::new();
        if matches!(
            request.search_type,
            Some(SearchType::Neural) | Some(SearchType::Auto)
        ) {
            notices.push(Notice::new(
                "capability",
                "Orcel local engine ranks lexically (BM25 + phrase + proximity). It does not run a neural retriever; use category/domain filters for precision.",
            ));
        }
        if let Some(contents) = &request.contents {
            if contents.subpages.is_some() {
                notices.push(Notice::new(
                    "ignored_parameter",
                    "contents.subpages is not supported locally: no subpage crawler is attached to the engine.",
                ));
            }
            if let Some(livecrawl) = contents.livecrawl {
                if livecrawl != crate::types::Livecrawl::Never {
                    let name = serde_json::to_value(livecrawl)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_default();
                    notices.push(Notice::new(
                        "ignored_parameter",
                        format!("contents.livecrawl='{name}' is a no-op: the local engine only reads documents already ingested."),
                    ));
                }
            }
        }

        if request.page.is_some() && request.offset.is_some() {
            return Err(EngineInputError::new(
                "page and offset are mutually exclusive",
            ));
        }
        if let Some(page) = request.page {
            if page > MAX_PAGE {
                return Err(EngineInputError::new(format!(
                    "page must be between 0 and {MAX_PAGE}"
                )));
            }
        }
        if let Some(offset) = request.offset {
            if offset > MAX_OFFSET {
                return Err(EngineInputError::new(format!(
                    "offset must be between 0 and {MAX_OFFSET}"
                )));
            }
        }

        let num_results = clamp_count(request.num_results, 10);
        let offset = match (request.page, request.offset) {
            (Some(page), _) => page as usize * num_results,
            (_, Some(offset)) => offset as usize,
            _ => 0,
        };
        let ranked = self.collect_ranked(query, request);
        let total = ranked.len();
        let contents = request.contents.clone().unwrap_or_default();
        let results: Vec<ResultItem> = ranked
            .iter()
            .skip(offset)
            .take(num_results)
            .filter_map(|hit| {
                self.docs
                    .get(&hit.id)
                    .map(|doc| self.to_result_item(doc, hit.score, query, &contents))
            })
            .collect();
        let pagination = (request.page.is_some() || request.offset.is_some()).then(|| {
            let end = offset + results.len();
            Pagination {
                page: request.page,
                offset,
                num_results,
                total_results: total,
                next_offset: (end < total).then_some(end),
            }
        });

        Ok(SearchResponse {
            request_id: self.next_request_id(),
            resolved_search_type: if matches!(
                request.search_type,
                Some(SearchType::Keyword) | Some(SearchType::Fast)
            ) {
                "keyword".to_string()
            } else {
                "auto".to_string()
            },
            results,
            cost_dollars: CostDollars {
                total: 0.0,
                break_down: Some(vec![CostBreakdown {
                    search: 0.0,
                    contents: 0.0,
                }]),
            },
            notices: (!notices.is_empty()).then_some(notices),
            pagination,
        })
    }

    /// Stored pages by URL or id (the proof of concept's `contents`), with
    /// the same 1 to [`MAX_BATCH_URLS`] limit as [`Self::contents_batch`];
    /// unknown targets are reported as `not_in_corpus`.
    pub fn contents(
        &self,
        targets: &[String],
        options: &ContentsOptions,
    ) -> Result<ContentsResponse, EngineInputError> {
        check_batch(targets.len())?;
        Ok(self.contents_inner(targets, options, &BTreeMap::new()))
    }

    /// `POST /contents`: 1 to [`MAX_BATCH_URLS`] targets, one `statuses[]`
    /// entry per target. A target that is not stored takes its typed error
    /// from `fetch_failures` (filled by the future governed-fetch adapter),
    /// else `unsupported_scheme` for a non-http URL, else `not_in_corpus`.
    /// One failing target never fails the request.
    pub fn contents_batch(
        &self,
        request: &ContentsRequest,
        fetch_failures: &BTreeMap<String, IngestError>,
    ) -> Result<ContentsResponse, EngineInputError> {
        let targets = request.targets();
        check_batch(targets.len())?;
        Ok(self.contents_inner(&targets, &request.options(), fetch_failures))
    }

    fn contents_inner(
        &self,
        targets: &[String],
        options: &ContentsOptions,
        fetch_failures: &BTreeMap<String, IngestError>,
    ) -> ContentsResponse {
        let mut results = Vec::new();
        let mut statuses = Vec::new();
        let mut missing = Vec::new();
        let query = match &options.highlights {
            Some(HighlightsOption::Options(o)) => o.query.clone().unwrap_or_default(),
            _ => String::new(),
        };
        for target in targets {
            if let Some(doc) = self.get_by_url(target).or_else(|| self.get(target)) {
                results.push(self.to_result_item(doc, 0.0, &query, options));
                statuses.push(ContentStatus {
                    id: target.clone(),
                    status: "success".to_string(),
                    source: Some("cached".to_string()),
                    error: None,
                });
                continue;
            }
            let error = if let Some(failure) = fetch_failures.get(target) {
                ContentStatusError {
                    tag: failure.code().to_string(),
                    http_status_code: failure.http_status(),
                    message: Some(failure.message().to_string()),
                }
            } else if url::parse(target).is_some() && !url::is_http(target) {
                ContentStatusError {
                    tag: "unsupported_scheme".to_string(),
                    http_status_code: None,
                    message: Some(format!("refusing non-http(s) target: {target}")),
                }
            } else {
                missing.push(target.clone());
                ContentStatusError {
                    tag: "not_in_corpus".to_string(),
                    http_status_code: None,
                    message: Some("not in the local corpus".to_string()),
                }
            };
            statuses.push(ContentStatus {
                id: target.clone(),
                status: "error".to_string(),
                source: None,
                error: Some(error),
            });
        }
        let mut notices = Vec::new();
        if !missing.is_empty() {
            notices.push(Notice::new(
                "not_found",
                format!(
                    "Not in the local corpus: {}. The local engine does not fetch arbitrary URLs on demand; ingest them with the fetcher first.",
                    missing.join(", ")
                ),
            ));
        }
        ContentsResponse {
            request_id: self.next_request_id(),
            results,
            statuses,
            cost_dollars: CostDollars::zero(),
            notices,
        }
    }

    /// Extractive answer with `[n]` citation markers; abstains with
    /// `no_support` when the evidence is weak. Nothing is generated.
    pub fn answer(&self, request: &AnswerRequest) -> Result<AnswerResponse, EngineInputError> {
        let query = validate_query(&request.query)?;
        let ranked = self.index.search(query);
        let threshold = self.support_threshold(query);
        let consider = clamp_count(request.num_results, 5).max(3);

        let mut passages: Vec<(&CorpusDoc, String, f64)> = Vec::new();
        for hit in ranked.iter().take(consider) {
            let Some(doc) = self.docs.get(&hit.id) else {
                continue;
            };
            let options = HighlightOptions {
                query: query.to_string(),
                num_sentences: Some(3),
                max_characters: None,
            };
            for highlight in extract_highlights(&doc.text, &options) {
                if highlight.score <= 0.0 {
                    continue;
                }
                passages.push((doc, highlight.text, hit.score * highlight.score));
            }
        }
        let total_support: f64 = passages.iter().map(|p| p.2).sum();
        if ranked.is_empty() || total_support < threshold {
            return Ok(AnswerResponse {
                request_id: self.next_request_id(),
                answer: None,
                citations: Vec::new(),
                status: AnswerStatus::NoSupport,
                cost_dollars: CostDollars::zero(),
                notices: Some(vec![Notice::new(
                    "abstained",
                    "No document in the local corpus supports an answer to this query. The engine abstains instead of generating unsupported text.",
                )]),
            });
        }

        passages.sort_by(|a, b| b.2.total_cmp(&a.2));
        let limit = passages.len().min(clamp_count(request.num_results, 3));
        let mut used: Vec<&CorpusDoc> = Vec::new();
        let mut lines: Vec<String> = Vec::new();
        for (doc, sentence, _) in passages.iter().take(limit) {
            let index = match used.iter().position(|d| d.id == doc.id) {
                Some(index) => index,
                None => {
                    used.push(doc);
                    used.len() - 1
                }
            };
            if lines.iter().any(|line| line.contains(sentence.as_str())) {
                continue;
            }
            lines.push(format!("{sentence} [{}]", index + 1));
        }
        Ok(AnswerResponse {
            request_id: self.next_request_id(),
            answer: Some(lines.join(" ")),
            citations: used
                .iter()
                .map(|doc| AnswerCitation {
                    id: doc.id.clone(),
                    url: doc.url.clone(),
                    title: doc.title.clone(),
                    published_date: doc.published_date.clone(),
                    author: doc.author.clone(),
                    text: doc.text.chars().take(2000).collect(),
                })
                .collect(),
            status: AnswerStatus::Supported,
            cost_dollars: CostDollars::zero(),
            notices: Some(vec![Notice::new(
                "extractive",
                "Answer is assembled from sentences of the cited pages, verbatim. No language model was invoked and no text was generated.",
            )]),
        })
    }

    /// Cosine similarity over BM25 term vectors (not embeddings).
    pub fn find_similar(
        &self,
        request: &FindSimilarRequest,
    ) -> Result<SearchResponse, EngineInputError> {
        let source = match (&request.id, &request.url) {
            (Some(id), _) => self.get(id),
            (None, Some(target)) => self.get_by_url(target),
            _ => None,
        };
        let Some(source) = source else {
            let looked_up = match (&request.id, &request.url) {
                (Some(id), _) => format!("id '{id}'"),
                (None, target) => format!("url '{}'", target.clone().unwrap_or_default()),
            };
            return Err(EngineInputError::new(format!(
                "findSimilar needs a document already in the corpus (looked up by {looked_up})"
            )));
        };
        let vector = self.index.term_vector(&source.id);
        let source_host = url::parse(&source.url).map(|p| p.host);
        let mut scored: Vec<Hit> = Vec::new();
        for doc in self.all() {
            if doc.id == source.id {
                continue;
            }
            if request.exclude_source_domain == Some(true) {
                let same = match (&source_host, url::parse(&doc.url)) {
                    (Some(host), Some(parts)) => *host == parts.host,
                    _ => doc.url.split('/').next() == source.url.split('/').next(),
                };
                if same {
                    continue;
                }
            }
            let similarity = cosine_similarity(&vector, &self.index.term_vector(&doc.id));
            if similarity > 0.0 {
                scored.push(Hit {
                    id: doc.id.clone(),
                    score: similarity,
                });
            }
        }
        scored.sort_by(|a, b| b.score.total_cmp(&a.score));
        let results = scored
            .iter()
            .take(clamp_count(request.num_results, 10))
            .filter_map(|hit| {
                self.docs.get(&hit.id).map(|doc| ResultItem {
                    id: doc.id.clone(),
                    url: doc.url.clone(),
                    title: doc.title.clone(),
                    published_date: doc.published_date.clone(),
                    author: doc.author.clone(),
                    score: round_to(hit.score, 6),
                    text: None,
                    highlights: None,
                    highlight_scores: None,
                    summary: None,
                    markdown: None,
                    html: None,
                    json: None,
                    etag: None,
                    last_modified: None,
                })
            })
            .collect();
        Ok(SearchResponse {
            request_id: self.next_request_id(),
            resolved_search_type: "keyword".to_string(),
            results,
            cost_dollars: CostDollars::zero(),
            notices: Some(vec![Notice::new(
                "capability",
                "Similarity is cosine over BM25-weighted term vectors, not embedding similarity.",
            )]),
            pagination: None,
        })
    }

    fn collect_ranked(&self, query: &str, request: &SearchRequest) -> Vec<Hit> {
        let blocked: Vec<String> = self
            .options
            .blocked_domains
            .iter()
            .chain(request.exclude_domains.iter().flatten())
            .map(|d| normalise_domain(d))
            .collect();
        let included: Vec<String> = request
            .include_domains
            .iter()
            .flatten()
            .map(|d| normalise_domain(d))
            .filter(|d| !d.is_empty())
            .collect();
        self.index
            .search(query)
            .into_iter()
            .filter(|hit| {
                let Some(doc) = self.docs.get(&hit.id) else {
                    return false;
                };
                let host = host_of(&doc.url);
                if blocked.iter().any(|d| domain_matches(&host, d)) {
                    return false;
                }
                if !included.is_empty() && !included.iter().any(|d| domain_matches(&host, d)) {
                    return false;
                }
                if request.category.is_some_and(|c| c != doc.category) {
                    return false;
                }
                if let Some(start) = &request.start_published_date {
                    if doc
                        .published_date
                        .as_deref()
                        .is_none_or(|d| d < start.as_str())
                    {
                        return false;
                    }
                }
                if let Some(end) = &request.end_published_date {
                    if doc
                        .published_date
                        .as_deref()
                        .is_none_or(|d| d > end.as_str())
                    {
                        return false;
                    }
                }
                let haystack = doc.text.to_lowercase();
                if let Some(needles) = &request.include_text {
                    if !needles.iter().all(|n| haystack.contains(&n.to_lowercase())) {
                        return false;
                    }
                }
                if let Some(needles) = &request.exclude_text {
                    if needles.iter().any(|n| haystack.contains(&n.to_lowercase())) {
                        return false;
                    }
                }
                true
            })
            .map(|hit| Hit {
                score: round_to(hit.score, 6),
                id: hit.id,
            })
            .collect()
    }

    /// Scales with query length so one rare term is not enough.
    fn support_threshold(&self, query: &str) -> f64 {
        let terms = query.split_whitespace().count().max(1);
        LOW_SUPPORT_THRESHOLD * terms.min(3) as f64
    }

    fn to_result_item(
        &self,
        doc: &CorpusDoc,
        score: f64,
        query: &str,
        contents: &ContentsOptions,
    ) -> ResultItem {
        let mut item = ResultItem {
            id: doc.id.clone(),
            url: doc.url.clone(),
            title: doc.title.clone(),
            published_date: doc.published_date.clone(),
            author: doc.author.clone(),
            score,
            text: None,
            highlights: None,
            highlight_scores: None,
            summary: None,
            markdown: None,
            html: None,
            json: None,
            etag: None,
            last_modified: None,
        };
        let wants_highlights = !matches!(
            contents.highlights,
            None | Some(HighlightsOption::Flag(false))
        );
        let wants_summary = !matches!(contents.summary, None | Some(SummaryOption::Flag(false)));

        if wants_highlights {
            let o = match &contents.highlights {
                Some(HighlightsOption::Options(o)) => o.clone(),
                _ => Default::default(),
            };
            let highlights = extract_highlights(
                &doc.text,
                &HighlightOptions {
                    query: o.query.unwrap_or_else(|| query.to_string()),
                    num_sentences: Some(o.num_sentences.unwrap_or(4)),
                    max_characters: o.max_characters,
                },
            );
            item.highlight_scores = Some(highlights.iter().map(|h| h.score).collect());
            item.highlights = Some(highlights.into_iter().map(|h| h.text).collect());
        }
        if wants_summary {
            let summary_query = match &contents.summary {
                Some(SummaryOption::Options(o)) => o.query.clone(),
                _ => None,
            };
            item.summary = Some(match summary_query {
                Some(q) => extract_highlights(
                    &doc.text,
                    &HighlightOptions {
                        query: q,
                        num_sentences: Some(3),
                        max_characters: None,
                    },
                )
                .into_iter()
                .map(|h| h.text)
                .collect::<Vec<_>>()
                .join(" "),
                None => lead_sentences(&doc.text, 3),
            });
        }

        let format = contents.format.unwrap_or(ContentFormat::Text);
        let cap = match &contents.text {
            Some(TextOption::Options(o)) => o.max_characters.unwrap_or(DEFAULT_TEXT_MAX_CHARACTERS),
            _ => DEFAULT_TEXT_MAX_CHARACTERS,
        };
        // Exa's rule: text by default; highlights, a summary or another
        // format stand in for it unless text is requested explicitly.
        let include_text = match &contents.text {
            Some(TextOption::Flag(false)) => false,
            Some(_) => true,
            None => !(wants_highlights || wants_summary || format != ContentFormat::Text),
        };
        if include_text {
            item.text = Some(truncate_at_word(&doc.text, cap));
        }
        match format {
            ContentFormat::Text => {}
            ContentFormat::Markdown => item.markdown = Some(truncate_at_word(&doc.markdown, cap)),
            ContentFormat::Html => item.html = Some(render_html(doc)),
            ContentFormat::Json => item.json = Some(render_json(doc)),
        }
        if contents.include_etag_and_last_modified == Some(true) {
            item.etag = doc.ingest.etag.clone();
            item.last_modified = doc.ingest.last_modified.clone();
        }
        item
    }
}
