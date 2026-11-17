//! Evidence with provenance, and the honesty flags of a search backend.
//!
//! Ported from `orcel-poc/src/orcel/search-port.ts` (`LocalEnginePort` and
//! the `ExaJsPort` capability classification). The `exa-js` client itself is
//! not ported: a bring-your-own-key cloud path belongs to `orceld`'s existing
//! search providers and is never a default.

use serde::{Deserialize, Serialize};

use crate::engine::{EngineInputError, LocalSearchEngine};
use crate::extract::content_hash;
use crate::types::{ContentsOptions, ResultItem, SearchRequest, TextOption};
use crate::url;

/// What a backend can honestly claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortCapabilities {
    pub semantic: bool,
    pub offline: bool,
    pub requires_api_key: bool,
    /// `Some(0.0)` locally; `None` when the provider prices the call.
    pub cost_per_call_usd: Option<f64>,
}

/// The in-process local engine: $0, offline, keyless, lexical.
pub fn local_capabilities() -> PortCapabilities {
    PortCapabilities {
        semantic: false,
        offline: true,
        requires_api_key: false,
        cost_per_call_usd: Some(0.0),
    }
}

/// An Exa-compatible endpoint by base URL: loopback means the local
/// Exa-compatible route (free, lexical); anything else is a paid,
/// provider-priced cloud that only an explicit opt-in may reach.
pub fn endpoint_capabilities(base_url: &str) -> PortCapabilities {
    let loopback = url::parse(base_url).is_some_and(|p| {
        let host = p.host.as_str();
        let bare = if host.starts_with('[') {
            host.split(']')
                .next()
                .map(|h| format!("{h}]"))
                .unwrap_or_default()
        } else {
            host.split(':').next().unwrap_or("").to_string()
        };
        matches!(bare.as_str(), "127.0.0.1" | "localhost" | "[::1]")
            && (p.scheme == "http" || p.scheme == "https")
    });
    PortCapabilities {
        semantic: !loopback,
        offline: loopback,
        requires_api_key: true,
        cost_per_call_usd: loopback.then_some(0.0),
    }
}

/// Which engine produced the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceEngine {
    #[serde(rename = "orcel-local")]
    OrcelLocal,
    #[serde(rename = "exa-cloud")]
    ExaCloud,
}

/// The citation fingerprint attached to every unit of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub engine: EvidenceEngine,
    pub doc_id: String,
    pub url: String,
    /// Lowercase hex SHA-256 of the document text.
    pub content_hash: String,
    /// Unix milliseconds, from the caller's clock.
    pub retrieved_at_ms: u64,
    pub origin: String,
    /// True when the text was assembled mechanically from spans, no model.
    pub extractive: bool,
}

/// One unit of evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub url: String,
    pub title: String,
    pub published_date: Option<String>,
    pub author: Option<String>,
    pub text: String,
    pub highlights: Vec<String>,
    pub score: f64,
    pub provenance: Provenance,
}

/// A search with evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchOutcome {
    pub query: String,
    pub results: Vec<Evidence>,
    pub cost_usd: f64,
    pub notices: Vec<String>,
}

fn evidence(engine: &LocalSearchEngine, item: ResultItem, origin: &str, now_ms: u64) -> Evidence {
    let doc = engine.get(&item.id);
    let text = item
        .text
        .clone()
        .or_else(|| doc.map(|d| d.text.clone()))
        .unwrap_or_default();
    let hash = doc.map_or_else(|| content_hash(&text), |d| d.content_hash.clone());
    Evidence {
        provenance: Provenance {
            engine: EvidenceEngine::OrcelLocal,
            doc_id: item.id.clone(),
            url: item.url.clone(),
            content_hash: hash,
            retrieved_at_ms: now_ms,
            origin: origin.to_string(),
            extractive: true,
        },
        url: item.url,
        title: item.title,
        published_date: item.published_date,
        author: item.author,
        text,
        highlights: item.highlights.unwrap_or_default(),
        score: item.score,
    }
}

/// Searches the local engine and wraps each result with provenance.
pub fn search_evidence(
    engine: &LocalSearchEngine,
    request: &SearchRequest,
    origin: &str,
    now_ms: u64,
) -> Result<SearchOutcome, EngineInputError> {
    let response = engine.search(request)?;
    Ok(SearchOutcome {
        query: request.query.clone(),
        cost_usd: response.cost_dollars.total,
        notices: response
            .notices
            .unwrap_or_default()
            .into_iter()
            .map(|n| n.message)
            .collect(),
        results: response
            .results
            .into_iter()
            .map(|item| evidence(engine, item, origin, now_ms))
            .collect(),
    })
}

/// Reads stored pages and wraps each with provenance.
pub fn contents_evidence(
    engine: &LocalSearchEngine,
    targets: &[String],
    origin: &str,
    now_ms: u64,
) -> Result<Vec<Evidence>, EngineInputError> {
    let options = ContentsOptions {
        text: Some(TextOption::Flag(true)),
        ..ContentsOptions::default()
    };
    Ok(engine
        .contents(targets, &options)?
        .results
        .into_iter()
        .map(|item| evidence(engine, item, origin, now_ms))
        .collect())
}
