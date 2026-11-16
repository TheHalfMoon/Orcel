//! The Exa-compatible route table, as data. No listener.
//!
//! Ported from the routing and error policy of
//! `orcel-poc/src/server/exa-compat.ts` (Orcel-authored). The proof of
//! concept ran its own HTTP server; in Orcel that is not allowed (`orceld` is
//! the sole authority), so this module only decides what a route is. A later
//! packet mounts these decisions on an `orceld` loopback route, the way the
//! Firecrawl REST routes are mounted (WP1-07), with `orceld`'s own auth.

use serde::{Deserialize, Serialize};

use crate::engine::{EngineInputError, LocalSearchEngine, MAX_BATCH_URLS, MAX_PAGE};

/// Routes the local engine serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Search,
    Contents,
    Answer,
    FindSimilar,
    Health,
    Capabilities,
}

/// `{ "error": { "code", "message" } }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

/// The error code and message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl ErrorBody {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.into(),
            },
        }
    }
}

/// What to do with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Serve(Route),
    /// A typed refusal with its HTTP status (404, 405 or 501).
    Reject {
        status: u16,
        body: ErrorBody,
    },
}

/// Hosted-only Exa surfaces that answer `501 not_implemented`.
pub const NOT_IMPLEMENTED: [&str; 7] = [
    "/agent/runs",
    "/batches",
    "/monitors",
    "/v0/websets",
    "/v0/imports",
    "/v0/webhooks",
    "/v0/events",
];

/// Routes the engine implements.
pub const IMPLEMENTED: [&str; 4] = ["/search", "/contents", "/answer", "/findSimilar"];

/// Decides a request by method and path (trailing slashes ignored).
pub fn route(method: &str, path: &str) -> RouteDecision {
    let trimmed = path.trim_end_matches('/');
    let path = if trimmed.is_empty() { "/" } else { trimmed };
    let method = method.to_ascii_uppercase();
    if method == "GET" && path == "/health" {
        return RouteDecision::Serve(Route::Health);
    }
    if method == "GET" && path == "/v1/capabilities" {
        return RouteDecision::Serve(Route::Capabilities);
    }
    if method != "POST" {
        return RouteDecision::Reject {
            status: 405,
            body: ErrorBody::new(
                "method_not_allowed",
                format!("{method} is not supported on {path}."),
            ),
        };
    }
    let hosted_only = matches!(path, "/agent" | "/monitors/batch")
        || NOT_IMPLEMENTED.contains(&path)
        || path.starts_with("/v0/")
        || path.starts_with("/agent/")
        || path.starts_with("/monitors/");
    if hosted_only {
        return RouteDecision::Reject {
            status: 501,
            body: ErrorBody::new(
                "not_implemented",
                "This Exa surface depends on Exa-hosted infrastructure (scheduler, worker fleet, hosted agent, webset enrichment). The Orcel local engine implements search, contents, answer and findSimilar only. See GET /v1/capabilities.",
            ),
        };
    }
    match path {
        "/search" => RouteDecision::Serve(Route::Search),
        "/contents" => RouteDecision::Serve(Route::Contents),
        "/answer" => RouteDecision::Serve(Route::Answer),
        "/findSimilar" => RouteDecision::Serve(Route::FindSimilar),
        _ => RouteDecision::Reject {
            status: 404,
            body: ErrorBody::new(
                "not_found",
                format!(
                    "No route for POST {path}. Implemented: /search, /contents, /answer, /findSimilar."
                ),
            ),
        },
    }
}

/// `400 bad_request` for a caller error.
pub fn bad_request(error: &EngineInputError) -> (u16, ErrorBody) {
    (
        error.status(),
        ErrorBody::new("bad_request", error.message.clone()),
    )
}

/// `GET /v1/capabilities`: the machine-readable limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    pub engine: String,
    pub retrieval: String,
    pub semantic: bool,
    pub documents: usize,
    pub implemented: Vec<String>,
    pub not_implemented: Vec<String>,
    pub formats: Vec<String>,
    pub max_batch_urls: usize,
    pub max_page: u32,
    pub cost_per_call_usd: f64,
}

/// The capabilities report for `engine`.
pub fn capabilities(engine: &LocalSearchEngine) -> Capabilities {
    Capabilities {
        engine: "orcel-local".to_string(),
        retrieval: "bm25".to_string(),
        semantic: false,
        documents: engine.len(),
        implemented: IMPLEMENTED.iter().map(|s| s.to_string()).collect(),
        not_implemented: NOT_IMPLEMENTED.iter().map(|s| s.to_string()).collect(),
        formats: ["text", "markdown", "html", "json"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        max_batch_urls: MAX_BATCH_URLS,
        max_page: MAX_PAGE,
        cost_per_call_usd: 0.0,
    }
}

/// `GET /health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub status: String,
    pub documents: usize,
    pub paid_calls: u64,
}

/// The health report for `engine`.
pub fn health(engine: &LocalSearchEngine) -> Health {
    Health {
        status: "ok".to_string(),
        documents: engine.len(),
        paid_calls: 0,
    }
}
