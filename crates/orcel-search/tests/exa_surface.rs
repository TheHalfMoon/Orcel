//! Port of `orcel-poc/test/exa-compat.test.ts` (8 tests) at the wire-shape
//! level. The proof of concept drove the unmodified `exa-js@2.28.0` over a
//! loopback HTTP server; this crate has no server (orceld is the only
//! authority), so these tests check the JSON bodies `exa-js` sends and
//! reads. The live `exa-js` test moves to the packet that mounts the route
//! on orceld. The 401 test moves there too: auth belongs to orceld.

mod common;

use common::build_engine;
use orcel_search::surface::{bad_request, capabilities, health, route, Route, RouteDecision};
use orcel_search::{ContentsRequest, SearchRequest};
use serde_json::{json, Value};

/// The body `exa.search(query, { numResults: 3 })` posts.
#[test]
fn an_exa_js_search_body_returns_the_local_engines_ranked_results() {
    let engine = build_engine();
    let body = json!({ "query": "BM25 inverted index retrieval", "numResults": 3 });
    let request: SearchRequest = serde_json::from_value(body).expect("exa-js body parses");
    let response = serde_json::to_value(engine.search(&request).expect("search")).expect("json");
    assert_eq!(
        response["results"][0]["url"],
        "https://searchlab.example.org/notes/bm25-hybrid-retrieval"
    );
    assert!(response["results"][0]["score"].is_number());
    assert!(response["requestId"].is_string());
    assert_eq!(response["costDollars"]["total"], 0.0);
    // Exa keeps publishedDate and author present (null when unknown).
    assert!(response["results"][0].get("publishedDate").is_some());
    assert!(response["results"][0].get("author").is_some());
    assert!(
        response.get("pagination").is_none(),
        "additive field only on request"
    );
}

#[test]
fn an_exa_js_search_with_highlights_receives_highlight_arrays() {
    let engine = build_engine();
    let body = json!({
        "query": "browser agent session persistence",
        "numResults": 2,
        "contents": { "highlights": { "numSentences": 2 } }
    });
    let request: SearchRequest = serde_json::from_value(body).expect("parses");
    let response = serde_json::to_value(engine.search(&request).expect("search")).expect("json");
    let results = response["results"].as_array().expect("results");
    let highlighted: Vec<&Value> = results
        .iter()
        .filter(|r| r["highlights"].is_array())
        .collect();
    assert!(!highlighted.is_empty());
    let first = highlighted[0]["highlights"][0].as_str().expect("string");
    assert!(first.chars().any(char::is_alphanumeric));
    assert!(highlighted[0]["highlightScores"].is_array());
}

/// The body `exa.getContents([url], { text: { maxCharacters: 500 } })` posts.
#[test]
fn an_exa_js_get_contents_body_reads_stored_pages_by_url() {
    let engine = build_engine();
    let body = json!({
        "urls": ["https://github.com/orcel-labs/obscura"],
        "text": { "maxCharacters": 500 }
    });
    let request: ContentsRequest = serde_json::from_value(body).expect("parses");
    let response = engine
        .contents_batch(&request, &Default::default())
        .expect("contents");
    assert_eq!(response.results.len(), 1);
    let text = response.results[0].text.as_deref().expect("text");
    assert!(text.chars().count() <= 500);
    assert!(text.contains("Obscura runs one process per profile"));
    let value = serde_json::to_value(&response).expect("json");
    assert_eq!(value["statuses"][0]["status"], "success");
    assert_eq!(
        value["statuses"][0]["id"],
        "https://github.com/orcel-labs/obscura"
    );
}

#[test]
fn hosted_only_surfaces_answer_501_not_implemented_never_a_fake_success() {
    for path in [
        "/v0/websets",
        "/v0/websets/abc/items",
        "/agent/runs",
        "/agent",
        "/batches",
        "/monitors",
        "/monitors/batch",
        "/monitors/m1/runs",
    ] {
        match route("POST", path) {
            RouteDecision::Reject { status, body } => {
                assert_eq!(status, 501, "{path}");
                assert_eq!(body.error.code, "not_implemented", "{path}");
            }
            other => panic!("{path}: {other:?}"),
        }
    }
}

#[test]
fn bad_input_is_a_400_with_a_message_not_a_500() {
    let engine = build_engine();
    let request: SearchRequest = serde_json::from_value(json!({ "query": "   " })).expect("parses");
    let error = engine.search(&request).expect_err("rejected");
    let (status, body) = bad_request(&error);
    assert_eq!(status, 400);
    assert_eq!(body.error.code, "bad_request");
    assert!(body
        .error
        .message
        .contains("query must be a non-empty string"));
    let empty = engine
        .contents_batch(&ContentsRequest::default(), &Default::default())
        .expect_err("rejected");
    assert!(empty.message.contains("non-empty urls or ids"));
}

#[test]
fn capabilities_report_states_the_real_limits() {
    let engine = build_engine();
    let body = serde_json::to_value(capabilities(&engine)).expect("json");
    assert_eq!(body["retrieval"], "bm25");
    assert_eq!(body["semantic"], false);
    assert_eq!(body["costPerCallUsd"], 0.0);
    assert_eq!(body["documents"], 6);
    assert!(body["notImplemented"]
        .as_array()
        .expect("array")
        .iter()
        .any(|v| v == "/agent/runs"));
    assert_eq!(body["maxBatchUrls"], 10);
    let h = serde_json::to_value(health(&engine)).expect("json");
    assert_eq!(h["status"], "ok");
    assert_eq!(h["paidCalls"], 0);
}

#[test]
fn the_route_table_serves_only_the_four_endpoints_and_typed_refusals() {
    assert_eq!(
        route("POST", "/search"),
        RouteDecision::Serve(Route::Search)
    );
    assert_eq!(
        route("POST", "/contents/"),
        RouteDecision::Serve(Route::Contents)
    );
    assert_eq!(
        route("POST", "/answer"),
        RouteDecision::Serve(Route::Answer)
    );
    assert_eq!(
        route("POST", "/findSimilar"),
        RouteDecision::Serve(Route::FindSimilar)
    );
    assert_eq!(route("GET", "/health"), RouteDecision::Serve(Route::Health));
    assert_eq!(
        route("get", "/v1/capabilities"),
        RouteDecision::Serve(Route::Capabilities)
    );
    match route("GET", "/search") {
        RouteDecision::Reject { status, body } => {
            assert_eq!(status, 405);
            assert_eq!(body.error.code, "method_not_allowed");
        }
        other => panic!("{other:?}"),
    }
    match route("POST", "/nope") {
        RouteDecision::Reject { status, body } => {
            assert_eq!(status, 404);
            assert_eq!(body.error.code, "not_found");
        }
        other => panic!("{other:?}"),
    }
}

/// Unknown request fields and unknown search types do not break parsing,
/// as an Exa client may send fields the local engine does not know.
#[test]
fn exa_bodies_with_unknown_fields_and_types_still_parse() {
    let request: SearchRequest = serde_json::from_value(json!({
        "query": "retrieval",
        "type": "deep",
        "userLocation": "US",
        "moderation": true
    }))
    .expect("parses");
    let engine = build_engine();
    let response = engine.search(&request).expect("search");
    assert_eq!(response.resolved_search_type, "auto");
}
