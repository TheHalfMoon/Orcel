//! New P-1 behaviour: pagination, batch contents with per-URL typed errors,
//! the html/json/markdown formats, the typed ingest error taxonomy and the
//! ETag/Last-Modified ingest record with conditional-request metadata.

mod common;

use std::collections::BTreeMap;

use common::{build_engine, search, FIXED_NOW_MS};
use orcel_search::engine::{MAX_BATCH_URLS, MAX_PAGE};
use orcel_search::formats::render_html;
use orcel_search::ingest::{
    classify_response, ingest_response, transport_error, FetchErrorKind, FetchedResponse,
    IngestError, IngestOutcome, IngestRecord, RefusalReason, TransportFailure,
};
use orcel_search::types::{ContentBlock, ContentFormat, ContentsOptions, TextOption};
use orcel_search::{ContentsRequest, LocalSearchEngine, SearchRequest};
use serde_json::json;

const OBSCURA: &str = "https://github.com/orcel-labs/obscura";

fn ids(engine: &LocalSearchEngine, request: &SearchRequest) -> Vec<String> {
    engine
        .search(request)
        .expect("search")
        .results
        .into_iter()
        .map(|r| r.id)
        .collect()
}

// ---- Pagination ----

#[test]
fn pages_partition_the_ranked_list_without_overlap() {
    let engine = build_engine();
    let all = ids(
        &engine,
        &SearchRequest {
            num_results: Some(100),
            ..search("retrieval")
        },
    );
    assert!(all.len() >= 4, "need several matches, got {}", all.len());
    let mut paged = Vec::new();
    for page in 0..=MAX_PAGE {
        let response = engine
            .search(&SearchRequest {
                num_results: Some(2),
                page: Some(page),
                ..search("retrieval")
            })
            .expect("search");
        let p = response.pagination.expect("pagination when paging");
        assert_eq!(p.page, Some(page));
        assert_eq!(p.offset, page as usize * 2);
        assert_eq!(p.total_results, all.len());
        if response.results.is_empty() {
            assert_eq!(p.next_offset, None);
            break;
        }
        paged.extend(response.results.into_iter().map(|r| r.id));
    }
    assert_eq!(paged, all);
}

#[test]
fn offset_pages_and_reports_the_next_offset() {
    let engine = build_engine();
    let all = ids(
        &engine,
        &SearchRequest {
            num_results: Some(100),
            ..search("retrieval")
        },
    );
    let response = engine
        .search(&SearchRequest {
            num_results: Some(2),
            offset: Some(1),
            ..search("retrieval")
        })
        .expect("search");
    let got: Vec<String> = response.results.iter().map(|r| r.id.clone()).collect();
    assert_eq!(got, all[1..3].to_vec());
    let p = response.pagination.expect("pagination");
    assert_eq!(p.offset, 1);
    assert_eq!(p.next_offset, (3 < all.len()).then_some(3));
    let past = engine
        .search(&SearchRequest {
            offset: Some(500),
            ..search("retrieval")
        })
        .expect("search");
    assert!(past.results.is_empty());
}

#[test]
fn pagination_input_errors_are_typed() {
    let engine = build_engine();
    let both = engine
        .search(&SearchRequest {
            page: Some(1),
            offset: Some(1),
            ..search("retrieval")
        })
        .expect_err("rejected");
    assert!(both.message.contains("mutually exclusive"));
    let high = engine
        .search(&SearchRequest {
            page: Some(MAX_PAGE + 1),
            ..search("retrieval")
        })
        .expect_err("rejected");
    assert!(high.message.contains("page must be between 0 and 10"));
    let far = engine
        .search(&SearchRequest {
            offset: Some(1_001),
            ..search("retrieval")
        })
        .expect_err("rejected");
    assert_eq!(far.status(), 400);
    let parsed: SearchRequest =
        serde_json::from_value(json!({"query": "retrieval", "page": 1, "numResults": 2}))
            .expect("parses");
    assert_eq!(parsed.page, Some(1));
}

// ---- Batch contents ----

#[test]
fn batch_contents_returns_one_status_per_url_and_one_failure_does_not_fail_the_batch() {
    let engine = build_engine();
    let mut failures = BTreeMap::new();
    failures.insert(
        "https://blocked.example/page".to_string(),
        IngestError::Fetch {
            kind: FetchErrorKind::BotBlocked,
            url: "https://blocked.example/page".into(),
            http_status: Some(403),
            message: "challenge page".into(),
        },
    );
    let request = ContentsRequest {
        urls: Some(vec![
            OBSCURA.into(),
            "https://blocked.example/page".into(),
            "https://never-seen.example/x".into(),
            "file:///C:/secrets.txt".into(),
        ]),
        ..Default::default()
    };
    let response = engine.contents_batch(&request, &failures).expect("batch");
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.statuses.len(), 4);
    let tags: Vec<Option<String>> = response
        .statuses
        .iter()
        .map(|s| s.error.as_ref().map(|e| e.tag.clone()))
        .collect();
    assert_eq!(
        tags,
        vec![
            None,
            Some("bot_blocked".into()),
            Some("not_in_corpus".into()),
            Some("unsupported_scheme".into())
        ]
    );
    assert_eq!(response.statuses[0].status, "success");
    assert_eq!(response.statuses[1].status, "error");
    assert_eq!(
        response.statuses[1]
            .error
            .as_ref()
            .and_then(|e| e.http_status_code),
        Some(403)
    );
    assert!(response.notices.iter().any(|n| n.kind == "not_found"));
    let value = serde_json::to_value(&response).expect("json");
    assert_eq!(value["statuses"][1]["error"]["httpStatusCode"], 403);
}

#[test]
fn batch_contents_accepts_ten_urls_and_refuses_eleven() {
    let engine = build_engine();
    let urls = |n: usize| ContentsRequest {
        urls: Some((0..n).map(|i| format!("https://example.org/{i}")).collect()),
        ..Default::default()
    };
    let ten = engine
        .contents_batch(&urls(MAX_BATCH_URLS), &BTreeMap::new())
        .expect("ten is allowed");
    assert_eq!(ten.statuses.len(), 10);
    let eleven = engine
        .contents_batch(&urls(MAX_BATCH_URLS + 1), &BTreeMap::new())
        .expect_err("eleven is refused");
    assert!(eleven.message.contains("at most 10"));
    let by_ids = engine
        .contents_batch(
            &ContentsRequest {
                ids: Some(vec![engine.get_by_url(OBSCURA).expect("doc").id.clone()]),
                ..Default::default()
            },
            &BTreeMap::new(),
        )
        .expect("ids");
    assert_eq!(by_ids.results[0].url, OBSCURA);
}

// ---- Formats ----

fn contents_with(
    engine: &LocalSearchEngine,
    format: ContentFormat,
) -> orcel_search::types::ResultItem {
    let request = ContentsRequest {
        urls: Some(vec![OBSCURA.into()]),
        format: Some(format),
        ..Default::default()
    };
    engine
        .contents_batch(&request, &BTreeMap::new())
        .expect("contents")
        .results
        .remove(0)
}

#[test]
fn html_format_is_cleaned_semantic_html_with_escaped_text() {
    let engine = build_engine();
    let item = contents_with(&engine, ContentFormat::Html);
    let html = item.html.expect("html");
    assert!(html.starts_with("<article><h1>"));
    assert!(html.contains("<h2>Chromium fallback</h2>"));
    assert!(html.contains("<pre><code>npm install @orcel/obscura</code></pre>"));
    assert!(!html.contains("<nav") && !html.contains("<a "));
    assert_eq!(item.text, None, "another format stands in for text");

    let mut doc = engine.get_by_url(OBSCURA).expect("doc").clone();
    doc.blocks = vec![
        ContentBlock::Paragraph {
            text: "<script>alert(1)</script> & \"q\"".into(),
        },
        ContentBlock::ListItem {
            ordered: true,
            text: "one".into(),
        },
        ContentBlock::ListItem {
            ordered: true,
            text: "two".into(),
        },
    ];
    let rendered = render_html(&doc);
    assert!(rendered.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;q&quot;"));
    assert!(rendered.contains("<ol><li>one</li><li>two</li></ol>"));
}

#[test]
fn json_format_is_a_typed_document_tree() {
    let engine = build_engine();
    let item = contents_with(&engine, ContentFormat::Json);
    let tree = serde_json::to_value(item.json.expect("json")).expect("value");
    assert_eq!(tree["url"], OBSCURA);
    let blocks = tree["blocks"].as_array().expect("blocks");
    assert!(blocks
        .iter()
        .any(|b| b["type"] == "heading" && b["level"] == 2 && b["text"] == "Architecture"));
    assert!(blocks.iter().any(|b| b["type"] == "code"));
    assert!(blocks.iter().any(|b| b["type"] == "paragraph"));
}

#[test]
fn markdown_format_and_explicit_text_can_be_combined() {
    let engine = build_engine();
    let request = ContentsRequest {
        urls: Some(vec![OBSCURA.into()]),
        contents: Some(ContentsOptions {
            format: Some(ContentFormat::Markdown),
            text: Some(TextOption::Flag(true)),
            ..Default::default()
        }),
        ..Default::default()
    };
    let item = engine
        .contents_batch(&request, &BTreeMap::new())
        .expect("contents")
        .results
        .remove(0);
    assert!(item.markdown.expect("markdown").contains("## Architecture"));
    assert!(item.text.is_some());
    let parsed: ContentsRequest =
        serde_json::from_value(json!({"urls": [OBSCURA], "format": "html"})).expect("parses");
    assert_eq!(parsed.options().format, Some(ContentFormat::Html));
}

// ---- Typed ingest errors ----

fn response(status: u16, content_type: &str, body: &str) -> FetchedResponse {
    FetchedResponse {
        url: "https://example.org/a".into(),
        final_url: None,
        status,
        headers: vec![("content-type".into(), content_type.into())],
        body: body.into(),
        fetched_at_ms: FIXED_NOW_MS,
    }
}

fn kind_of(result: Result<IngestOutcome, IngestError>) -> String {
    match result {
        Err(error) => error.code().to_string(),
        Ok(_) => "ok".to_string(),
    }
}

#[test]
fn http_outcomes_map_to_the_five_fetch_error_kinds() {
    let html = "text/html";
    assert_eq!(
        kind_of(ingest_response(&response(404, html, "gone"), None)),
        "page_not_found"
    );
    assert_eq!(
        kind_of(ingest_response(&response(410, html, "gone"), None)),
        "page_not_found"
    );
    assert_eq!(
        kind_of(ingest_response(&response(500, html, "oops"), None)),
        "target_http_error"
    );
    assert_eq!(
        kind_of(ingest_response(&response(403, html, "forbidden"), None)),
        "target_http_error"
    );
    assert_eq!(
        kind_of(ingest_response(
            &response(403, html, "<title>Just a moment...</title>"),
            None
        )),
        "bot_blocked"
    );
    assert_eq!(
        kind_of(ingest_response(
            &response(200, html, "<div class=\"g-recaptcha captcha\"></div>"),
            None
        )),
        "bot_blocked"
    );
    let mut challenged = response(503, html, "");
    challenged
        .headers
        .push(("cf-mitigated".into(), "challenge".into()));
    assert_eq!(
        classify_response(&challenged),
        Some(FetchErrorKind::BotBlocked)
    );
    match ingest_response(&response(502, html, ""), None) {
        Err(IngestError::Fetch { http_status, .. }) => assert_eq!(http_status, Some(502)),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        transport_error("https://example.org/a", TransportFailure::Timeout, "30s").code(),
        "timeout"
    );
    for failure in [
        TransportFailure::Dns,
        TransportFailure::Connect,
        TransportFailure::Tls,
        TransportFailure::Reset,
        TransportFailure::Refused,
    ] {
        assert_eq!(
            transport_error("https://example.org/a", failure, "x").code(),
            "target_unreachable"
        );
    }
    let codes: Vec<String> = [
        FetchErrorKind::BotBlocked,
        FetchErrorKind::Timeout,
        FetchErrorKind::TargetUnreachable,
        FetchErrorKind::PageNotFound,
        FetchErrorKind::TargetHttpError,
    ]
    .iter()
    .map(|k| {
        serde_json::to_value(k)
            .expect("json")
            .as_str()
            .expect("str")
            .to_string()
    })
    .collect();
    assert_eq!(
        codes,
        [
            "bot_blocked",
            "timeout",
            "target_unreachable",
            "page_not_found",
            "target_http_error"
        ]
    );
}

#[test]
fn refusals_are_typed_and_an_empty_page_is_never_a_success() {
    match ingest_response(&response(200, "application/pdf", "%PDF"), None) {
        Err(IngestError::Refused { reason, .. }) => {
            assert_eq!(reason, RefusalReason::UnsupportedContentType)
        }
        other => panic!("{other:?}"),
    }
    let mut no_type = response(200, "", "<p>x</p>");
    no_type.headers.clear();
    assert_eq!(
        kind_of(ingest_response(&no_type, None)),
        "unsupported_content_type"
    );
    assert_eq!(
        kind_of(ingest_response(
            &response(
                200,
                "text/html",
                "<html><body><div id=app></div><script>render()</script></body></html>"
            ),
            None
        )),
        "empty_content"
    );
}

// ---- ETag / Last-Modified and conditional requests ----

fn fresh_with_validators() -> orcel_search::CorpusDoc {
    let mut first = response(
        200,
        "text/html; charset=utf-8",
        "<article><p>Version one of the page.</p></article>",
    );
    first.headers.push(("ETag".into(), "W/\"abc123\"".into()));
    first.headers.push((
        "Last-Modified".into(),
        "Wed, 11 Feb 2026 09:00:00 GMT".into(),
    ));
    first.final_url = Some("https://example.org/a/".into());
    match ingest_response(&first, None) {
        Ok(IngestOutcome::Fresh(doc)) => doc,
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_ingest_record_keeps_validators_and_yields_conditional_request_headers() {
    let doc = fresh_with_validators();
    let record: &IngestRecord = &doc.ingest;
    assert_eq!(record.etag.as_deref(), Some("W/\"abc123\""));
    assert_eq!(
        record.last_modified.as_deref(),
        Some("Wed, 11 Feb 2026 09:00:00 GMT")
    );
    assert_eq!(record.final_url.as_deref(), Some("https://example.org/a/"));
    assert_eq!(record.fetched_at_ms, FIXED_NOW_MS);
    let conditional = record.conditional_request();
    assert!(conditional.is_conditional());
    assert_eq!(
        conditional.headers(),
        vec![
            ("If-None-Match", "W/\"abc123\"".to_string()),
            (
                "If-Modified-Since",
                "Wed, 11 Feb 2026 09:00:00 GMT".to_string()
            ),
        ]
    );
    assert!(!IngestRecord::default()
        .conditional_request()
        .is_conditional());
    let value = serde_json::to_value(record).expect("json");
    assert_eq!(value["etag"], "W/\"abc123\"");
    assert_eq!(value["lastModified"], "Wed, 11 Feb 2026 09:00:00 GMT");
}

#[test]
fn a_304_revalidates_the_stored_document_and_a_200_replaces_it() {
    let doc = fresh_with_validators();
    let mut not_modified = response(304, "text/html", "");
    not_modified.fetched_at_ms = FIXED_NOW_MS + 60_000;
    not_modified
        .headers
        .push(("ETag".into(), "W/\"abc123\"".into()));
    match ingest_response(&not_modified, Some(&doc)) {
        Ok(IngestOutcome::NotModified(same)) => {
            assert_eq!(same.content_hash, doc.content_hash);
            assert_eq!(same.text, doc.text);
            assert_eq!(same.ingest.revalidated_at_ms, Some(FIXED_NOW_MS + 60_000));
            assert_eq!(same.ingest.fetched_at_ms, FIXED_NOW_MS);
            assert!(same.ingest.is_fresh(FIXED_NOW_MS + 90_000, 60_000));
            assert!(!same.ingest.is_fresh(FIXED_NOW_MS + 200_000, 60_000));
            assert!(
                !same.ingest.is_fresh(FIXED_NOW_MS + 60_000, 0),
                "ttl 0 means live"
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        kind_of(ingest_response(&not_modified, None)),
        "target_http_error"
    );

    let changed = response(
        200,
        "text/html",
        "<article><p>Version two of the page.</p></article>",
    );
    match ingest_response(&changed, Some(&doc)) {
        Ok(IngestOutcome::Fresh(new_doc)) => {
            assert_ne!(new_doc.content_hash, doc.content_hash);
            assert_eq!(new_doc.id, doc.id);
            assert_eq!(new_doc.ingest.etag, None);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn contents_can_report_etag_and_last_modified_per_result() {
    let mut engine = build_engine();
    engine.add(fresh_with_validators());
    let request = ContentsRequest {
        urls: Some(vec!["https://example.org/a".into(), OBSCURA.into()]),
        include_etag_and_last_modified: Some(true),
        ..Default::default()
    };
    let response = engine
        .contents_batch(&request, &BTreeMap::new())
        .expect("contents");
    assert_eq!(response.results[0].etag.as_deref(), Some("W/\"abc123\""));
    assert_eq!(
        response.results[0].last_modified.as_deref(),
        Some("Wed, 11 Feb 2026 09:00:00 GMT")
    );
    assert_eq!(
        response.results[1].etag, None,
        "fixtures carry no validators"
    );
    let plain = engine
        .contents_batch(
            &ContentsRequest {
                urls: Some(vec!["https://example.org/a".into()]),
                ..Default::default()
            },
            &BTreeMap::new(),
        )
        .expect("contents");
    assert_eq!(plain.results[0].etag, None, "validators only on request");
}
