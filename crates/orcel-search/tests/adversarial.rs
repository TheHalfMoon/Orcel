//! Hostile input: every case must finish within a deterministic work bound
//! (node counts and the parser's and analyser's step counters), never a
//! wall clock, and refuse with a typed error past the size limits.

mod common;

use common::{build_engine, search, FIXED_NOW_MS};
use orcel_search::extract::{extract_page, ExtractedPage};
use orcel_search::highlights::split_sentences;
use orcel_search::html::{
    decode_entities, parse, HtmlLimit, MAX_ATTRIBUTES, MAX_ATTRIBUTE_VALUE_BYTES, MAX_HTML_BYTES,
    MAX_NODES, MAX_OPEN_DEPTH,
};
use orcel_search::ingest::{
    ingest_html, ingest_response, sanitize_validator, ConditionalRequest, FetchedResponse,
    IngestError, IngestOutcome, RefusalReason,
};
use orcel_search::tokenize::{MAX_QUERY_BYTES, MAX_QUERY_TERMS};
use orcel_search::types::ContentsOptions;
use orcel_search::{AnswerRequest, SearchRequest};

const URL: &str = "https://example.org/hostile";

/// Linear-work bound: the parser's rule lookups and the analysis visits are
/// each at most a small constant times the input size or node count.
fn assert_linear(page: &ExtractedPage) {
    let s = page.stats;
    assert!(s.nodes <= MAX_NODES, "nodes {}", s.nodes);
    assert!(
        s.parse.stack_steps <= 16 * s.parse.input_bytes.max(1),
        "stack steps {} for {} bytes",
        s.parse.stack_steps,
        s.parse.input_bytes
    );
    assert!(
        s.analysis_steps <= 2 * s.nodes + 1,
        "analysis steps {} for {} nodes",
        s.analysis_steps,
        s.nodes
    );
}

fn extract(html: &str) -> ExtractedPage {
    let page = extract_page(html, URL).expect("within limits");
    assert_linear(&page);
    page
}

#[test]
fn deep_nesting_is_capped_at_the_open_depth_and_stays_linear() {
    let depth = 100_000;
    let html = format!(
        "<body>{}<p>deep text that survives</p>{}</body>",
        "<div>".repeat(depth),
        "</div>".repeat(depth)
    );
    let page = extract(&html);
    assert_eq!(page.stats.parse.max_depth, MAX_OPEN_DEPTH);
    assert!(page.text.contains("deep text that survives"));

    let dom = parse(&format!("{}x", "<li><ul>".repeat(20_000))).expect("parses");
    assert!(dom.stats.max_depth <= MAX_OPEN_DEPTH);
    assert!(dom.stats.stack_steps <= 16 * dom.stats.input_bytes);
}

#[test]
fn implied_end_rules_do_not_rescan_the_stack() {
    // A list item deep under 500 open elements, then thousands of items that
    // are closed and reopened: each rule is a constant number of lookups.
    let html = format!(
        "<body><ul><li>{}{}</ul></body>",
        "<div>".repeat(500),
        "<li>item</li>".repeat(50_000)
    );
    let page = extract(&html);
    // About 15 lookups per item (the p rule, the li rule, the end tag).
    assert!(page.stats.parse.stack_steps <= 32 * 50_002);
}

#[test]
fn attributes_are_capped_per_tag_and_values_are_cut() {
    let many: String = (0..10_000).map(|i| format!(" a{i}=v")).collect();
    let dupes = " same=1".repeat(100_000);
    let long_value = "x".repeat(MAX_ATTRIBUTE_VALUE_BYTES * 4);
    let html = format!(
        "<body><div{many}><p>one</p></div><div{dupes}><p>two</p></div><div title=\"{long_value}\"><p>three</p></div></body>"
    );
    let dom = parse(&html).expect("parses");
    assert_eq!(dom.stats.dropped_attributes, 10_000 - MAX_ATTRIBUTES);
    let divs = dom.find_all(0, |d, id| d.tag(id) == Some("div"));
    let attr_count = |id: usize| match &dom.nodes[id].kind {
        orcel_search::html::NodeKind::Element { attrs, .. } => attrs.len(),
        _ => 0,
    };
    assert_eq!(attr_count(divs[0]), MAX_ATTRIBUTES);
    assert_eq!(attr_count(divs[1]), 1, "duplicates keep the first only");
    assert_eq!(
        dom.attr(divs[2], "title").map(str::len),
        Some(MAX_ATTRIBUTE_VALUE_BYTES)
    );
    let page = extract(&html);
    assert!(page.text.contains("one") && page.text.contains("three"));
}

#[test]
fn unterminated_constructs_consume_the_rest_without_rescanning() {
    let tail = "x".repeat(1_000_000);
    for prefix in [
        "<body><p>kept</p><script>",
        "<body><p>kept</p><!--",
        "<body><p>kept</p><div class=\"",
        "<body><p>kept</p><title>",
        "<body><p>kept</p></p",
        "<body><p>kept</p><!doctype",
    ] {
        let page = extract(&format!("{prefix}{tail}"));
        assert!(page.text.contains("kept"), "{prefix}");
        assert!(
            page.stats.nodes < 16,
            "{prefix}: {} nodes",
            page.stats.nodes
        );
    }
    // Many tag openers with no closing '>' still finish linearly.
    let page = extract(&format!("<body><p>kept</p>{}", "<a b=".repeat(100_000)));
    assert!(page.text.contains("kept"));
}

#[test]
fn entities_at_buffer_boundaries_decode_safely() {
    assert_eq!(decode_entities("tail &amp"), "tail &amp");
    assert_eq!(decode_entities("&"), "&");
    assert_eq!(decode_entities("&#"), "&#");
    assert_eq!(decode_entities("&#x"), "&#x");
    assert_eq!(decode_entities("&#;"), "&#;");
    assert_eq!(decode_entities("&#xD800;"), "\u{fffd}");
    assert_eq!(decode_entities("&#99999999999;"), "&#99999999999;");
    assert_eq!(decode_entities("&#0;"), "\u{fffd}");
    assert_eq!(decode_entities("a&amp;"), "a&");
    let long_name = format!("&{};", "a".repeat(100));
    assert_eq!(decode_entities(&long_name), long_name);
    let many = "&".repeat(200_000);
    assert_eq!(decode_entities(&many).len(), 200_000);
    let page = extract(&format!(
        "<body><p>{}</p></body>",
        "&amp;&#x41;&bogus;".repeat(50_000)
    ));
    assert!(page.text.starts_with("&A&bogus;"));
}

#[test]
fn validators_with_control_characters_are_dropped_at_ingest_and_in_headers() {
    let mut response = FetchedResponse {
        url: URL.into(),
        final_url: None,
        status: 200,
        headers: vec![
            ("content-type".into(), "text/html".into()),
            ("etag".into(), "\"a\"\r\nX-Injected: 1".into()),
            (
                "last-modified".into(),
                "Wed, 11 Feb 2026 09:00:00 GMT\n".into(),
            ),
        ],
        body: "<article><p>Body text.</p></article>".into(),
        fetched_at_ms: FIXED_NOW_MS,
    };
    let doc = match ingest_response(&response, None) {
        Ok(IngestOutcome::Fresh(doc)) => doc,
        other => panic!("{other:?}"),
    };
    assert_eq!(doc.ingest.etag, None, "CRLF in ETag drops it");
    assert_eq!(
        doc.ingest.last_modified, None,
        "LF in Last-Modified drops it"
    );
    assert!(doc.ingest.conditional_request().headers().is_empty());

    response.headers[1].1 = "W/\"ok\"".into();
    response.headers[2].1 = "Wed, 11 Feb 2026 09:00:00 GMT".into();
    match ingest_response(&response, None) {
        Ok(IngestOutcome::Fresh(doc)) => {
            assert_eq!(doc.ingest.etag.as_deref(), Some("W/\"ok\""));
            assert_eq!(doc.ingest.conditional_request().headers().len(), 2);
        }
        other => panic!("{other:?}"),
    }

    let forged = ConditionalRequest {
        if_none_match: Some("\"x\"\r\nHost: evil.test".into()),
        if_modified_since: Some("Wed, 11 Feb 2026 09:00:00 GMT".into()),
    };
    assert_eq!(
        forged.headers(),
        vec![(
            "If-Modified-Since",
            "Wed, 11 Feb 2026 09:00:00 GMT".to_string()
        )]
    );
    for bad in ["", "   ", "a\tb", "caf\u{e9}", "a\0b", "\u{7f}"] {
        assert_eq!(sanitize_validator(bad), None, "{bad:?}");
    }
    assert_eq!(sanitize_validator(&"a".repeat(257)), None);
    assert_eq!(sanitize_validator(" \"v1\" ").as_deref(), Some("\"v1\""));
}

#[test]
fn oversized_input_is_refused_as_content_too_large() {
    let huge = format!("<body><p>{}</p></body>", "a".repeat(MAX_HTML_BYTES));
    assert!(matches!(
        extract_page(&huge, URL),
        Err(HtmlLimit::InputTooLarge { .. })
    ));
    match ingest_html(URL, &huge, "local-corpus", 0) {
        Err(error @ IngestError::Refused { .. }) => assert_eq!(error.code(), "content_too_large"),
        other => panic!("{other:?}"),
    }
    let response = FetchedResponse {
        url: URL.into(),
        final_url: None,
        status: 200,
        headers: vec![("content-type".into(), "text/html".into())],
        body: huge,
        fetched_at_ms: 0,
    };
    match ingest_response(&response, None) {
        Err(IngestError::Refused { reason, .. }) => {
            assert_eq!(reason, RefusalReason::ContentTooLarge)
        }
        other => panic!("{other:?}"),
    }

    let too_many = format!("<body>{}</body>", "<br>".repeat(MAX_NODES + 1));
    assert!(too_many.len() < MAX_HTML_BYTES);
    assert_eq!(
        extract_page(&too_many, URL).err(),
        Some(HtmlLimit::TooManyNodes)
    );

    // Just under the byte limit is accepted and stays linear.
    let near = format!("<body><p>{}</p></body>", "word ".repeat(MAX_HTML_BYTES / 6));
    assert!(near.len() <= MAX_HTML_BYTES);
    let page = extract(&near);
    assert!(page.stats.nodes < 16);
}

#[test]
fn many_dropped_siblings_are_removed_in_one_pass() {
    let html = format!(
        "<body><article><p>kept paragraph text</p>{}</article></body>",
        "<aside>x</aside><nav>y</nav>".repeat(40_000)
    );
    let page = extract(&html);
    assert_eq!(page.text, "kept paragraph text");
}

#[test]
fn nested_articles_and_blocks_are_measured_once() {
    let depth = 400;
    let html = format!(
        "<body>{}<p>{}</p>{}</body>",
        "<article><li><blockquote>".repeat(depth),
        "evidence ".repeat(50),
        "</blockquote></li></article>".repeat(depth)
    );
    let page = extract(&html);
    assert!(page.text.starts_with("evidence"));
}

#[test]
fn sentence_splitting_with_many_non_boundaries_finishes() {
    let text = "Dr. ".repeat(200_000);
    let sentences = split_sentences(&text);
    assert_eq!(sentences.len(), 1);
    let digits = "1. ".repeat(200_000);
    assert_eq!(split_sentences(&digits).len(), 1);
}

#[test]
fn query_length_and_term_caps_are_typed_input_errors() {
    let engine = build_engine();
    let long = "a".repeat(MAX_QUERY_BYTES + 1);
    let error = engine.search(&search(&long)).expect_err("too long");
    assert!(error.message.contains("at most 2048 bytes"));
    let terms: String = (0..=MAX_QUERY_TERMS).map(|i| format!("term{i} ")).collect();
    assert!(terms.len() <= MAX_QUERY_BYTES);
    let error = engine.search(&search(&terms)).expect_err("too many terms");
    assert!(error.message.contains("at most 64 terms"));
    let error = engine
        .answer(&AnswerRequest {
            query: long,
            ..Default::default()
        })
        .expect_err("too long");
    assert_eq!(error.status(), 400);
    let ok: String = (0..MAX_QUERY_TERMS).map(|i| format!("term{i} ")).collect();
    assert!(engine.search(&search(&ok)).is_ok());
}

#[test]
fn answer_num_results_is_clamped_and_contents_enforces_the_batch_limit() {
    let engine = build_engine();
    for n in [i64::MIN, -1, 0, 1, 1_000_000, i64::MAX] {
        let response = engine
            .answer(&AnswerRequest {
                query: "chromium fallback browser engine".into(),
                num_results: Some(n),
                ..Default::default()
            })
            .expect("answer");
        assert!(response.citations.len() <= 100, "{n}");
    }
    let eleven: Vec<String> = (0..11)
        .map(|i| format!("https://example.org/{i}"))
        .collect();
    let error = engine
        .contents(&eleven, &ContentsOptions::default())
        .expect_err("refused");
    assert!(error.message.contains("at most 10"));
    assert!(engine.contents(&[], &ContentsOptions::default()).is_err());
    let pagination = engine.search(&SearchRequest {
        num_results: Some(i64::MAX),
        offset: Some(1_000),
        ..search("retrieval")
    });
    assert!(pagination.expect("search").results.is_empty());
}
