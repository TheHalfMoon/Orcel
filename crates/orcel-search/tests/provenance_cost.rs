//! Port of `orcel-poc/test/provenance-cost.test.ts` (8 tests). The two
//! fetch tests become tests of the pure ingest functions: this crate never
//! fetches, so "no socket" is proven by its dependency set and source.

mod common;

use common::{build_engine, search, FIXED_NOW_MS};
use orcel_search::ingest::{
    check_target, ingest_response, FetchedResponse, IngestError, IngestOutcome, RefusalReason,
};
use orcel_search::provenance::{
    endpoint_capabilities, local_capabilities, search_evidence, EvidenceEngine,
};
use orcel_search::{AnswerRequest, FindSimilarRequest, SearchRequest};

#[test]
fn local_port_advertises_zero_cost_offline_keyless_non_semantic() {
    let caps = local_capabilities();
    assert_eq!(caps.cost_per_call_usd, Some(0.0));
    assert!(caps.offline);
    assert!(!caps.requires_api_key);
    assert!(!caps.semantic);
}

/// The proof of concept removed `globalThis.fetch`; the Rust equivalent is
/// that the crate cannot open a socket: it depends only on serde,
/// serde_json and sha2, and its source names no network, process or file
/// API.
#[test]
fn the_crate_has_no_network_surface_and_local_search_still_works() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("manifest");
    let deps: Vec<&str> = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("dependencies section")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('['))
        .map(|l| l.split(['.', '=', ' ']).next().unwrap_or(""))
        .collect();
    assert_eq!(deps, vec!["serde", "serde_json", "sha2"]);
    assert!(!manifest.contains("[dev-dependencies]"));

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(src).expect("src") {
        let path = entry.expect("entry").path();
        let code = std::fs::read_to_string(&path).expect("source");
        // Hosted endpoints are spelled in pieces so this file names neither.
        let exa_cloud = ["api", ".exa", ".ai"].concat();
        let tinyfish_cloud = ["tinyfish", ".ai"].concat();
        for forbidden in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process",
            "std::fs",
            exa_cloud.as_str(),
            tinyfish_cloud.as_str(),
        ] {
            assert!(
                !code.contains(forbidden),
                "{} names {forbidden}",
                path.display()
            );
        }
    }

    let engine = build_engine();
    let outcome = search_evidence(
        &engine,
        &SearchRequest {
            num_results: Some(2),
            ..search("chromium fallback browser engine")
        },
        "local-corpus",
        FIXED_NOW_MS,
    )
    .expect("search");
    assert!(!outcome.results.is_empty());
    assert_eq!(outcome.cost_usd, 0.0);
}

#[test]
fn every_evidence_item_carries_url_doc_id_sha256_content_hash_and_a_local_engine_tag() {
    let engine = build_engine();
    let outcome = search_evidence(
        &engine,
        &SearchRequest {
            num_results: Some(3),
            ..search("browser agents procurement")
        },
        "local-corpus",
        FIXED_NOW_MS,
    )
    .expect("search");
    assert!(!outcome.results.is_empty());
    for item in &outcome.results {
        let p = &item.provenance;
        assert_eq!(p.engine, EvidenceEngine::OrcelLocal);
        assert!(p.extractive);
        assert_eq!(p.url, item.url);
        assert_eq!(p.content_hash.len(), 64);
        assert!(p.content_hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!p.doc_id.is_empty());
        assert_eq!(p.retrieved_at_ms, FIXED_NOW_MS);
        assert_eq!(p.origin, "local-corpus");
        assert_eq!(
            engine.get(&p.doc_id).expect("doc").content_hash,
            p.content_hash
        );
    }
}

#[test]
fn exa_compatible_endpoint_on_loopback_is_classified_as_offline_and_free() {
    for base in [
        "http://127.0.0.1:8787",
        "http://localhost:8787/",
        "http://[::1]:8787",
    ] {
        let caps = endpoint_capabilities(base);
        assert!(caps.offline, "{base}");
        assert!(!caps.semantic, "{base}");
        assert_eq!(caps.cost_per_call_usd, Some(0.0), "{base}");
    }
    // A lookalike host is not loopback.
    assert!(!endpoint_capabilities("http://127.0.0.1.evil.test").offline);
}

#[test]
fn exa_compatible_endpoint_elsewhere_is_classified_as_semantic_paid_and_not_offline() {
    let caps = endpoint_capabilities("https://cloud.example");
    assert!(!caps.offline);
    assert!(caps.semantic);
    assert_eq!(
        caps.cost_per_call_usd, None,
        "cloud cost is provider-priced, so it is not asserted as a number"
    );
}

#[test]
fn ingest_refuses_non_http_schemes_before_any_fetch() {
    for target in [
        "file:///C:/secrets.txt",
        "ftp://example.org/x",
        "javascript:alert(1)",
    ] {
        match check_target(target) {
            Err(IngestError::Refused {
                reason: RefusalReason::UnsupportedScheme,
                message,
                ..
            }) => assert!(message.contains("refusing to ingest non-http")),
            other => panic!("{target}: {other:?}"),
        }
    }
    assert!(check_target("https://example.org/x").is_ok());
}

#[test]
fn ingest_turns_the_adapter_supplied_response_into_a_document() {
    let response = FetchedResponse {
        url: "https://example.org/injected".into(),
        final_url: None,
        status: 200,
        headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
        body: "<html><body><article><p>Injected body.</p></article></body></html>".into(),
        fetched_at_ms: FIXED_NOW_MS,
    };
    match ingest_response(&response, None) {
        Ok(IngestOutcome::Fresh(doc)) => {
            assert!(doc.text.contains("Injected body"));
            assert_eq!(doc.url, "https://example.org/injected");
            assert_eq!(doc.ingest.origin, "governed-fetch");
            assert_eq!(doc.ingest.http_status, Some(200));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn engine_responses_always_report_zero_dollars() {
    let engine = build_engine();
    assert_eq!(
        engine
            .search(&search("embeddings"))
            .expect("s")
            .cost_dollars
            .total,
        0.0
    );
    assert_eq!(
        engine
            .answer(&AnswerRequest {
                query: "chromium fallback".into(),
                ..Default::default()
            })
            .expect("a")
            .cost_dollars
            .total,
        0.0
    );
    assert_eq!(
        engine
            .find_similar(&FindSimilarRequest {
                url: Some("https://searchlab.example.org/notes/bm25-hybrid-retrieval".into()),
                ..Default::default()
            })
            .expect("f")
            .cost_dollars
            .total,
        0.0
    );
}
