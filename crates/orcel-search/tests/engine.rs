//! Port of `orcel-poc/test/engine.test.ts` (15 tests).

mod common;

use common::{build_engine, find_by_url, host, load_fixtures, search};
use orcel_search::bm25::Bm25Index;
use orcel_search::ingest::{ingest_html, IngestRecord};
use orcel_search::types::{
    AnswerStatus, ContentsOptions, DocCategory, HighlightsOption, SearchType, TextOption,
    TextOptions,
};
use orcel_search::url::{domain_matches, normalise_domain};
use orcel_search::{
    AnswerRequest, CorpusDoc, EngineOptions, FindSimilarRequest, LocalSearchEngine, SearchRequest,
};

const BM25_URL: &str = "https://searchlab.example.org/notes/bm25-hybrid-retrieval";

#[test]
fn search_returns_rank_ordered_results_with_the_exa_response_envelope() {
    let engine = build_engine();
    let response = engine
        .search(&SearchRequest {
            num_results: Some(3),
            ..search("BM25 inverted index retrieval")
        })
        .expect("search");
    assert_eq!(response.request_id.len(), 36);
    assert!(response
        .request_id
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '-'));
    assert_eq!(response.resolved_search_type, "auto");
    assert_eq!(response.cost_dollars.total, 0.0);
    assert!(!response.results.is_empty() && response.results.len() <= 3);
    let scores: Vec<f64> = response.results.iter().map(|r| r.score).collect();
    let mut sorted = scores.clone();
    sorted.sort_by(|a, b| b.total_cmp(a));
    assert_eq!(scores, sorted, "results must be sorted by score");
    let top = &response.results[0];
    assert_eq!(top.url, BM25_URL);
    let text = top
        .text
        .as_deref()
        .expect("default search returns page text");
    assert!(text.chars().count() > 100 && text.chars().count() <= 10_000);
}

#[test]
fn search_reports_its_lexical_limitation_as_a_notice_instead_of_claiming_semantics() {
    let engine = build_engine();
    let response = engine
        .search(&SearchRequest {
            search_type: Some(SearchType::Auto),
            ..search("embeddings")
        })
        .expect("search");
    let notices = response.notices.expect("notices");
    assert!(notices.iter().any(|n| n.kind == "capability"));
    assert!(notices.iter().any(|n| n
        .message
        .to_lowercase()
        .contains("does not run a neural retriever")));
}

#[test]
fn domain_include_exclude_filters_operate_on_host_suffixes() {
    let engine = build_engine();
    let only_arxiv = engine
        .search(&SearchRequest {
            include_domains: Some(vec!["arxiv.org".into()]),
            ..search("retrieval")
        })
        .expect("search");
    let hosts: Vec<String> = only_arxiv.results.iter().map(|r| host(&r.url)).collect();
    assert_eq!(hosts, vec!["arxiv.org".to_string()]);

    let no_example = engine
        .search(&SearchRequest {
            exclude_domains: Some(vec!["example.org".into(), "example.net".into()]),
            ..search("retrieval")
        })
        .expect("search");
    assert!(no_example
        .results
        .iter()
        .all(|r| !r.url.contains("example.")));

    assert!(domain_matches("news.bbc.co.uk", "bbc.co.uk"));
    assert!(!domain_matches("bbc.co.uk.evil.test", "bbc.co.uk"));
    assert_eq!(
        normalise_domain("https://www.Example.org/path"),
        "example.org"
    );
}

#[test]
fn category_filter_uses_the_inferred_category() {
    let engine = build_engine();
    let papers = engine
        .search(&SearchRequest {
            category: Some(DocCategory::ResearchPaper),
            ..search("retrieval")
        })
        .expect("search");
    assert_eq!(papers.results.len(), 1);
    assert_eq!(host(&papers.results[0].url), "arxiv.org");

    let github = engine
        .search(&SearchRequest {
            category: Some(DocCategory::Github),
            ..search("browser engine chromium")
        })
        .expect("search");
    assert!(!github.results.is_empty());
    assert!(github.results.iter().all(|r| r.url.contains("github.com")));
}

#[test]
fn date_range_filter_excludes_pages_outside_the_window() {
    let engine = build_engine();
    let recent = engine
        .search(&SearchRequest {
            start_published_date: Some("2026-03-01".into()),
            end_published_date: Some("2026-03-31".into()),
            ..search("browser agents")
        })
        .expect("search");
    let dates: Vec<Option<String>> = recent
        .results
        .iter()
        .map(|r| r.published_date.clone())
        .collect();
    assert_eq!(dates, vec![Some("2026-03-14".to_string())]);
}

#[test]
fn include_text_and_exclude_text_match_raw_page_text_including_the_whole_document_edge() {
    let engine = build_engine();
    let docs = load_fixtures();
    let doc = find_by_url(&docs, "arxiv");
    let urls = |request: SearchRequest| -> Vec<String> {
        engine
            .search(&request)
            .expect("search")
            .results
            .into_iter()
            .map(|r| r.url)
            .collect()
    };

    let both = urls(SearchRequest {
        include_text: Some(vec!["SPARSE LEXICAL".into(), "dense embedding".into()]),
        ..search("retrieval")
    });
    assert!(!both.is_empty());
    assert!(both.iter().all(|u| *u == doc.url));

    let whole = urls(SearchRequest {
        include_text: Some(vec![doc.text.clone()]),
        ..search("retrieval")
    });
    assert_eq!(whole, vec![doc.url.clone()]);

    let impossible = urls(SearchRequest {
        include_text: Some(vec![format!("{}x", doc.text)]),
        ..search("retrieval")
    });
    assert!(impossible.is_empty());

    let excluded = urls(SearchRequest {
        exclude_text: Some(vec![doc.text.clone()]),
        ..search("retrieval")
    });
    assert!(excluded.iter().all(|u| *u != doc.url));
    assert!(!excluded.is_empty());

    let unfiltered = urls(SearchRequest {
        include_text: Some(vec![]),
        exclude_text: Some(vec![]),
        ..search("retrieval")
    });
    assert_eq!(unfiltered.len(), urls(search("retrieval")).len());
}

#[test]
fn contents_highlights_replaces_page_text_unless_a_text_cap_is_set() {
    let engine = build_engine();
    let highlights_only = engine
        .search(&SearchRequest {
            contents: Some(ContentsOptions {
                highlights: Some(HighlightsOption::Flag(true)),
                ..Default::default()
            }),
            ..search("browser agents")
        })
        .expect("search");
    let with_cap = engine
        .search(&SearchRequest {
            contents: Some(ContentsOptions {
                highlights: Some(HighlightsOption::Flag(true)),
                text: Some(TextOption::Options(TextOptions {
                    max_characters: Some(200),
                    include_html_tags: None,
                })),
                ..Default::default()
            }),
            ..search("browser agents")
        })
        .expect("search");
    assert!(!highlights_only.results[0]
        .highlights
        .as_ref()
        .expect("highlights")
        .is_empty());
    assert_eq!(highlights_only.results[0].text, None);
    assert!(
        with_cap.results[0]
            .text
            .as_ref()
            .expect("text")
            .chars()
            .count()
            <= 200
    );
}

#[test]
fn contents_returns_stored_documents_and_reports_urls_it_has_never_ingested() {
    let engine = build_engine();
    let text = ContentsOptions {
        text: Some(TextOption::Flag(true)),
        ..Default::default()
    };
    let hit = engine
        .contents(&[BM25_URL.to_string()], &text)
        .expect("contents");
    assert_eq!(hit.results.len(), 1);
    assert_eq!(hit.results[0].url, BM25_URL);
    assert!(hit.results[0].text.as_ref().expect("text").len() > 100);

    let miss = engine
        .contents(&["https://never-seen.example/x".to_string()], &text)
        .expect("contents");
    assert!(miss.results.is_empty());
    assert!(miss.notices.iter().any(|n| n.kind == "not_found"));
}

#[test]
fn answer_quotes_cited_spans_and_carries_citation_ids() {
    let engine = build_engine();
    let response = engine
        .answer(&AnswerRequest {
            query: "how does the chromium fallback work in obscura".into(),
            ..Default::default()
        })
        .expect("answer");
    assert_eq!(response.status, AnswerStatus::Supported);
    let answer = response.answer.expect("answer text");
    assert!(answer.len() > 40);
    let has_marker = answer.split('[').skip(1).any(|part| {
        part.split_once(']')
            .is_some_and(|(n, _)| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    });
    assert!(has_marker, "answer carries [n] citation markers: {answer}");
    assert!(!response.citations.is_empty());
    assert!(response
        .citations
        .iter()
        .any(|c| c.url.contains("github.com/orcel-labs/obscura")));
    assert_eq!(response.cost_dollars.total, 0.0);
    assert!(response
        .notices
        .expect("notices")
        .iter()
        .any(|n| n.kind == "extractive"));
}

#[test]
fn answer_abstains_rather_than_inventing_support() {
    let engine = build_engine();
    let response = engine
        .answer(&AnswerRequest {
            query: "quantum chromodynamics lattice spacing".into(),
            ..Default::default()
        })
        .expect("answer");
    assert_eq!(response.status, AnswerStatus::NoSupport);
    assert_eq!(response.answer, None);
    assert!(response.citations.is_empty());
    assert!(response
        .notices
        .expect("notices")
        .iter()
        .any(|n| n.kind == "abstained"));
}

#[test]
fn find_similar_uses_bm25_term_vectors_and_can_exclude_the_source_domain() {
    let engine = build_engine();
    let similar = engine
        .find_similar(&FindSimilarRequest {
            url: Some(BM25_URL.into()),
            num_results: Some(3),
            ..Default::default()
        })
        .expect("findSimilar");
    assert!(!similar.results.is_empty());
    assert!(similar.results.iter().all(|r| r.url != BM25_URL));
    assert!(similar.notices.expect("notices").iter().any(|n| n
        .message
        .to_lowercase()
        .contains("not embedding similarity")));

    let cross = engine
        .find_similar(&FindSimilarRequest {
            url: Some(BM25_URL.into()),
            exclude_source_domain: Some(true),
            ..Default::default()
        })
        .expect("findSimilar");
    assert!(cross
        .results
        .iter()
        .all(|r| !r.url.contains("searchlab.example.org")));
}

#[test]
fn empty_query_is_rejected_with_a_typed_input_error() {
    let engine = build_engine();
    let error = engine.search(&search("   ")).expect_err("must reject");
    assert!(error.message.contains("non-empty string"));
    assert_eq!(error.status(), 400);
}

#[test]
fn re_adding_the_same_url_replaces_the_old_document_instead_of_duplicating_it() {
    let mut engine = build_engine();
    let before = engine.len();
    let mut doc = load_fixtures().remove(0);
    doc.title = format!("{} (revised)", doc.title);
    let url = doc.url.clone();
    engine.add(doc);
    assert_eq!(engine.len(), before);
    assert!(engine
        .get_by_url(&url)
        .expect("doc")
        .title
        .contains("revised"));
}

fn plain_doc(i: usize) -> CorpusDoc {
    CorpusDoc {
        id: format!("d{i}"),
        url: format!("https://example.org/{i}"),
        title: format!("doc {i}"),
        text: format!("content about topic {i}"),
        markdown: String::new(),
        blocks: Vec::new(),
        published_date: None,
        author: None,
        site_name: None,
        language: None,
        category: DocCategory::General,
        content_hash: format!("hash{i}"),
        ingest: IngestRecord::default(),
    }
}

#[test]
fn corpus_eviction_keeps_the_index_consistent() {
    let mut engine = LocalSearchEngine::new(EngineOptions {
        max_documents: 2,
        ..Default::default()
    });
    for i in 1..=3 {
        engine.add(plain_doc(i));
    }
    assert_eq!(engine.len(), 2);
    assert!(engine.get("d1").is_none());
    let hits = engine.search(&search("topic 1")).expect("search");
    assert!(hits.results.iter().all(|r| r.id != "d1"));
}

#[test]
fn index_and_document_store_stay_addressable_by_id() {
    let engine = build_engine();
    let docs = load_fixtures();
    let doc = find_by_url(&docs, "arxiv");
    assert_eq!(engine.get(&doc.id).expect("doc").url, doc.url);
    let mut index = Bm25Index::default();
    index.add(&doc.id, &doc.title, &doc.text);
    assert!(index.term_vector(&doc.id).len() > 5);
    // Same id rule as the proof of concept: 12 hex chars of sha256(url).
    let again = ingest_html(&doc.url, "<p>x</p>", "local-corpus", 0).expect("doc");
    assert_eq!(again.id, doc.id);
    assert_eq!(doc.id.len(), 12);
}
