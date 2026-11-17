//! Port of `orcel-poc/test/ranking.test.ts` (11 tests).

use std::collections::BTreeMap;

use orcel_search::bm25::{cosine_similarity, Bm25Index};
use orcel_search::highlights::{extract_highlights, split_sentences, HighlightOptions};
use orcel_search::tokenize::{index_terms, stem, tokenize};

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn tokenize_folds_diacritics_lowercases_and_keeps_unicode_letters() {
    assert_eq!(tokenize("Café Résumé"), strings(&["cafe", "resume"]));
    assert_eq!(tokenize("Привет мир"), strings(&["привет", "мир"]));
    assert!(tokenize("").is_empty());
}

#[test]
fn stem_trims_safe_english_suffixes_but_leaves_short_tokens_alone() {
    assert_eq!(stem("parsing"), "pars");
    assert_eq!(stem("retrieval"), "retrieval");
    assert_eq!(stem("ies"), "ies");
    assert_eq!(stem("queries"), "query");
}

#[test]
fn index_terms_drops_stopwords() {
    assert_eq!(
        index_terms("the quick brown fox and the dog"),
        strings(&["quick", "brown", "fox", "dog"])
    );
}

#[test]
fn bm25_ranks_the_document_that_repeats_the_rare_query_term_first() {
    let mut index = Bm25Index::default();
    index.add(
        "a",
        "Vector database internals",
        "a vector database stores embeddings and serves nearest neighbour search",
    );
    index.add(
        "b",
        "Retrieval notes",
        "retrieval combines ranking signals; hamming distance is unrelated",
    );
    index.add("c", "Unrelated", "cooking, gardening and long walks");
    let hits = index.search("nearest neighbour vector");
    assert_eq!(hits.first().map(|h| h.id.as_str()), Some("a"));
    assert!(hits.iter().all(|h| h.id != "c"));
}

#[test]
fn bm25_term_frequency_saturates_keyword_stuffing_does_not_win() {
    let mut index = Bm25Index::default();
    index.add("stuffed", "x", &"browser ".repeat(60));
    index.add(
        "focused",
        "browser agents for procurement",
        "browser agent session persistence and audit trails",
    );
    let hits = index.search("browser agent procurement");
    assert_eq!(
        hits.first().map(|h| h.id.as_str()),
        Some("focused"),
        "{hits:?}"
    );
}

#[test]
fn bm25_idf_is_zero_for_an_unseen_term() {
    let mut index = Bm25Index::default();
    index.add("a", "t", "alpha beta");
    assert_eq!(index.idf("gamma"), 0.0);
    assert!(index.idf("alpha") > 0.0);
}

#[test]
fn cosine_similarity_is_1_for_identical_vectors_and_0_for_disjoint_vectors() {
    let a: BTreeMap<String, f64> = [("x".to_string(), 1.0), ("y".to_string(), 2.0)].into();
    let same = a.clone();
    let disjoint: BTreeMap<String, f64> = [("z".to_string(), 3.0)].into();
    assert_eq!(cosine_similarity(&a, &same), 1.0);
    assert_eq!(cosine_similarity(&a, &disjoint), 0.0);
}

#[test]
fn split_sentences_does_not_split_on_abbreviations_decimals_or_single_initials() {
    let sentences =
        split_sentences("Dr. Smith raised $3.5 million. J. Doe disagreed! It shipped in 2026?");
    assert_eq!(sentences.len(), 3);
    assert!(sentences[0].text.ends_with("3.5 million."));
}

#[test]
fn highlights_pick_the_sentence_that_answers_the_query_in_document_order() {
    let text = "The company was founded in 2019. Its flagship product is a browser engine written in Rust. \
Revenue grew substantially last year. The browser engine supports a Chromium fallback for heavy pages. \
Hiring continues across the platform team.";
    let highlights = extract_highlights(
        text,
        &HighlightOptions {
            query: "chromium fallback browser engine".into(),
            num_sentences: Some(2),
            max_characters: None,
        },
    );
    assert_eq!(highlights.len(), 2);
    assert!(highlights[0].text.contains("Rust"));
    assert!(highlights[1].text.contains("Chromium fallback"));
    assert!(highlights.iter().all(|h| h.score > 0.0));
}

#[test]
fn highlights_respect_the_character_budget() {
    let text = "Alpha beta gamma delta epsilon. ".repeat(20);
    let highlights = extract_highlights(
        &text,
        &HighlightOptions {
            query: "alpha".into(),
            num_sentences: None,
            max_characters: Some(120),
        },
    );
    let total: usize = highlights.iter().map(|h| h.text.chars().count() + 1).sum();
    assert!(total <= 120, "budget exceeded: {total}");
    assert!(!highlights.is_empty());
}

#[test]
fn highlights_fall_back_to_the_lead_sentences_when_nothing_matches() {
    let highlights = extract_highlights(
        "First sentence here. Second sentence here. Third sentence here.",
        &HighlightOptions {
            query: "zzzz".into(),
            num_sentences: Some(2),
            max_characters: None,
        },
    );
    assert_eq!(highlights.len(), 2);
    assert!(highlights[0].text.contains("First sentence"));
    assert_eq!(highlights[0].score, 0.0);
}
