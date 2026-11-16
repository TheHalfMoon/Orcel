//! Port of `orcel-poc/test/extract.test.ts` (6 tests) plus HTML-parser and
//! date checks this port needs because it has no `linkedom`.

mod common;

use common::{find_by_url, load_fixtures};
use orcel_search::extract::{content_hash, extract_page, infer_category, normalise_date};
use orcel_search::html::decode_entities;
use orcel_search::ingest::ingest_html;
use orcel_search::types::{ContentBlock, DocCategory};

#[test]
fn extraction_drops_navigation_sidebar_footer_and_scripts_from_the_main_text() {
    let docs = load_fixtures();
    let bench = find_by_url(&docs, "bench.example.net");
    assert!(bench.text.to_lowercase().contains("density heuristic"));
    assert!(!bench.text.contains("Related reports"));
    assert!(!bench.text.contains("takes no vendor funding"));
    assert!(!bench.text.contains("document.querySelector"));
}

#[test]
fn extraction_reads_structured_metadata_title_author_published_date_site_name() {
    let docs = load_fixtures();
    let bm25 = find_by_url(&docs, "bm25-hybrid-retrieval");
    assert_eq!(
        bm25.title,
        "BM25 and hybrid retrieval: what lexical ranking still buys you"
    );
    assert_eq!(bm25.author.as_deref(), Some("Dana Whitfield"));
    assert_eq!(bm25.published_date.as_deref(), Some("2026-02-11"));
    assert_eq!(bm25.site_name.as_deref(), Some("Search Lab Notes"));
    assert_eq!(bm25.language.as_deref(), Some("en"));
}

#[test]
fn json_ld_supplies_author_and_date_when_meta_tags_are_absent() {
    let html = r#"<!doctype html><html><head><title>T</title>
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"NewsArticle","datePublished":"2025-11-02T10:00:00Z","author":{"@type":"Person","name":"A. Writer"}}</script>
    </head><body><article><h1>T</h1><p>Body text long enough to be selected as the main block by the density rule.</p></article></body></html>"#;
    let page = extract_page(html, "https://example.org/t");
    assert_eq!(page.author.as_deref(), Some("A. Writer"));
    assert_eq!(page.published_date.as_deref(), Some("2025-11-02"));
}

#[test]
fn markdown_output_preserves_headings_lists_and_code_fences() {
    let html = "<!doctype html><html><body><main>
    <h2>Steps</h2><ul><li>first</li><li>second</li></ul><pre><code>npm install</code></pre>
    <p>Closing paragraph.</p></main></body></html>";
    let page = extract_page(html, "https://example.org/x");
    assert!(page.markdown.contains("## Steps"));
    assert!(page.markdown.contains("- first"));
    assert!(page.markdown.contains("```\nnpm install"));
}

#[test]
fn content_hash_is_stable_for_identical_text_and_differs_for_changed_text() {
    let html = "<html><body><article><p>Alpha beta gamma.</p></article></body></html>";
    let a = ingest_html("https://example.org/a", html, "local-corpus", 1);
    let b = ingest_html("https://example.org/a", html, "local-corpus", 2);
    let c = ingest_html(
        "https://example.org/a",
        &html.replace("Alpha", "Delta"),
        "local-corpus",
        3,
    );
    assert_eq!(a.content_hash, b.content_hash);
    assert_ne!(a.content_hash, c.content_hash);
    assert_eq!(a.content_hash.len(), 64);
    assert!(a
        .content_hash
        .chars()
        .all(|ch| ch.is_ascii_digit() || ('a'..='f').contains(&ch)));
    assert_eq!(
        content_hash(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn category_inference_uses_the_url_host_and_the_declared_open_graph_type() {
    let og = Some("article");
    assert_eq!(
        infer_category("https://arxiv.org/abs/2601.00001", og),
        DocCategory::ResearchPaper
    );
    assert_eq!(
        infer_category("https://github.com/o/r", og),
        DocCategory::Github
    );
    assert_eq!(
        infer_category("https://www.reuters.com/technology/x", og),
        DocCategory::News
    );
    assert_eq!(
        infer_category("https://docs.example.org/guide.pdf", og),
        DocCategory::Pdf
    );
    assert_eq!(
        infer_category("https://example.org/plain", og),
        DocCategory::General
    );
}

// --- Port-specific checks (no linkedom) ---

#[test]
fn tree_builder_closes_implied_paragraphs_and_list_items() {
    let html = "<body><main><p>One<p>Two<ul><li>a<li>b</ul><p>Three &amp; four &#8212; &#x41;</main></body>";
    let page = extract_page(html, "https://example.org/p");
    let texts: Vec<String> = page
        .blocks
        .iter()
        .map(|b| match b {
            ContentBlock::Paragraph { text }
            | ContentBlock::ListItem { text, .. }
            | ContentBlock::Quote { text }
            | ContentBlock::Code { text }
            | ContentBlock::Heading { text, .. } => text.clone(),
        })
        .collect();
    assert_eq!(
        texts,
        vec!["One", "Two", "a", "b", "Three & four \u{2014} A"]
    );
    assert_eq!(decode_entities("&unknown; &lt;b&gt;"), "&unknown; <b>");
}

#[test]
fn hidden_and_aria_hidden_elements_and_comments_are_dropped() {
    let html = "<body><article><p>Visible text stays.</p><p hidden>secret one</p>\
<div aria-hidden=\"true\"><p>secret two</p></div><!-- <p>secret three</p> -->\
<div id=\"comments\"><p>secret four</p></div><script>var x = '<p>secret five</p>';</script></article></body>";
    let page = extract_page(html, "https://example.org/h");
    assert!(page.text.contains("Visible text stays."));
    assert!(!page.text.contains("secret"), "{}", page.text);
}

#[test]
fn dates_normalise_from_common_written_forms() {
    assert_eq!(
        normalise_date("2026-02-11T09:00:00Z").as_deref(),
        Some("2026-02-11")
    );
    assert_eq!(normalise_date("2026/01/05").as_deref(), Some("2026-01-05"));
    assert_eq!(
        normalise_date("Wed, 11 Feb 2026 09:00:00 GMT").as_deref(),
        Some("2026-02-11")
    );
    assert_eq!(
        normalise_date("February 11, 2026").as_deref(),
        Some("2026-02-11")
    );
    assert_eq!(
        normalise_date("March 3rd 2026").as_deref(),
        Some("2026-03-03")
    );
    assert_eq!(normalise_date("2026/02/30"), None);
    assert_eq!(normalise_date("soon"), None);
}
