//! WI-02: ranking a map's URLs against a search term, locally.
//!
//! Ported from firecrawl/firecrawl at commit
//! f84845c864b6e2af22791c18fcf89ac2a21f1434, `apps/api/src/lib/map-cosine.ts`
//! (blob 0449827ca57efc5d8d6bc69eb49de22c54110729), `performCosineSimilarity`.
//! AGPL-3.0 upstream; ported under the founder authorization recorded in
//! `docs/orcel/grants/2026-10-13-founder-source-authorization.md`; notice:
//! `docs/orcel/notices/firecrawl-AGPL-3.0.txt`.
//!
//! What is kept: the query is lower-cased and split on non-word characters;
//! each text (a URL) becomes the vector of, per query word, its occurrence
//! count divided by the text's length; texts are ordered by the cosine of
//! their vector and the query's own, highest first, ties keeping their
//! order. Orcel's changes: words are matched as literal substrings (the
//! donor builds a regular expression from each word, which its split
//! already restricts to word characters); empty words are dropped (the
//! donor's empty word matched everywhere); the query is bounded; and no
//! hosted index or network is involved.

/// Longest search term, in bytes.
pub const MAX_SEARCH_BYTES: usize = 256;

/// The query's words: lower-case runs of ASCII letters, digits and `_`
/// (JavaScript's `\W+` split), at most 32 of them.
fn words(search: &str) -> Vec<String> {
    search
        .to_lowercase()
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|word| !word.is_empty())
        .take(32)
        .map(str::to_owned)
        .collect()
}

fn vector(text: &str, words: &[String]) -> Vec<f64> {
    let lower = text.to_lowercase();
    let length = text.chars().count().max(1) as f64;
    words
        .iter()
        .map(|word| lower.matches(word.as_str()).count() as f64 / length)
        .collect()
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let norm = |v: &[f64]| v.iter().map(|x| x * x).sum::<f64>().sqrt();
    let (na, nb) = (norm(a), norm(b));
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Orders `urls` by relevance to `search`, most relevant first; ties (and
/// every URL when the search has no word) keep their order.
pub(crate) fn rank(urls: &mut [String], search: &str) {
    let words = words(search);
    if words.is_empty() {
        return;
    }
    let query = vector(search, &words);
    let mut scored: Vec<(f64, usize)> = urls
        .iter()
        .enumerate()
        .map(|(index, url)| (cosine(&vector(url, &words), &query), index))
        .collect();
    // Stable: equal scores keep the crawl's order.
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    let ordered: Vec<String> = scored
        .iter()
        .map(|(_, index)| urls[*index].clone())
        .collect();
    for (slot, url) in urls.iter_mut().zip(ordered) {
        *slot = url;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranked(urls: &[&str], search: &str) -> Vec<String> {
        let mut owned: Vec<String> = urls.iter().map(|url| (*url).to_owned()).collect();
        rank(&mut owned, search);
        owned
    }

    #[test]
    fn wi02_the_most_relevant_urls_come_first() {
        let urls = [
            "https://site.test/docs/",
            "https://site.test/docs/install",
            "https://site.test/pricing",
            "https://site.test/docs/pricing-faq",
            "https://site.test/blog/announcing-pricing-and-plans",
        ];
        assert_eq!(
            ranked(&urls, "pricing")[..3],
            [
                // One word: every URL containing it outranks those without;
                // ties keep the crawl order (cosine of one-dimensional vectors).
                "https://site.test/pricing",
                "https://site.test/docs/pricing-faq",
                "https://site.test/blog/announcing-pricing-and-plans",
            ]
        );
        // Two words: a URL with both beats one with either.
        let two = ranked(
            &[
                "https://site.test/plans",
                "https://site.test/pricing",
                "https://site.test/pricing/plans",
            ],
            "Pricing plans",
        );
        assert_eq!(two[0], "https://site.test/pricing/plans");
    }

    #[test]
    fn wi02_no_words_or_no_matches_keep_the_crawl_order() {
        let urls = [
            "https://site.test/b",
            "https://site.test/a",
            "https://site.test/c",
        ];
        assert_eq!(ranked(&urls, ""), urls);
        assert_eq!(ranked(&urls, " -- !! "), urls, "no word characters");
        assert_eq!(ranked(&urls, "zebra"), urls, "equal scores are stable");
    }

    #[test]
    fn wi02_words_are_literal_and_bounded() {
        // A regex-looking query is split into words, never compiled.
        let urls = ["https://site.test/a.b", "https://site.test/axb"];
        assert_eq!(ranked(&urls, "a.b"), urls);
        assert_eq!(words(&"w ".repeat(100)).len(), 32);
    }
}
